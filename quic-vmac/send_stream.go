package quic

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/flowcontrol"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

type sendStreamI interface {
	SendStream
	handleStopSendingFrame(*wire.StopSendingFrame)
	hasData() bool
	popStreamFrame(maxBytes protocol.ByteCount, v protocol.VersionNumber) (frame ackhandler.StreamFrame, ok, hasMore bool)
	closeForShutdown(error)
	updateSendWindow(protocol.ByteCount)
}

type sendStream struct {
	mutex sync.Mutex

	numOutstandingFrames int64
	retransmissionQueue  []*wire.StreamFrame

	ctx       context.Context
	ctxCancel context.CancelFunc

	streamID protocol.StreamID
	sender   streamSender

	writeOffset protocol.ByteCount

	cancelWriteErr      error
	closeForShutdownErr error

	finishedWriting bool // set once Close() is called
	finSent         bool // set when a STREAM_FRAME with FIN bit has been sent
	completed       bool // set when this stream has been reported to the streamSender as completed

	dataForWriting []byte // during a Write() call, this slice is the part of p that still needs to be sent out
	nextFrame      *wire.StreamFrame

	writeChan chan struct{}
	writeOnce chan struct{}
	deadline  time.Time

	flowController flowcontrol.StreamFlowController

	// ICN-QUIC
	isMainStream bool
}

var (
	_ SendStream  = &sendStream{}
	_ sendStreamI = &sendStream{}
)

func newSendStream(
	streamID protocol.StreamID,
	sender streamSender,
	flowController flowcontrol.StreamFlowController,
) *sendStream {
	s := &sendStream{
		streamID:       streamID,
		sender:         sender,
		flowController: flowController,
		writeChan:      make(chan struct{}, 1),
		writeOnce:      make(chan struct{}, 1), // cap: 1, to protect against concurrent use of Write
		isMainStream:   false,
	}
	s.ctx, s.ctxCancel = context.WithCancel(context.Background())
	return s
}

func (s *sendStream) SetMainStream() {
	s.isMainStream = true
}

func (s *sendStream) StreamID() protocol.StreamID {
	return s.streamID // same for receiveStream and sendStream
}

// Write The functions performed by Write() do not include constructing frames, except for the last frame (or very small frames can be done directly by Write())
// Other than that, the function of Write() is mainly to assign the data to dataForWriting
// And then notify the connection that it is ready to send the data, after which the dataForWriting will be handled from there
func (s *sendStream) Write(p []byte) (int, error) {
	// Concurrent use of Write is not permitted (and doesn't make any sense),
	// but sometimes people do it anyway.
	// Make sure that we only execute one call at any given time to avoid hard to debug failures.

	// put the handshake done logic from connection.go/handleHandshakeComplete to here for avoiding synchronous bug
	// TODO: This bug still exist, it is solved temporarily by Sleep() before Write() in userspace
	// set seminar handshake done
	if len(seminars) > 0 {
		seminars[0].ifHandshakeDone = true
	} else {
		fmt.Errorf("handshake has done but seminar's length is zero")
	}

	if !s.isMainStream && IQPerspective == protocol.PerspectiveServer {
		fmt.Println("IN Write, not the main stream, cancel write")
		return 0, nil
	}

	s.writeOnce <- struct{}{}
	defer func() { <-s.writeOnce }()

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.finishedWriting {
		return 0, fmt.Errorf("write on closed stream %d", s.streamID)
	}
	if s.cancelWriteErr != nil {
		return 0, s.cancelWriteErr
	}
	if s.closeForShutdownErr != nil {
		return 0, s.closeForShutdownErr
	}
	// time out, deadline is set to zero initially
	if !s.deadline.IsZero() && !time.Now().Before(s.deadline) {
		return 0, errDeadline
	}
	if len(p) == 0 {
		return 0, nil
	}

	// dataForWriting means the data still need to be sent out
	s.dataForWriting = p

	var (
		deadlineTimer  *utils.Timer
		bytesWritten   int
		notifiedSender bool
	)
	for {
		var copied bool
		var deadline time.Time
		// As soon as dataForWriting becomes smaller than a certain size x, we copy all the data to a STREAM frame (s.nextFrame),
		// which can then be popped the next time we assemble a packet.
		// This allows us to return Write() when all data but x bytes have been sent out.
		// When the user now calls Close(), this is much more likely to happen before we popped that last STREAM frame,
		// allowing us to set the FIN bit on that frame (instead of sending an empty STREAM frame with FIN).
		/*  MOC: Comments for dataForWriting
		一旦dataForWriting小于一个确定的大小x，我们就将所有数据复制到一个STREAM帧（s.nextFrame）中，然后在下一次组装数据包时弹出该帧。
		这样我们就可以在除x字节外的所有数据都发送完毕时返回Write()。
		如果用户这时候调用Close()，这更有可能发生在我们弹出最后一个STREAM帧之前，允许我们设置该帧上的FIN位（而不是发送一个带有FIN的空STREAM帧）。
		*/

		// canBufferStreamFrame return true only if there is a small amount of data left to send
		if s.canBufferStreamFrame() && len(s.dataForWriting) > 0 {
			if s.nextFrame == nil {
				f := wire.GetStreamFrame()
				// writeOffset, streamID are 0 at begin (usually)
				f.Offset = s.writeOffset
				f.StreamID = s.streamID
				f.DataLenPresent = true
				f.Data = f.Data[:len(s.dataForWriting)]
				copy(f.Data, s.dataForWriting)
				s.nextFrame = f
			} else {
				l := len(s.nextFrame.Data)
				// extend the Data, adding len(s.dataForWriting)
				s.nextFrame.Data = s.nextFrame.Data[:l+len(s.dataForWriting)]
				copy(s.nextFrame.Data[l:], s.dataForWriting)
			}
			// if s.canBufferStreamFrame() return true (in this logic), meaning that the dataForWriting will be clear at this round, also meaning Write done
			s.dataForWriting = nil
			bytesWritten = len(p)
			copied = true
		} else {
			// if there is still some data that cannot be sent now (but already buffers some data [bytesWritten])
			bytesWritten = len(p) - len(s.dataForWriting)
			deadline = s.deadline
			// if we have deadline (usually no), reset the timer to it. After deadline, try sending data again
			if !deadline.IsZero() {
				if !time.Now().Before(deadline) {
					s.dataForWriting = nil
					return bytesWritten, errDeadline
				}
				if deadlineTimer == nil {
					deadlineTimer = utils.NewTimer()
					defer deadlineTimer.Stop()
				}
				deadlineTimer.Reset(deadline)
			}
			if s.dataForWriting == nil || s.cancelWriteErr != nil || s.closeForShutdownErr != nil {
				break
			}
		}

		s.mutex.Unlock()
		// Notify the send queue of the connection that it's ready to send data if it hasn't already done so
		if !notifiedSender {
			// onHasStreamData() -> stream.go/(s *uniStreamSender) onHasStreamData() -> connection.go/onHasStreamData()
			s.sender.onHasStreamData(s.streamID) // must be called without holding the mutex
			notifiedSender = true
		}
		// copied = true means Write done
		if copied {
			s.mutex.Lock()
			break
		}
		// block here until someone calls signalWrite()
		if deadline.IsZero() {
			<-s.writeChan
		} else {
			select {
			case <-s.writeChan:
			case <-deadlineTimer.Chan():
				deadlineTimer.SetRead()
			}
		}
		s.mutex.Lock()
	}

	if bytesWritten == len(p) {
		return bytesWritten, nil
	}
	if s.closeForShutdownErr != nil {
		return bytesWritten, s.closeForShutdownErr
	} else if s.cancelWriteErr != nil {
		return bytesWritten, s.cancelWriteErr
	}
	return bytesWritten, nil
}

func (s *sendStream) canBufferStreamFrame() bool {
	var l protocol.ByteCount
	// normally next frame has been consumed, so it is nil usually
	if s.nextFrame != nil {
		l = s.nextFrame.DataLen()
	}
	// return true only if there is a small amount of data left to send
	return l+protocol.ByteCount(len(s.dataForWriting)) <= protocol.MaxPacketBufferSize
}

// popStreamFrame returns the next STREAM frame that is supposed to be sent on this stream
// maxBytes is the maximum length this frame (including frame header) will have.
func (s *sendStream) popStreamFrame(maxBytes protocol.ByteCount, v protocol.VersionNumber) (af ackhandler.StreamFrame, ok, hasMore bool) {
	s.mutex.Lock()
	f, hasMoreData := s.popNewOrRetransmittedStreamFrame(maxBytes, v)
	if f != nil {
		s.numOutstandingFrames++
	}
	s.mutex.Unlock()

	if f == nil {
		return ackhandler.StreamFrame{}, false, hasMoreData
	}
	return ackhandler.StreamFrame{
		Frame:   f,
		Handler: (*sendStreamAckHandler)(s),
	}, true, hasMoreData
}

func (s *sendStream) popNewOrRetransmittedStreamFrame(maxBytes protocol.ByteCount, v protocol.VersionNumber) (*wire.StreamFrame, bool /* has more data to send */) {
	if s.cancelWriteErr != nil || s.closeForShutdownErr != nil {
		return nil, false
	}

	if len(s.retransmissionQueue) > 0 {
		f, hasMoreRetransmissions := s.maybeGetRetransmission(maxBytes, v)
		if f != nil || hasMoreRetransmissions {
			if f == nil {
				return nil, true
			}
			// We always claim that we have more data to send.
			// This might be incorrect, in which case there'll be a spurious call to popStreamFrame in the future.
			return f, true
		}
	}

	if len(s.dataForWriting) == 0 && s.nextFrame == nil {
		if s.finishedWriting && !s.finSent {
			s.finSent = true
			return &wire.StreamFrame{
				StreamID:       s.streamID,
				Offset:         s.writeOffset,
				DataLenPresent: true,
				Fin:            true,
			}, false
		}
		return nil, false
	}

	// MOC: flow control about
	sendWindow := s.flowController.SendWindowSize()
	if sendWindow == 0 {
		//s.flowController.UpdateSendWindowAuto()
		if isBlocked, offset := s.flowController.IsNewlyBlocked(); isBlocked {
			s.sender.queueControlFrame(&wire.StreamDataBlockedFrame{
				StreamID:          s.streamID,
				MaximumStreamData: offset,
			})
			return nil, false
		}
		return nil, true
	}

	f, hasMoreData := s.popNewStreamFrame(maxBytes, sendWindow, v)
	if dataLen := f.DataLen(); dataLen > 0 {
		s.writeOffset += f.DataLen()
		// add both connection-level and stream-level flow controller information about bytes sent
		s.flowController.AddBytesSent(f.DataLen())
	}
	f.Fin = s.finishedWriting && s.dataForWriting == nil && s.nextFrame == nil && !s.finSent
	if f.Fin {
		s.finSent = true
	}
	return f, hasMoreData
}

func (s *sendStream) popNewStreamFrame(maxBytes, sendWindow protocol.ByteCount, v protocol.VersionNumber) (*wire.StreamFrame, bool) {
	if s.nextFrame != nil {
		nextFrame := s.nextFrame
		s.nextFrame = nil

		maxDataLen := utils.Min(sendWindow, nextFrame.MaxDataLen(maxBytes, v))
		if nextFrame.DataLen() > maxDataLen {
			s.nextFrame = wire.GetStreamFrame()
			s.nextFrame.StreamID = s.streamID
			s.nextFrame.Offset = s.writeOffset + maxDataLen
			s.nextFrame.Data = s.nextFrame.Data[:nextFrame.DataLen()-maxDataLen]
			s.nextFrame.DataLenPresent = true
			copy(s.nextFrame.Data, nextFrame.Data[maxDataLen:])
			nextFrame.Data = nextFrame.Data[:maxDataLen]
		} else {
			s.signalWrite()
		}
		return nextFrame, s.nextFrame != nil || s.dataForWriting != nil
	}

	f := wire.GetStreamFrame()
	f.Fin = false
	f.StreamID = s.streamID
	f.Offset = s.writeOffset
	f.DataLenPresent = true
	f.Data = f.Data[:0]

	hasMoreData := s.popNewStreamFrameWithoutBuffer(f, maxBytes, sendWindow, v)
	if len(f.Data) == 0 && !f.Fin {
		f.PutBack()
		return nil, hasMoreData
	}
	return f, hasMoreData
}

func (s *sendStream) popNewStreamFrameWithoutBuffer(f *wire.StreamFrame, maxBytes, sendWindow protocol.ByteCount, v protocol.VersionNumber) bool {
	maxDataLen := f.MaxDataLen(maxBytes, v)
	if maxDataLen == 0 { // a STREAM frame must have at least one byte of data
		return s.dataForWriting != nil || s.nextFrame != nil || s.finishedWriting
	}
	s.getDataForWriting(f, utils.Min(maxDataLen, sendWindow))

	return s.dataForWriting != nil || s.nextFrame != nil || s.finishedWriting
}

func (s *sendStream) maybeGetRetransmission(maxBytes protocol.ByteCount, v protocol.VersionNumber) (*wire.StreamFrame, bool /* has more retransmissions */) {
	f := s.retransmissionQueue[0]
	newFrame, needsSplit := f.MaybeSplitOffFrame(maxBytes, v)
	if needsSplit {
		return newFrame, true
	}
	s.retransmissionQueue = s.retransmissionQueue[1:]
	return f, len(s.retransmissionQueue) > 0
}

func (s *sendStream) hasData() bool {
	s.mutex.Lock()
	hasData := len(s.dataForWriting) > 0
	s.mutex.Unlock()
	return hasData
}

func (s *sendStream) getDataForWriting(f *wire.StreamFrame, maxBytes protocol.ByteCount) {
	if protocol.ByteCount(len(s.dataForWriting)) <= maxBytes {
		f.Data = f.Data[:len(s.dataForWriting)]
		copy(f.Data, s.dataForWriting)
		s.dataForWriting = nil
		s.signalWrite()
		return
	}
	f.Data = f.Data[:maxBytes]
	copy(f.Data, s.dataForWriting)
	s.dataForWriting = s.dataForWriting[maxBytes:]
	if s.canBufferStreamFrame() {
		s.signalWrite()
	}
}

func (s *sendStream) isNewlyCompleted() bool {
	completed := (s.finSent || s.cancelWriteErr != nil) && s.numOutstandingFrames == 0 && len(s.retransmissionQueue) == 0
	if completed && !s.completed {
		s.completed = true
		return true
	}
	return false
}

func (s *sendStream) Close() error {
	s.mutex.Lock()
	if s.closeForShutdownErr != nil {
		s.mutex.Unlock()
		return nil
	}
	if s.cancelWriteErr != nil {
		s.mutex.Unlock()
		return fmt.Errorf("close called for canceled stream %d", s.streamID)
	}
	s.ctxCancel()
	s.finishedWriting = true
	s.mutex.Unlock()

	s.sender.onHasStreamData(s.streamID) // need to send the FIN, must be called without holding the mutex
	return nil
}

func (s *sendStream) CancelWrite(errorCode StreamErrorCode) {
	s.cancelWriteImpl(errorCode, false)
}

// must be called after locking the mutex
func (s *sendStream) cancelWriteImpl(errorCode qerr.StreamErrorCode, remote bool) {
	s.mutex.Lock()
	if s.cancelWriteErr != nil {
		s.mutex.Unlock()
		return
	}
	s.ctxCancel()
	s.cancelWriteErr = &StreamError{StreamID: s.streamID, ErrorCode: errorCode, Remote: remote}
	s.numOutstandingFrames = 0
	s.retransmissionQueue = nil
	newlyCompleted := s.isNewlyCompleted()
	s.mutex.Unlock()

	s.signalWrite()
	s.sender.queueControlFrame(&wire.ResetStreamFrame{
		StreamID:  s.streamID,
		FinalSize: s.writeOffset,
		ErrorCode: errorCode,
	})
	if newlyCompleted {
		s.sender.onStreamCompleted(s.streamID)
	}
}

func (s *sendStream) updateSendWindow(limit protocol.ByteCount) {
	s.mutex.Lock()
	hasStreamData := s.dataForWriting != nil || s.nextFrame != nil
	s.mutex.Unlock()

	s.flowController.UpdateSendWindow(limit)
	if hasStreamData {
		s.sender.onHasStreamData(s.streamID)
	}
}

func (s *sendStream) handleStopSendingFrame(frame *wire.StopSendingFrame) {
	s.cancelWriteImpl(frame.ErrorCode, true)
}

func (s *sendStream) Context() context.Context {
	return s.ctx
}

func (s *sendStream) SetWriteDeadline(t time.Time) error {
	s.mutex.Lock()
	s.deadline = t
	s.mutex.Unlock()
	s.signalWrite()
	return nil
}

// CloseForShutdown closes a stream abruptly.
// It makes Write unblock (and return the error) immediately.
// The peer will NOT be informed about this: the stream is closed without sending a FIN or RST.
func (s *sendStream) closeForShutdown(err error) {
	s.mutex.Lock()
	s.ctxCancel()
	s.closeForShutdownErr = err
	s.mutex.Unlock()
	s.signalWrite()
}

// signalWrite performs a non-blocking send on the writeChan
func (s *sendStream) signalWrite() {
	select {
	case s.writeChan <- struct{}{}:
	default:
	}
}

type sendStreamAckHandler sendStream

var _ ackhandler.FrameHandler = &sendStreamAckHandler{}

func (s *sendStreamAckHandler) OnAcked(f wire.Frame) {
	sf := f.(*wire.StreamFrame)
	sf.PutBack()
	s.mutex.Lock()
	if s.cancelWriteErr != nil {
		s.mutex.Unlock()
		return
	}
	s.numOutstandingFrames--
	if s.numOutstandingFrames < 0 {
		panic("numOutStandingFrames negative")
	}
	newlyCompleted := (*sendStream)(s).isNewlyCompleted()
	s.mutex.Unlock()

	if newlyCompleted {
		s.sender.onStreamCompleted(s.streamID)
	}
}

func (s *sendStreamAckHandler) OnLost(f wire.Frame) {
	sf := f.(*wire.StreamFrame)
	s.mutex.Lock()
	if s.cancelWriteErr != nil {
		s.mutex.Unlock()
		return
	}
	sf.DataLenPresent = true
	s.retransmissionQueue = append(s.retransmissionQueue, sf)
	s.numOutstandingFrames--
	if s.numOutstandingFrames < 0 {
		panic("numOutStandingFrames negative")
	}
	s.mutex.Unlock()

	s.sender.onHasStreamData(s.streamID)
}
