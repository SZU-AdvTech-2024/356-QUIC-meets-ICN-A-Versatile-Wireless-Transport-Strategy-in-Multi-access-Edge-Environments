package quic

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	list "github.com/quic-go/quic-go/internal/utils/linkedlist"
)

// byteInterval is an interval from one ByteCount to the other
type byteInterval struct {
	Start protocol.ByteCount
	End   protocol.ByteCount
}

var byteIntervalElementPool sync.Pool

var lastReadPosition protocol.ByteCount
var lastLastReadPosition protocol.ByteCount

func init() {
	byteIntervalElementPool = *list.NewPool[byteInterval]()
}

type frameSorterEntry struct {
	Data   []byte
	DoneCb func()
}

type frameSorter struct {
	queue   map[protocol.ByteCount]frameSorterEntry
	readPos protocol.ByteCount
	gaps    *list.List[byteInterval]
}

var errDuplicateStreamData = errors.New("duplicate stream data")

func newFrameSorter() *frameSorter {
	s := frameSorter{
		gaps:  list.NewWithPool[byteInterval](&byteIntervalElementPool),
		queue: make(map[protocol.ByteCount]frameSorterEntry),
	}
	s.gaps.PushFront(byteInterval{Start: 0, End: protocol.MaxByteCount})
	return &s
}

func (s *frameSorter) Push(data []byte, offset protocol.ByteCount, doneCb func()) error {
	// doneCb mainly recall the buffer pool resources
	err := s.push(data, offset, doneCb)
	if err == errDuplicateStreamData {
		if doneCb != nil {
			doneCb()
		}
		return nil
	}
	return err
}

func (s *frameSorter) push(data []byte, offset protocol.ByteCount, doneCb func()) error {
	if len(data) == 0 {
		return errDuplicateStreamData
	}

	// the start offset and the end offset of current frame in this stream
	start := offset
	end := offset + protocol.ByteCount(len(data))

	// s.gaps.Front() means the first offset that still not receive in. So before the Front() means receive a data that have been received (duplicate)
	// end <= s.gaps.Front() is just one type of data that must be duplicated, while the below other cases may have duplicates (duplicates on parts, not the whole)
	if end <= s.gaps.Front().Value.Start {
		return errDuplicateStreamData
	}

	// startGap is the first gap that the start of this gap is lager than Start
	// startsInGap means the start of the frame whether in this gap, it doesn't denote the frame have or have not duplicate data
	// maybe startsInGap = false denotes that the frame have some duplicated data
	startGap, startsInGap := s.findStartGap(start)
	// endGap find the last gap that the start of this gap is smaller than End
	endGap, endsInGap := s.findEndGap(startGap, end)

	startGapEqualsEndGap := startGap == endGap

	if (startGapEqualsEndGap && end <= startGap.Value.Start) ||
		(!startGapEqualsEndGap && startGap.Value.End >= endGap.Value.Start && end <= startGap.Value.Start) {
		return errDuplicateStreamData
	}

	startGapNext := startGap.Next()
	startGapEnd := startGap.Value.End // save it, in case startGap is modified
	endGapStart := endGap.Value.Start // save it, in case endGap is modified
	endGapEnd := endGap.Value.End     // save it, in case endGap is modified
	var adjustedStartGapEnd bool
	var wasCut bool

	pos := start
	var hasReplacedAtLeastOne bool
	for {
		// if we can not find the old entry, means it is a new frame with a new start. We only need to insert it into queue and update gap
		oldEntry, ok := s.queue[pos]
		if !ok {
			break
		}
		oldEntryLen := protocol.ByteCount(len(oldEntry.Data))
		if end-pos > oldEntryLen || (hasReplacedAtLeastOne && end-pos == oldEntryLen) {
			// The existing frame is shorter than the new frame. Replace it.
			delete(s.queue, pos)
			pos += oldEntryLen
			hasReplacedAtLeastOne = true
			if oldEntry.DoneCb != nil {
				// release buffer
				oldEntry.DoneCb()
			}
		} else {
			// The existing frame is longer than the new frame, which means the new frame is meaningless
			if !hasReplacedAtLeastOne {
				return errDuplicateStreamData
			}
			// The existing frame is longer than the new frame.
			// Cut the new frame such that the end aligns with the start of the existing frame.
			data = data[:pos-start]
			end = pos
			wasCut = true
			break
		}
	}

	if !startsInGap && !hasReplacedAtLeastOne {
		// cut the frame, such that it starts at the start of the gap
		data = data[startGap.Value.Start-start:]
		start = startGap.Value.Start
		wasCut = true
	}
	if start <= startGap.Value.Start {
		if end >= startGap.Value.End {
			// The frame covers the whole startGap. Delete the gap.
			s.gaps.Remove(startGap)
		} else {
			startGap.Value.Start = end
		}
	} else if !hasReplacedAtLeastOne {
		startGap.Value.End = start
		adjustedStartGapEnd = true
	}

	if !startGapEqualsEndGap {
		s.deleteConsecutive(startGapEnd)
		var nextGap *list.Element[byteInterval]
		for gap := startGapNext; gap.Value.End < endGapStart; gap = nextGap {
			nextGap = gap.Next()
			s.deleteConsecutive(gap.Value.End)
			s.gaps.Remove(gap)
		}
	}

	if !endsInGap && start != endGapEnd && end > endGapEnd {
		// cut the frame, such that it ends at the end of the gap
		data = data[:endGapEnd-start]
		end = endGapEnd
		wasCut = true
	}
	if end == endGapEnd {
		if !startGapEqualsEndGap {
			// The frame covers the whole endGap. Delete the gap.
			s.gaps.Remove(endGap)
		}
	} else {
		if startGapEqualsEndGap && adjustedStartGapEnd {
			// The frame split the existing gap into two.
			s.gaps.InsertAfter(byteInterval{Start: end, End: startGapEnd}, startGap)
		} else if !startGapEqualsEndGap {
			endGap.Value.Start = end
		}
	}

	if wasCut && len(data) < protocol.MinStreamFrameBufferSize {
		newData := make([]byte, len(data))
		copy(newData, data)
		data = newData
		if doneCb != nil {
			doneCb()
			doneCb = nil
		}
	}

	if s.gaps.Len() > protocol.MaxStreamFrameSorterGaps {
		return errors.New("too many gaps in received data")
	}

	s.queue[start] = frameSorterEntry{Data: data, DoneCb: doneCb}
	return nil
}

func (s *frameSorter) findStartGap(offset protocol.ByteCount) (*list.Element[byteInterval], bool) {
	for gap := s.gaps.Front(); gap != nil; gap = gap.Next() {
		if offset >= gap.Value.Start && offset <= gap.Value.End {
			return gap, true
		}
		if offset < gap.Value.Start {
			return gap, false
		}
	}
	panic("no gap found")
}

func (s *frameSorter) findEndGap(startGap *list.Element[byteInterval], offset protocol.ByteCount) (*list.Element[byteInterval], bool) {
	for gap := startGap; gap != nil; gap = gap.Next() {
		if offset >= gap.Value.Start && offset < gap.Value.End {
			return gap, true
		}
		if offset < gap.Value.Start {
			return gap.Prev(), false
		}
	}
	panic("no gap found")
}

// deleteConsecutive deletes consecutive frames from the queue, starting at pos
func (s *frameSorter) deleteConsecutive(pos protocol.ByteCount) {
	for {
		oldEntry, ok := s.queue[pos]
		if !ok {
			break
		}
		oldEntryLen := protocol.ByteCount(len(oldEntry.Data))
		delete(s.queue, pos)
		if oldEntry.DoneCb != nil {
			oldEntry.DoneCb()
		}
		pos += oldEntryLen
	}
}

func (s *frameSorter) Pop() (protocol.ByteCount, []byte, func()) {
	// readPos is zero initially
	entry, ok := s.queue[s.readPos]
	// MOC: The key is here. Only the entries that are in order and have data in them will be read
	// fmt.Println("all s.readPos: ", s.readPos)
	if !ok {
		// fmt.Println("not ok s.readPos: ", s.readPos)
		// if there is a new offset that have not been received
		if s.readPos == lastReadPosition && s.readPos != seminars[0].currentWaitingOffset &&
			IQPerspective == protocol.PerspectiveClient && seminars[0].ifHandshakeDone {
			seminars[0].timerMap.RLock()
			if _, ok := seminars[0].timerMap.m[s.readPos]; !ok {
				// according to the current read position, start a new timer
				if seminars[0].smoothOneRoundTime.Seconds() > 0 {
					seminars[0].currentWaitingOffset = s.readPos
					go func(readPosition protocol.ByteCount) {
						retransmitTimer := utils.NewTimer()
						defer retransmitTimer.Stop()
						retransmitTimer.Reset(time.Now().Add(8 * seminars[0].smoothOneRoundTime))
						seminars[0].timerMap.Lock()
						seminars[0].timerMap.m[readPosition]++
						seminars[0].timerMap.Unlock()
						select {
						case <-retransmitTimer.Chan():
							// now it still block at here
							if readPosition == seminars[0].currentWaitingOffset {
								fmt.Println("time to send", readPosition, seminars[0].currentWaitingOffset)
								// send the request
								bytesBuffer := bytes.NewBuffer([]byte{})
								binary.Write(bytesBuffer, binary.LittleEndian, readPosition)
								prefix := requestPrefix
								dataForWrite := make([]byte, len(prefix))
								copy(dataForWrite, prefix)
								seminars[0].frameCountMap[readPosition]++
								seminars[0].mainStream.Write(utils.BytesCombine(dataForWrite, bytesBuffer.Bytes()))
								// start a new timer to repeat this process until receive the correct offset
								retransmitTicker := time.NewTicker(8 * seminars[0].smoothOneRoundTime)
								defer retransmitTicker.Stop()
								// if still equal, means no forwarding
								for seminars[0].currentWaitingOffset == readPosition {
									select {
									case <-retransmitTicker.C:
										if seminars[0].currentWaitingOffset == readPosition {
											fmt.Println("SEND AGAIN", seminars[0].currentWaitingOffset, readPosition)
											seminars[0].frameCountMap[readPosition]++
											seminars[0].mainStream.Write(utils.BytesCombine(dataForWrite, bytesBuffer.Bytes()))
										}
									}
								}
							}
							retransmitTimer.SetRead()
						}
					}(s.readPos)
				}
			}
			seminars[0].timerMap.RUnlock()
		}
		lastLastReadPosition = lastReadPosition
		lastReadPosition = s.readPos
		return s.readPos, nil, nil
	}
	lastLastReadPosition = lastReadPosition
	lastReadPosition = s.readPos
	seminars[0].frameCountMutex.Lock()
	seminars[0].frameCount++
	delete(s.queue, s.readPos)
	seminars[0].frameCountMutex.Unlock()
	offset := s.readPos
	s.readPos += protocol.ByteCount(len(entry.Data))
	if s.gaps.Front().Value.End <= s.readPos {
		panic("frame sorter BUG: read position higher than a gap")
	}
	return offset, entry.Data, entry.DoneCb
}

// HasMoreData says if there is any more data queued at *any* offset.
func (s *frameSorter) HasMoreData() bool {
	return len(s.queue) > 0
}
