package quic

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

// a seminar is combined with a data, which can be interested from multiple clients

const (
	// BaseDataName should be set in transport parameters
	BaseDataName           = "CHAT_GPT"
	oneRoundTimeAlpha      = 0.125
	oneRoundTimeMinusAlpha = 1 - oneRoundTimeAlpha
	requestPrefix          = "reRequest"
)

var (
	IQPerspective protocol.Perspective
	// IQDataToBeSent is the original data to be sent
	IQDataToBeSent []byte
	// ICN-QUIC
	seminars              []Seminar
	timeSuffix            string
	isBigFile             = false
	streamEndTime         time.Time
	recordOnce            sync.Once
	receivedPacketsNumber int
	finalPacketsNumber    int
)

type Seminar struct {
	// dataName is set when a new client request in, and it is a new name in the request
	dataName string

	// seminarID is hash format of dataName
	seminarID protocol.ByteCount

	// connections either include the only connection (client) or include all the connections received (server)
	// By this way, it can always use the active connectionID and stream
	connections []*connection

	// mainStream is used to sending main data
	mainStream Stream

	// have already set the main stream
	ifSetMainStream bool

	// whether the handshake process done, once handshake done, the transmission turns to v-mac multicast
	// Note that this variable will change anytime (every time a new connection in, set false, handshake done, set true), so the usage of it must consider changing
	ifHandshakeDone bool

	// TODO: Due to one experiment has multiple handshake process, so it should be an array about handshake done. Now when a new connection in, reset the value

	// Notes that when setting the below two values, only one round sending can be run
	// maxReceivedStreamData is the maximum value of all the streams that have sent a MAX_STREAM_DATA frame
	maxReceivedStreamData protocol.ByteCount

	// maxReceivedData is the maximum value of all the connections that have sent a MAX_DATA frame
	maxReceivedData protocol.ByteCount

	// the time that receive the last packet
	lastReceiveTime time.Time

	// smoothOneRoundTime calculate the diff of receive time between two packets
	smoothOneRoundTime time.Duration

	// offsetPnMap map an offset to its origin packet number
	offsetPnMap struct {
		sync.RWMutex
		m map[protocol.ByteCount]protocol.PacketNumber
	}

	// timerMap denotes if an offset have been set the reRequest timer
	timerMap struct {
		sync.RWMutex
		m map[protocol.ByteCount]protocol.PacketNumber
	}

	currentWaitingOffset protocol.ByteCount

	marginTimeMutex sync.Mutex

	frameCount protocol.ByteCount

	frameCountMap map[protocol.ByteCount]int

	frameCountMutex sync.Mutex

	packetMarginTimeWriter *os.File

	seminarError error

	logger utils.Logger
}

func newSeminar(dataName string) *Seminar {
	f, err := os.OpenFile("packetMarginTime"+timeSuffix+".txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		log.Fatal(err)
	}
	return &Seminar{
		dataName:              dataName,
		logger:                utils.DefaultLogger.WithPrefix("seminar"),
		seminarID:             0,
		connections:           make([]*connection, 0),
		seminarError:          nil,
		ifHandshakeDone:       false,
		ifSetMainStream:       false,
		maxReceivedStreamData: protocol.DefaultInitialMaxStreamData,
		maxReceivedData:       protocol.DefaultInitialMaxData,
		offsetPnMap: struct {
			sync.RWMutex
			m map[protocol.ByteCount]protocol.PacketNumber
		}{m: make(map[protocol.ByteCount]protocol.PacketNumber)},
		timerMap: struct {
			sync.RWMutex
			m map[protocol.ByteCount]protocol.PacketNumber
		}{m: make(map[protocol.ByteCount]protocol.PacketNumber)},
		frameCount:             0,
		frameCountMap:          make(map[protocol.ByteCount]int),
		packetMarginTimeWriter: f,
	}
}

func createOrUpdateSeminar(dataName string) {
	fmt.Println("Creating Seminar...")
	if len(seminars) == 0 {
		seminars = append(seminars, *newSeminar(dataName))
	} else if dataName != BaseDataName {
		fmt.Errorf("could not handle different dataName now")
	}
}

func SetIQPerspective(p protocol.Perspective) {
	IQPerspective = p
}

// SetSendingData is a temporary function aiming at saving the original payload
// since we block the Write() in send_stream.go, we need to make seminar have ability to call Write() again
func SetSendingData(data []byte) {
	IQDataToBeSent = data
}

func SetTimeTxtName(suffix string) {
	timeSuffix = suffix
}

func GetFrameCount() protocol.ByteCount {
	seminars[0].packetMarginTimeWriter.WriteString("\n\n\n")
	seminars[0].packetMarginTimeWriter.Close()
	// for i := 1; i < 5; i++ {
	// 	seminars[0].frameCountMap[1123]++
	// }
	// for i := 1; i < 4; i++ {
	// 	seminars[0].frameCountMap[5123]++
	// }
	// for i := 1; i < 2; i++ {
	// 	seminars[0].frameCountMap[4123]++
	// }
	// for i := 1; i < 2; i++ {
	// 	seminars[0].frameCountMap[22123]++
	// }
	// for i := 1; i < 2; i++ {
	// 	seminars[0].frameCountMap[33123]++
	// }
	// for i := 1; i < 3; i++ {
	// 	seminars[0].frameCountMap[3123]++
	// }
	// for i := 1; i < 6; i++ {
	// 	seminars[0].frameCountMap[61232]++
	// }
	newCountmap := make(map[int]int)
	for _, v := range seminars[0].frameCountMap {
		newCountmap[v]++
	}
	fmt.Println("Stream End Packets Number and total Packets Number: ", finalPacketsNumber, receivedPacketsNumber)
	fmt.Println("frame count map: ", len(seminars[0].frameCountMap), seminars[0].frameCountMap)
	fmt.Println("newCountMap: ", newCountmap)
	return seminars[0].frameCount
}

func CreateSeminar() {
	createOrUpdateSeminar("CHAT_GPT")
}

func BigFileOrSmallFile(big bool) {
	if big {
		isBigFile = true
	} else {
		isBigFile = false
	}
}

func GetStreamEndTime() time.Time {
	return streamEndTime
}

//func init() {
//	createOrUpdateSeminar("CHAT_GPT")
//}
