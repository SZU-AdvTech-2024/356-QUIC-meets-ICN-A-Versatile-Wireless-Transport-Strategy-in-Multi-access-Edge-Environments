package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

const addr = "localhost:4242"

const message = `foobar`

// ../3.png ../200.jpeg ../small.jpeg
const pngFileName = "../3.png"

const flvFileName = "../2.flv"

var flv = 0

func getFileSize(fileName string) (int64, error) {
	f, err := os.Stat(fileName)
	if err != nil {
		return 0, err
	}
	return f.Size(), nil
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	// private key
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	// template is setting (signature) of CA (Certificate Authority)
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	// crate CA
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	// before using, need to PEM encode (.pem)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	// the tlsCert contains information about private key and certificate, which can be delivered to client
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}

func sleepForSending() {
	time.Sleep(6 * time.Second)
}

func clientMain(url string) error {
	// ssl key
	//var keyLog io.Writer
	//f, err := os.Create("./ssl.log")
	//if err != nil {
	//	log.Fatal(err)
	//}
	//defer f.Close()
	//keyLog = f

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo-example"},
		//KeyLogWriter:       keyLog,
	}
	var conn quic.Connection
	var err error
	if url != "" {
		conn, err = quic.DialAddr(context.Background(), url, tlsConf, nil)
		if err != nil {
			return err
		}
	} else {
		conn, err = quic.DialAddr(context.Background(), addr, tlsConf, nil)
		if err != nil {
			return err
		}
	}

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return err
	}

	fmt.Printf("Client: Sending '%s'\n", message)

	_, err = stream.Write([]byte(message))
	if err != nil {
		return err
	}

	var fileSize int64
	if flv == 1 {
		fileSize, _ = getFileSize(flvFileName)
	} else {
		fileSize, _ = getFileSize(pngFileName)
	}
	buf := make([]byte, fileSize)
	fmt.Println("Client start reading")
	startTime := time.Now()
	_, err = io.ReadFull(stream, buf)
	if err != nil {
		return err
	}
	fmt.Println("Client Got it")
	fileTime := time.Since(startTime).Seconds()
	goodput := float64(fileSize) / 1024 / 1024 * 8 / (fileTime - float64(6))
	fmt.Println()
	fmt.Printf("Goodput: %.2fMbps \tDelay: %.5fs \tdatalen: %.2fMB \t\n", goodput, fileTime-6, float32(fileSize)/1024/1024)
	fmt.Printf("Stream End Time: %.5fs \n", quic.GetStreamEndTime().Sub(startTime).Seconds()-6)
	//fmt.Println("Frame Count: ", quic.GetFrameCount())
	fmt.Println()

	//err = stream.Close()
	//if err != nil {
	//	return err
	//}
	//fmt.Println("Stream Close")

	return nil
}

// Start a server that echos all data on the first stream opened by the client
func echoServer(url string) error {
	var listener *quic.Listener
	var err error
	if url != "" {
		listener, err = quic.ListenAddr(url, generateTLSConfig(), nil)
		if err != nil {
			return err
		}
	} else {
		listener, err = quic.ListenAddr(addr, generateTLSConfig(), nil)
		if err != nil {
			return err
		}
	}
	// FIXME: just store the data to be sent, this mechanism must be modified in the future because we don't want to modify user's code
	//sendingData := []byte("FOOBAR")
	var file *os.File
	if flv == 1 {
		file, err = os.Open(flvFileName)
	} else {
		file, err = os.Open(pngFileName)
	}
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	fileContent, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	sendingData := fileContent
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return err
		}
		go func() {
			stream, err := conn.AcceptStream(context.Background())
			if err != nil {
				panic(err)
			}
			// Echo through the loggingWriter
			// TODO: why block here? Maybe don't exist an EOF.
			//_, err = io.Copy(loggingWriter{stream}, stream)

			sleepForSending()
			fmt.Println("server stream writing")
			stream.Write(sendingData)
		}()
		println("server done.")
	}
	return err
}

func main() {

	ifClient := flag.Bool("c", false, "client")
	ifServer := flag.Bool("s", false, "server")
	verbose := flag.Bool("v", false, "verbose")
	round := flag.String("r", "", "")
	ifFlv := flag.Bool("flv", false, "")
	flag.Parse()
	urls := flag.Args()

	if !*ifClient && !*ifServer {
		fmt.Println("NO SET A MODE")
		return
	}

	if *ifFlv {
		flv = 1
		quic.BigFileOrSmallFile(true)
	}

	quic.SetTimeTxtName(*round)
	quic.CreateSeminar()

	logger := utils.DefaultLogger

	if *verbose {
		logger.SetLogLevel(utils.LogLevelDebug)
	} else {
		logger.SetLogLevel(utils.LogLevelInfo)
	}
	logger.SetLogTimeFormat("")

	if *ifServer {
		quic.SetIQPerspective(protocol.PerspectiveServer)
		log.Fatal(echoServer(urls[0]))
	} else if *ifClient {
		quic.SetIQPerspective(protocol.PerspectiveClient)
		err := clientMain(urls[0])
		if err != nil {
			log.Fatal(err)
		}
	}

}
