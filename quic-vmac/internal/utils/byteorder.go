package utils

import (
	"bytes"
	"io"
)

// A ByteOrder specifies how to convert byte sequences into 16-, 32-, or 64-bit unsigned integers.
type ByteOrder interface {
	Uint32([]byte) uint32
	Uint24([]byte) uint32
	Uint16([]byte) uint16

	ReadUint32(io.ByteReader) (uint32, error)
	ReadUint24(io.ByteReader) (uint32, error)
	ReadUint16(io.ByteReader) (uint16, error)

	WriteUint32(*bytes.Buffer, uint32)
	WriteUint24(*bytes.Buffer, uint32)
	WriteUint16(*bytes.Buffer, uint16)
}

func BytesCombine(pBytes ...[]byte) []byte {
	length := len(pBytes)
	s := make([][]byte, length)
	for index := 0; index < length; index++ {
		s[index] = pBytes[index]
	}
	sep := []byte("")
	return bytes.Join(s, sep)
}
