// +build gofuzz

// This fuzz test checks if streaming salsa20 behaves exacely the same way
// that XORStream does.
package salsa20

import (
	"bytes"
	"encoding/binary"
	"errors"

	gs20 "golang.org/x/crypto/salsa20"
)

var decU16 = binary.LittleEndian.Uint16

var fkey = &[32]byte{}
var fnonce = make([]byte, 8)

var sampleData = dr{}

type dr struct{}

func (dr) Read(s []byte) (int, error) {
	for i := 0; i < len(s); i++ {
		s[i] = 0x55
	}

	return len(s), nil
}

func fdecode(in []byte) ([]uint16, uint64, error) {
	if len(in)%2 != 0 {
		return nil, 0, errors.New("odd size")
	}
	if len(in) < 2*2 {
		return nil, 0, errors.New("too small")
	}

	N := decU16(in)
	in = in[2:]
	if N == 0 {
		return nil, 0, errors.New("no samples")
	}

	if len(in)/2 != int(N) {
		return nil, 0, errors.New("wrong length")
	}

	total := uint64(0)
	S := make([]uint16, 0, N)
	for len(in) != 0 {
		a := decU16(in)
		if a == 0 {
			return nil, 0, errors.New("sample of size 0")

		}
		total += uint64(a)
		in = in[2:]
		S = append(S, a)
	}
	return S, total, nil
}

// The in buffer has flowing format:
//  N := little-endian uint16 - specifying number of writes
//  S[N] := series of little-endian uint16 - specifying lengths of writes
func Fuzz(in []byte) int {
	S, total, err := fdecode(in)
	if err != nil {
		return -1
	}

	input := make([]byte, total)
	sampleData.Read(input)

	output := make([]byte, total)
	outputStream := make([]byte, total)

	gs20.XORKeyStream(output, input, fnonce, fkey)

	s20 := New(fkey, fnonce)

	done := uint64(0)
	for _, v := range S {
		s20.XORKeyStream(outputStream[done:done+uint64(v)], input[:v])
		input = input[v:]
		done += uint64(v)
	}

	if !bytes.Equal(output, outputStream) {
		panic("stream no equal to whole buffer")
	}

	return 1
}
