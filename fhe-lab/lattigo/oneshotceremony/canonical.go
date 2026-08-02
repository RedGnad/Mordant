package oneshotceremony

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const maxCanonicalField = 1 << 30

var errCanonical = errors.New("non-canonical one-shot ceremony encoding")

type encoder struct {
	bytes.Buffer
}

func (e *encoder) u8(v uint8)   { _ = e.WriteByte(v) }
func (e *encoder) u16(v uint16) { _ = binary.Write(&e.Buffer, binary.BigEndian, v) }
func (e *encoder) u32(v uint32) { _ = binary.Write(&e.Buffer, binary.BigEndian, v) }
func (e *encoder) u64(v uint64) { _ = binary.Write(&e.Buffer, binary.BigEndian, v) }
func (e *encoder) i64(v int64)  { _ = binary.Write(&e.Buffer, binary.BigEndian, v) }

func (e *encoder) fixed(v []byte) { _, _ = e.Write(v) }

func (e *encoder) field(v []byte) {
	e.u32(uint32(len(v)))
	e.fixed(v)
}

func (e *encoder) text(v string) { e.field([]byte(v)) }

type decoder struct {
	*bytes.Reader
}

func newDecoder(data []byte) *decoder { return &decoder{Reader: bytes.NewReader(data)} }

func (d *decoder) u8() (uint8, error) {
	v, err := d.ReadByte()
	return v, canonicalError(err)
}

func (d *decoder) u16() (uint16, error) {
	var v uint16
	err := binary.Read(d, binary.BigEndian, &v)
	return v, canonicalError(err)
}

func (d *decoder) u32() (uint32, error) {
	var v uint32
	err := binary.Read(d, binary.BigEndian, &v)
	return v, canonicalError(err)
}

func (d *decoder) u64() (uint64, error) {
	var v uint64
	err := binary.Read(d, binary.BigEndian, &v)
	return v, canonicalError(err)
}

func (d *decoder) i64() (int64, error) {
	var v int64
	err := binary.Read(d, binary.BigEndian, &v)
	return v, canonicalError(err)
}

func (d *decoder) fixed(size int) ([]byte, error) {
	if size < 0 || size > d.Len() {
		return nil, errCanonical
	}
	v := make([]byte, size)
	_, err := io.ReadFull(d, v)
	return v, canonicalError(err)
}

func (d *decoder) field() ([]byte, error) {
	size, err := d.u32()
	if err != nil || size > maxCanonicalField || uint64(size) > uint64(d.Len()) {
		return nil, errCanonical
	}
	return d.fixed(int(size))
}

func (d *decoder) text() (string, error) {
	v, err := d.field()
	if err != nil {
		return "", err
	}
	return string(v), nil
}

func (d *decoder) done() error {
	if d.Len() != 0 {
		return errCanonical
	}
	return nil
}

func canonicalError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %v", errCanonical, err)
}

func copy32(dst *[32]byte, src []byte) error {
	if len(src) != len(dst[:]) {
		return errCanonical
	}
	copy(dst[:], src)
	return nil
}

func isZero32(v [32]byte) bool { return v == ([32]byte{}) }
