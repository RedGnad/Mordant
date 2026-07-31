package lattigospike

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// ProcessEnrollmentEnvelope is the only payload crossing from one client
// process into the evaluator process. It contains ciphertext and a signed
// enrollment only; it deliberately has no plaintext field.
type ProcessEnrollmentEnvelope struct {
	Ciphertext []byte
	Enrollment []byte
}

const (
	processEnvelopeMagic = "MPE1"
	maxProcessEnvelope   = 128 << 20
)

func (envelope ProcessEnrollmentEnvelope) MarshalBinary() ([]byte, error) {
	if len(envelope.Ciphertext) == 0 || len(envelope.Ciphertext) > maxProcessEnvelope ||
		len(envelope.Enrollment) == 0 || len(envelope.Enrollment) > maxProcessEnvelope {
		return nil, ErrMalformedEnrollment
	}
	var out bytes.Buffer
	out.WriteString(processEnvelopeMagic)
	for _, value := range [][]byte{envelope.Ciphertext, envelope.Enrollment} {
		if err := binary.Write(&out, binary.BigEndian, uint32(len(value))); err != nil {
			return nil, err
		}
		out.Write(value)
	}
	return out.Bytes(), nil
}

func UnmarshalProcessEnrollmentEnvelope(data []byte) (*ProcessEnrollmentEnvelope, error) {
	reader := bytes.NewReader(data)
	magic := make([]byte, len(processEnvelopeMagic))
	if _, err := io.ReadFull(reader, magic); err != nil || string(magic) != processEnvelopeMagic {
		return nil, fmt.Errorf("%w: process envelope header", ErrMalformedEnrollment)
	}
	parts := make([][]byte, 2)
	for index := range parts {
		var length uint32
		if err := binary.Read(reader, binary.BigEndian, &length); err != nil || length == 0 || length > maxProcessEnvelope || uint64(length) > uint64(reader.Len()) {
			return nil, fmt.Errorf("%w: process envelope length", ErrMalformedEnrollment)
		}
		parts[index] = make([]byte, length)
		if _, err := io.ReadFull(reader, parts[index]); err != nil {
			return nil, fmt.Errorf("%w: process envelope truncated", ErrMalformedEnrollment)
		}
	}
	if reader.Len() != 0 {
		return nil, fmt.Errorf("%w: process envelope trailing bytes", ErrMalformedEnrollment)
	}
	return &ProcessEnrollmentEnvelope{Ciphertext: parts[0], Enrollment: parts[1]}, nil
}
