// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package rtcp

import (
	"errors"
	"reflect"
	"testing"
)

func TestTApplicationPacketUnmarshal(t *testing.T) {
	for _, test := range []struct {
		Name      string
		Data      []byte
		Want      ApplicationDefined
		WantError error
	}{
		{
			Name: "valid",
			Data: []byte{
				// Application Packet Type + Length(0x0003)
				0x80, 0xcc, 0x00, 0x03,
				// sender=0x4baae1ab
				0x4b, 0xaa, 0xe1, 0xab,
				// name='SUIT'
				0x53, 0x55, 0x49, 0x54,
				// data='ABCD'
				0x41, 0x42, 0x43, 0x44,
			},
			Want: ApplicationDefined{
				SSRC: 0x4baae1ab,
				Name: [4]byte{0x53, 0x55, 0x49, 0x54},
				Data: []byte{0x41, 0x42, 0x43, 0x44},
			},
		}, {
			Name: "validWithPadding",
			Data: []byte{
				// Application Packet Type + Length(0x0002)  (0xA0 has padding bit set)
				0xA0, 0xcc, 0x00, 0x04,
				// sender=0x4baae1ab
				0x4b, 0xaa, 0xe1, 0xab,
				// name='SUIT'
				0x53, 0x55, 0x49, 0x54,
				// data='ABCDE'
				0x41, 0x42, 0x43, 0x44, 0x45,
				// 3 bytes padding as packet length must be a division of 4
				0x03, 0x03, 0x03,
			},
			Want: ApplicationDefined{
				SSRC: 0x4baae1ab,
				Name: [4]byte{0x53, 0x55, 0x49, 0x54},
				Data: []byte{0x41, 0x42, 0x43, 0x44, 0x45},
			},
		}, {
			Name: "invalidAppPacketLengthField",
			Data: []byte{
				// Application Packet Type + invalid Length(0x00FF)
				0x80, 0xcc, 0x00, 0xFF,
				// sender=0x4baae1ab
				0x4b, 0xaa, 0xe1, 0xab,
				// name='SUIT'
				0x53, 0x55, 0x49, 0x54,
				// data='ABCD'
				0x41, 0x42, 0x43, 0x44,
			},
			WantError: errAppDefinedInvalidLength,
		}, {
			Name: "invalidPacketLengthTooShort",
			Data: []byte{
				// Application Packet Type + Length(0x0002). Total packet length is less than 12 bytes
				0x80, 0xcc, 0x00, 0x2,
				// sender=0x4baae1ab
				0x4b, 0xaa, 0xe1, 0xab,
				// name='SUI'
				0x53, 0x55, 0x49,
			},
			WantError: errPacketTooShort,
		},
		{
			Name: "wrongPaddingSize",
			Data: []byte{
				// Application Packet Type + Length(0x0002)  (0xA0 has padding bit set)
				0xA0, 0xcc, 0x00, 0x04,
				// sender=0x4baae1ab
				0x4b, 0xaa, 0xe1, 0xab,
				// name='SUIT'
				0x53, 0x55, 0x49, 0x54,
				// data='ABCDE'
				0x41, 0x42, 0x43, 0x44, 0x45,
				// 3 bytes padding as packet length must be a division of 4
				0x03, 0x03, 0x09, // last byte has padding size 0x09 which is more than the data + padding bytes
			},
			WantError: errWrongPadding,
		},
		{
			Name: "invalidHeader",
			Data: []byte{
				// Application Packet Type + invalid Length(0x00FF)
				0xFF,
			},
			WantError: errPacketTooShort,
		},
	} {
		var apk ApplicationDefined
		err := apk.Unmarshal(test.Data)
		if got, want := err, test.WantError; !errors.Is(got, want) {
			t.Fatalf("Unmarshal %q result: got = %v, want %v", test.Name, got, want)
		}
		if err != nil {
			continue
		}

		if got, want := apk, test.Want; !reflect.DeepEqual(got, want) {
			t.Fatalf("Unmarshal %q result: got %v, want %v", test.Name, got, want)
		}

		// Check SSRC is matching
		if apk.SSRC != 0x4baae1ab {
			t.Fatalf("SSRC %q result: got packet SSRC %x instead of %x", test.Name, apk.SSRC, 0x4baae1ab)
		}

	}
}
func TestTApplicationPacketMarshal(t *testing.T) {
	for _, test := range []struct {
		Name      string
		Want      []byte
		Packet    ApplicationDefined
		WantError error
	}{
		{
			Name: "valid",
			Want: []byte{
				// Application Packet Type + Length(0x0003)
				0x80, 0xcc, 0x00, 0x03,
				// sender=0x4baae1ab
				0x4b, 0xaa, 0xe1, 0xab,
				// name='SUIT'
				0x53, 0x55, 0x49, 0x54,
				// data='ABCD'
				0x41, 0x42, 0x43, 0x44,
			},
			Packet: ApplicationDefined{
				SSRC: 0x4baae1ab,
				Name: [4]byte{0x53, 0x55, 0x49, 0x54},
				Data: []byte{0x41, 0x42, 0x43, 0x44},
			},
		}, {
			Name: "validWithPadding",
			Want: []byte{
				// Application Packet Type + Length(0x0002)  (0xA0 has padding bit set)
				0xA0, 0xcc, 0x00, 0x04,
				// sender=0x4baae1ab
				0x4b, 0xaa, 0xe1, 0xab,
				// name='SUIT'
				0x53, 0x55, 0x49, 0x54,
				// data='ABCDE'
				0x41, 0x42, 0x43, 0x44, 0x45,
				// 3 bytes padding as packet length must be a division of 4
				0x03, 0x03, 0x03,
			},
			Packet: ApplicationDefined{
				SSRC: 0x4baae1ab,
				Name: [4]byte{0x53, 0x55, 0x49, 0x54},
				Data: []byte{0x41, 0x42, 0x43, 0x44, 0x45},
			},
		}, {
			Name:      "invalidDataTooLarge",
			WantError: errAppDefinedDataTooLarge,
			Packet: ApplicationDefined{
				SSRC: 0x4baae1ab,
				Name: [4]byte{0x53, 0x55, 0x49, 0x54},
				Data: make([]byte, 0xFFFF-12+1), // total max packet size is 0xFFFF including header and other fields.
			},
		},
	} {
		rawPacket, err := test.Packet.Marshal()

		// Check for expected errors
		if got, want := err, test.WantError; !errors.Is(got, want) {
			t.Fatalf("Unmarshal %q result: got = %v, want %v", test.Name, got, want)
		}
		if err != nil {
			continue
		}

		// Check for expected succesful result
		if got, want := rawPacket, test.Want; !reflect.DeepEqual(got, want) {
			t.Fatalf("Unmarshal %q result: got %v, want %v", test.Name, got, want)
		}

		// Check if MarshalSize() is matching the marshalled bytes
		marshalSize := test.Packet.MarshalSize()
		if marshalSize != len(rawPacket) {
			t.Fatalf("MarshalSize %q result: got %d bytes instead of %d", test.Name, len(rawPacket), marshalSize)
		}
	}
}
