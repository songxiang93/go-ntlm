//Copyright 2013 Thomson Reuters Global Resources. BSD License please see License file for more information

package ntlm

import (
	"bytes"
	"encoding/binary"
        "errors"
)

type NegotiateMessage struct {
	// sig - 8 bytes
	Signature []byte //[]byte("NTLMSSP\00")
	// message type - 4 bytes
	MessageType uint32 //010000
	// negotiate flags - 4bytes
        NegotiateFlags NegotiateFlags
	// If the NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED flag is not set in NegotiateFlags,
	// indicating that no DomainName is supplied in Payload  - then this should have Len 0 / MaxLen 0
	// this contains a domain name
	DomainNameFields *PayloadStruct
	// If the NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED flag is not set in NegotiateFlags,
	// indicating that no WorkstationName is supplied in Payload - then this should have Len 0 / MaxLen 0
	WorkstationFields *PayloadStruct
	// version - 8 bytes
	Version *VersionStruct
	// payload - variable
	Payload       []byte
}

func ParseNegotiateMessage(body []byte) (*NegotiateMessage, error) {
        if len(body) < 16 {
                return nil, errors.New("Invalid NTLM negotiate message: message is too short.")
        }

        negotiate := new(NegotiateMessage)

        negotiate.Signature = body[0:8]
        if !bytes.Equal(negotiate.Signature, []byte("NTLMSSP\x00")) {
                return negotiate, errors.New("Invalid NTLM message signature")
        }

        negotiate.MessageType = binary.LittleEndian.Uint32(body[8:12])
        if negotiate.MessageType != 1 {
                return negotiate, errors.New("Invalid NTLM message type should be 0x00000001 for negotiate message")
        }

        var err error

        negotiate.NegotiateFlags = ReadNegotiateFlags(body[12:16])

        if NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED.IsSet(negotiate.NegotiateFlags) {
                negotiate.DomainNameFields, err = ReadOemPayload(16, body)
                if err != nil {
                        return nil, err
                }
        }

        if NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED.IsSet(negotiate.NegotiateFlags) {
                negotiate.WorkstationFields, err = ReadOemPayload(24, body)
                if err != nil {
                        return nil, err
                }
        }

        offset := 32

        if NTLMSSP_NEGOTIATE_VERSION.IsSet(negotiate.NegotiateFlags) {

                // [Psiphon]
                // Don't panic on malformed remote input.
                if len(body) < offset+8 {
                        return nil, errors.New("Unvalid negotiate message")
                }

                negotiate.Version, err = ReadVersionStruct(body[offset : offset+8])
                if err != nil {
                        return nil, err
                }
                offset = offset + 8
        }

        negotiate.Payload = body[offset:]

        return negotiate, nil
}

func (nm *NegotiateMessage) Bytes() []byte {
        payloadLen := int(nm.DomainNameFields.Len + nm.WorkstationFields.Len)
        messageLen := 40
        payloadOffset := uint32(messageLen)

        dest := make([]byte, 0, messageLen+payloadLen)
	buffer := bytes.NewBuffer(dest)

	buffer.Write(nm.Signature)
	binary.Write(buffer, binary.LittleEndian, nm.MessageType)
        buffer.Write(nm.NegotiateFlags.Bytes())

        nm.DomainNameFields.Offset = payloadOffset
        payloadOffset += uint32(nm.DomainNameFields.Len)
	buffer.Write(nm.DomainNameFields.Bytes())

        nm.WorkstationFields.Offset = payloadOffset
        payloadOffset += uint32(nm.WorkstationFields.Len)
	buffer.Write(nm.WorkstationFields.Bytes())

	buffer.Write(nm.Version.Bytes())

        // Write out the payloads

        buffer.Write(nm.DomainNameFields.Payload)
        buffer.Write(nm.WorkstationFields.Payload)

	return buffer.Bytes()
}

/*

struct {
        byte    protocol[8];     // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
        byte    type;            // 0x01
        byte    zero[3];
        short   flags;           // 0xb203
        byte    zero[2];

        short   dom_len;         // domain string length
        short   dom_len;         // domain string length
        short   dom_off;         // domain string offset
        byte    zero[2];

        short   host_len;        // host string length
        short   host_len;        // host string length
        short   host_off;        // host string offset (always 0x20)
        byte    zero[2];

        byte    host[*];         // host string (ASCII)
        byte    dom[*];          // domain string (ASCII)
    } type-1-message

*/
