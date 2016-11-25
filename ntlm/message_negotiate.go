//Copyright 2013 Thomson Reuters Global Resources. BSD License please see License file for more information

package ntlm

import (
	"bytes"
	"encoding/binary"
)

type NegotiateMessage struct {
	// All bytes of the message
	//Bytes []byte

	// sig - 8 bytes
	Signature []byte //[]byte("NTLMSSP\00")
	// message type - 4 bytes
	MessageType uint32 //010000
	// negotiate flags - 4bytes
	NegotiateFlags uint32
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
	PayloadOffset int
}

func (nm *NegotiateMessage) Bytes() []byte {

	dest := make([]byte, 0, 40)
	buffer := bytes.NewBuffer(dest)
	buffer.Write(nm.Signature)
	binary.Write(buffer, binary.LittleEndian, nm.MessageType)
	buffer.Write(uint32ToBytes(nm.NegotiateFlags))
	buffer.Write(nm.DomainNameFields.Bytes())
	buffer.Write(nm.WorkstationFields.Bytes())
	buffer.Write(nm.Version.Bytes())
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
