//Copyright 2013 Thomson Reuters Global Resources. BSD License please see License file for more information

package ntlm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

type ChallengeMessage struct {
	// sig - 8 bytes
	Signature []byte
	// message type - 4 bytes
	MessageType uint32
	// targetname - 12 bytes
	TargetName *PayloadStruct
	// negotiate flags - 4bytes
	NegotiateFlags NegotiateFlags
	// server challenge - 8 bytes
	ServerChallenge []byte

	// MS-NLMP and Davenport disagree a little on the next few fields and how optional they are
	// This is what Davenport has to say:
	// As with the Type 1 message, there are a few versions of the Type 2 that have been observed:
	//
	// Version 1 -- The Context, Target Information, and OS Version structure are all omitted. The data block
	// (containing only the contents of the Target Name security buffer) begins at offset 32. This form
	// is seen in older Win9x-based systems, and is roughly documented in the Open Group's ActiveX reference
	// documentation (Section 11.2.3).
	//
	// Version 2 -- The Context and Target Information fields are present, but the OS Version structure is not.
	// The data block begins after the Target Information header, at offset 48. This form is seen in most out-of-box
	// shipping versions of Windows.
	//
	// Version 3 -- The Context, Target Information, and OS Version structure are all present. The data block begins
	// after the OS Version structure, at offset 56. Again, the buffers may be empty (yielding a zero-length data block).
	// This form was introduced in a relatively recent Service Pack, and is seen on currently-patched versions of Windows 2000,
	// Windows XP, and Windows 2003.

	// reserved - 8 bytes (set to 0). This field is also known as 'context' in the davenport documentation
	Reserved []byte

	// targetinfo  - 12 bytes
	TargetInfo              *AvPairs

	// version - 8 bytes
	Version *VersionStruct
	// payload - variable
	Payload []byte
}

func ParseChallengeMessage(body []byte) (*ChallengeMessage, error) {
	challenge := new(ChallengeMessage)

	// [Psiphon]
	// Don't panic on malformed remote input.
	if len(body) < 40 {
		return nil, errors.New("invalid challenge message")
	}
	challenge.Signature = body[0:8]
	if !bytes.Equal(challenge.Signature, []byte("NTLMSSP\x00")) {
		return challenge, errors.New("Invalid NTLM message signature")
	}

	challenge.MessageType = binary.LittleEndian.Uint32(body[8:12])
	if challenge.MessageType != 2 {
		return challenge, errors.New("Invalid NTLM message type should be 0x00000002 for challenge message")
	}

	challenge.NegotiateFlags = ReadNegotiateFlags(body[20:24])

	var err error

	challenge.TargetName, err = challenge.readStringPayload(12, body)
	if err != nil {
		return nil, err
	}

	challenge.ServerChallenge = body[24:32]

	challenge.Reserved = body[32:40]

	targetInfoPayloadStruct, err := ReadBytePayload(40, body)
	if err != nil {
		return nil, err
	}

	challenge.TargetInfo, err = ReadAvPairs(targetInfoPayloadStruct.Payload)
	if err != nil {
		return nil, err
	}

	offset := 48

	if NTLMSSP_NEGOTIATE_VERSION.IsSet(challenge.NegotiateFlags) {
		// [Psiphon]
		// Don't panic on malformed remote input.
		if len(body) < offset+8 {
			return nil, errors.New("invalid challenge message")
		}
		challenge.Version, err = ReadVersionStruct(body[offset : offset+8])
		if err != nil {
			return nil, err
		}
		offset = offset + 8
	}

	// [Psiphon]
	// Don't panic on malformed remote input.
	if len(body) < offset {
		return nil, errors.New("invalid challenge message")
	}

	challenge.Payload = body[offset:]

	return challenge, nil
}

func (c *ChallengeMessage) Bytes() []byte {
        targetInfoPayloadStruct, _ := CreateBytePayload(c.TargetInfo.Bytes())

	payloadLen := int(c.TargetName.Len + targetInfoPayloadStruct.Len)
	messageLen := 8 + 4 + 8 + 4 + 8 + 8 + 8 + 8
	payloadOffset := uint32(messageLen)

	messageBytes := make([]byte, 0, messageLen+payloadLen)
	buffer := bytes.NewBuffer(messageBytes)

	buffer.Write(c.Signature)
	binary.Write(buffer, binary.LittleEndian, c.MessageType)

	c.TargetName.Offset = payloadOffset
	buffer.Write(c.TargetName.Bytes())
	payloadOffset += uint32(c.TargetName.Len)

	binary.Write(buffer, binary.LittleEndian, c.NegotiateFlags)
	buffer.Write(c.ServerChallenge)
	buffer.Write(make([]byte, 8))

	targetInfoPayloadStruct.Offset = payloadOffset
	buffer.Write(targetInfoPayloadStruct.Bytes())
	payloadOffset += uint32(targetInfoPayloadStruct.Len)

	// if(c.Version != nil) {
	buffer.Write(c.Version.Bytes())
	// } else {
	//  buffer.Write(make([]byte, 8))
	//}

	// Write out the payloads
	buffer.Write(c.TargetName.Payload)
	buffer.Write(targetInfoPayloadStruct.Payload)

	return buffer.Bytes()
}

func (c *ChallengeMessage) readStringPayload (startByte int, bytes []byte) (*PayloadStruct, error) {
        if NTLMSSP_NEGOTIATE_UNICODE.IsSet(c.NegotiateFlags) {
                return ReadUnicodePayload(startByte, bytes)
        } else if NTLM_NEGOTIATE_OEM.IsSet(c.NegotiateFlags) {
                return ReadOemPayload(startByte, bytes)
        }

        return nil, errors.New("no encoding specified")
}

func (c *ChallengeMessage) String() string {
	var buffer bytes.Buffer

	buffer.WriteString("Challenge NTLM Message")
	buffer.WriteString(fmt.Sprintf("\nTargetName: %s", c.TargetName.String()))
	buffer.WriteString(fmt.Sprintf("\nServerChallenge: %s", hex.EncodeToString(c.ServerChallenge)))
	if c.Version != nil {
		buffer.WriteString(fmt.Sprintf("\nVersion: %s\n", c.Version.String()))
	}
	buffer.WriteString("\nTargetInfo")
	buffer.WriteString(c.TargetInfo.String())
	buffer.WriteString(fmt.Sprintf("\nFlags %d\n", c.NegotiateFlags))
	buffer.WriteString(FlagsToString(c.NegotiateFlags))

	return buffer.String()
}
