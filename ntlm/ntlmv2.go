//Copyright 2013 Thomson Reuters Global Resources. BSD License please see License file for more information

package ntlm

import (
	"bytes"
	rc4P "crypto/rc4"
	"encoding/binary"
	"errors"
	"log"
	"strings"
	"time"
)

/*******************************
 Shared Session Data and Methods
*******************************/

type V2Session struct {
	SessionData
}

func (n *V2Session) SetUserInfo(username string, password string, domain string) {
	n.sequenceNumber = 0
	n.user = username
	n.password = password
	n.userDomain = domain
}

func (n *V2Session) GetUserInfo() (string, string, string) {
	return n.user, n.password, n.userDomain
}

func (n *V2Session) SetMode(mode Mode) {
	n.mode = mode
}

func (n *V2Session) SetTarget(target string) {
	n.target = target
}

func (n *V2Session) Version() int {
	return 2
}

func (n *V2Session) SetNTHash(nthash []byte) {
	if len(nthash) > 0 {
		concat := utf16FromString(strings.ToUpper(n.user) + n.userDomain)
		n.responseKeyNT = hmacMd5(nthash, concat)
	}
}

func (n *V2Session) fetchResponseKeys() (err error) {
	if len(n.responseKeyNT) > 0 {
		return
	}
	// Usually at this point we'd go out to Active Directory and get these keys
	// Here we are assuming we have the information locally
	n.responseKeyLM = lmowfv2(n.user, n.password, n.userDomain)
	n.responseKeyNT = ntowfv2(n.user, n.password, n.userDomain)
	return
}

func (n *V2ServerSession) GetSessionData() *SessionData {
	return &n.SessionData
}

func (n *V2Session) GetSequenceNumber() uint32 {
	return n.sequenceNumber
}
func (n *V2Session) SetSequenceNumber(sequence uint32) {
	n.sequenceNumber = sequence
}

// Define ComputeResponse(NegFlg, ResponseKeyNT, ResponseKeyLM, CHALLENGE_MESSAGE.ServerChallenge, ClientChallenge, Time, ServerName)
// ServerNameBytes - The NtChallengeResponseFields.NTLMv2_RESPONSE.NTLMv2_CLIENT_CHALLENGE.AvPairs field structure of the AUTHENTICATE_MESSAGE payload.
func (n *V2Session) computeExpectedResponses(timestamp []byte, avPairBytes []byte) (err error) {
	temp := concat([]byte{0x01}, []byte{0x01}, zeroBytes(6), timestamp, n.clientChallenge, zeroBytes(4), avPairBytes, zeroBytes(4)) //ConcatenationOf(Responserversion, HiResponserversion,Z(6), Time, ClientChallenge, Z(4), ServerName, Z(4))
	ntProofStr := hmacMd5(n.responseKeyNT, concat(n.serverChallenge, temp))                                                         //NTProofStr to HMAC_MD5(ResponseKeyNT,ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge,temp))
	n.ntChallengeResponse = concat(ntProofStr, temp)                                                                                //ConcatenationOf(NTProofStr, temp)
	//if MsvAvTimestamp is set, lmChallengeResponse should be Z(24)
        v, err := ReadAvPairs(avPairBytes)
        if err != nil {
                return err
        }
	if k := v.Find(MsvAvTimestamp); k != nil {
		n.lmChallengeResponse = make([]byte, 24)
	} else {
		n.lmChallengeResponse = concat(hmacMd5(n.responseKeyNT, concat(n.serverChallenge, n.clientChallenge)), n.clientChallenge)
	}
	n.sessionBaseKey = hmacMd5(n.responseKeyNT, ntProofStr) //HMAC_MD5(ResponseKeyNT, NTProofStr)
	return err
}

//If NTLM v2 is used, KeyExchangeKey MUST be set to the given 128-bit SessionBaseKey value.
func (n *V2Session) computeKeyExchangeKey() (err error) {
	n.keyExchangeKey = n.sessionBaseKey
	return
}

func (n *V2Session) calculateKeys(ntlmRevisionCurrent uint8) (err error) {
	// This lovely piece of code comes courtesy of an the excellent Open Document support system from MSFT
	// In order to calculate the keys correctly when the client has set the NTLMRevisionCurrent to 0xF (15)
	// We must treat the flags as if NTLMSSP_NEGOTIATE_LM_KEY is set.
	// This information is not contained (at least currently, until they correct it) in the MS-NLMP document
	if ntlmRevisionCurrent == 15 {
		//n.NegotiateFlags = NTLMSSP_NEGOTIATE_LM_KEY.Set(n.NegotiateFlags)
	}

	n.ClientSigningKey = signKey(n.NegotiateFlags, n.exportedSessionKey, "Client")
	n.ServerSigningKey = signKey(n.NegotiateFlags, n.exportedSessionKey, "Server")
	n.ClientSealingKey = sealKey(n.NegotiateFlags, n.exportedSessionKey, "Client")
	n.ServerSealingKey = sealKey(n.NegotiateFlags, n.exportedSessionKey, "Server")

	return
}

//Seal returns the sealed message and signature
func (n *V2Session) Seal(message []byte) ([]byte, []byte, error) {
	//for now we are just doing client stuff
	d, s := seal(n.NegotiateFlags, n.clientHandle, n.ClientSigningKey, n.sequenceNumber, message)
	n.sequenceNumber++
	return d, s.Bytes(), nil
}

func (n *V2Session) UnSeal(message []byte) ([]byte, error) {
	//return rc4K(n.ServerSealingKey, message)
	dec := rc4(n.serverHandle, message)
	//move the stream along by calculating signature as well
	NtlmV2Mac(message, int(n.sequenceNumber), n.serverHandle, n.ServerSealingKey, n.ServerSigningKey, n.NegotiateFlags)
	return dec, nil
}

//SealV2 takes a message to seal and a message to sign. Returns each seperately. This is a requirement for DCERP
func (n *V2Session) SealV2(messageToSeal []byte, messageToSign []byte) ([]byte, []byte, error) {
	//for now we are just doing client stuff
	sealedMessage := rc4(n.clientHandle, messageToSeal)
	signature := NtlmV2Mac(messageToSign, int(n.sequenceNumber), n.clientHandle, n.ClientSealingKey, n.ClientSigningKey, n.NegotiateFlags)
	n.sequenceNumber++
	return sealedMessage, signature, nil
}

//Sign returns the signing value of the message
func (n *V2Session) Sign(message []byte) ([]byte, error) {
	sig := mac(n.NegotiateFlags, n.clientHandle, n.ClientSigningKey, uint32(n.sequenceNumber), message)
	n.sequenceNumber++
	return sig.Bytes(), nil
}

//Mildly ghetto that we expose this
func NtlmVCommonMac(message []byte, sequenceNumber int, sealingKey, signingKey []byte, NegotiateFlags NegotiateFlags) []byte {
	var handle *rc4P.Cipher
	// TODO: Need to keep track of the sequence number for connection oriented NTLM
	if NTLMSSP_NEGOTIATE_DATAGRAM.IsSet(NegotiateFlags) && NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.IsSet(NegotiateFlags) {
		handle, _ = reinitSealingKey(sealingKey, sequenceNumber)
	} else if NTLMSSP_NEGOTIATE_DATAGRAM.IsSet(NegotiateFlags) {
		// CONOR: Reinitializing the rc4 cipher on every requst, but not using the
		// algorithm as described in the MS-NTLM document. Just reinitialize it directly.
		handle, _ = rc4Init(sealingKey)
	}
	sig := mac(NegotiateFlags, handle, signingKey, uint32(sequenceNumber), message)
	return sig.Bytes()
}

func NtlmV2Mac(message []byte, sequenceNumber int, handle *rc4P.Cipher, sealingKey, signingKey []byte, NegotiateFlags NegotiateFlags) []byte {
	// TODO: Need to keep track of the sequence number for connection oriented NTLM
	if NTLMSSP_NEGOTIATE_DATAGRAM.IsSet(NegotiateFlags) && NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.IsSet(NegotiateFlags) {
		handle, _ = reinitSealingKey(sealingKey, sequenceNumber)
	} else if NTLMSSP_NEGOTIATE_DATAGRAM.IsSet(NegotiateFlags) {
		// CONOR: Reinitializing the rc4 cipher on every requst, but not using the
		// algorithm as described in the MS-NTLM document. Just reinitialize it directly.
		handle, _ = rc4Init(sealingKey)
	}
	sig := mac(NegotiateFlags, handle, signingKey, uint32(sequenceNumber), message)
	return sig.Bytes()
}

func (n *V2ServerSession) Mac(message []byte, sequenceNumber int) ([]byte, error) {
	mac := NtlmV2Mac(message, sequenceNumber, n.serverHandle, n.ServerSealingKey, n.ServerSigningKey, n.NegotiateFlags)
	return mac, nil
}

func (n *V2ServerSession) VerifyMac(message, expectedMac []byte, sequenceNumber int) (bool, error) {
	mac := NtlmV2Mac(message, sequenceNumber, n.clientHandle, n.ClientSealingKey, n.ClientSigningKey, n.NegotiateFlags)
	return MacsEqual(mac, expectedMac), nil
}

func (n *V2ClientSession) Mac(message []byte, sequenceNumber int) ([]byte, error) {
	mac := NtlmV2Mac(message, sequenceNumber, n.clientHandle, n.ClientSealingKey, n.ClientSigningKey, n.NegotiateFlags)
	return mac, nil
}

func (n *V2ClientSession) VerifyMac(message, expectedMac []byte, sequenceNumber int) (bool, error) {
	mac := NtlmV2Mac(message, sequenceNumber, n.serverHandle, n.ServerSealingKey, n.ServerSigningKey, n.NegotiateFlags)
	return MacsEqual(mac, expectedMac), nil
}

/**************
 Server Session
**************/

type V2ServerSession struct {
	V2Session
}

func (n *V2ServerSession) SetServerChallenge(challenge []byte) {
	n.serverChallenge = challenge
}

func (n *V2ServerSession) ProcessNegotiateMessage(nm *NegotiateMessage) (err error) {
	n.negotiateMessage = nm
	return
}

func (n *V2ServerSession) GenerateChallengeMessage() (cm *ChallengeMessage, err error) {
	cm = new(ChallengeMessage)
	cm.Signature = []byte("NTLMSSP\x00")
	cm.MessageType = uint32(2)
	cm.TargetName, _ = CreateBytePayload(make([]byte, 0))

        flags := NegotiateFlags(0)
	flags = NTLMSSP_NEGOTIATE_KEY_EXCH.Set(flags)
	flags = NTLMSSP_NEGOTIATE_VERSION.Set(flags)
        flags = NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.Set(flags)
	flags = NTLMSSP_NEGOTIATE_TARGET_INFO.Set(flags)
	flags = NTLMSSP_NEGOTIATE_IDENTIFY.Set(flags)
	flags = NTLMSSP_NEGOTIATE_ALWAYS_SIGN.Set(flags)
	flags = NTLMSSP_NEGOTIATE_NTLM.Set(flags)
	flags = NTLMSSP_NEGOTIATE_DATAGRAM.Set(flags)
	flags = NTLMSSP_NEGOTIATE_SIGN.Set(flags)
	flags = NTLMSSP_REQUEST_TARGET.Set(flags)
	flags = NTLMSSP_NEGOTIATE_UNICODE.Set(flags)
	flags = NTLMSSP_NEGOTIATE_128.Set(flags)

	cm.NegotiateFlags = flags

	n.serverChallenge = randomBytes(8)
	cm.ServerChallenge = n.serverChallenge
	cm.Reserved = make([]byte, 8)

	// Create the AvPairs we need
	pairs := new(AvPairs)
	pairs.AddAvPair(MsvAvNbDomainName, utf16FromString("REUTERS"))
	pairs.AddAvPair(MsvAvNbComputerName, utf16FromString("UKBP-CBTRMFE06"))
	pairs.AddAvPair(MsvAvDnsDomainName, utf16FromString("Reuters.net"))
	pairs.AddAvPair(MsvAvDnsComputerName, utf16FromString("ukbp-cbtrmfe06.Reuters.net"))
	pairs.AddAvPair(MsvAvDnsTreeName, utf16FromString("Reuters.net"))
	pairs.AddAvPair(MsvAvEOL, make([]byte, 0))
	cm.TargetInfo = pairs
	cm.TargetInfoPayloadStruct, _ = CreateBytePayload(pairs.Bytes())

	cm.Version = &VersionStruct{ProductMajorVersion: uint8(5), ProductMinorVersion: uint8(1), ProductBuild: uint16(2600), NTLMRevisionCurrent: uint8(15)}
	return cm, nil
}

func (n *V2ServerSession) ProcessAuthenticateMessage(am *AuthenticateMessage) (err error) {
	n.authenticateMessage = am
	n.NegotiateFlags = am.NegotiateFlags
	n.clientChallenge = am.ClientChallenge()
	n.encryptedRandomSessionKey = am.EncryptedRandomSessionKey.Payload
	// Ignore the values used in SetUserInfo and use these instead from the authenticate message
	// They should always be correct (I hope)
	n.user = am.UserName.String()
	n.userDomain = am.DomainName.String()
	log.Printf("(ProcessAuthenticateMessage)NTLM v2 User %s Domain %s", n.user, n.userDomain)

	err = n.fetchResponseKeys()
	if err != nil {
		return err
	}

	timestamp := am.NtlmV2Response.NtlmV2ClientChallenge.TimeStamp
	avPairsBytes := am.NtlmV2Response.NtlmV2ClientChallenge.AvPairs.Bytes()

	err = n.computeExpectedResponses(timestamp, avPairsBytes)
	if err != nil {
		return err
	}

	if !bytes.Equal(am.NtChallengeResponseFields.Payload, n.ntChallengeResponse) {
		if !bytes.Equal(am.LmChallengeResponse.Payload, n.lmChallengeResponse) {
			return errors.New("Could not authenticate")
		}
	}

	err = n.computeKeyExchangeKey()
	if err != nil {
		return err
	}

	n.mic = am.Mic
	am.Mic = zeroBytes(16)

	err = n.computeExportedSessionKey()
	if err != nil {
		return err
	}

	if am.Version == nil {
		//UGH not entirely sure how this could possibly happen, going to put this in for now
		//TODO investigate if this ever is really happening
		am.Version = &VersionStruct{ProductMajorVersion: uint8(5), ProductMinorVersion: uint8(1), ProductBuild: uint16(2600), NTLMRevisionCurrent: uint8(15)}

		log.Printf("Nil version in ntlmv2")
	}

	err = n.calculateKeys(am.Version.NTLMRevisionCurrent)
	if err != nil {
		return err
	}

	n.clientHandle, err = rc4Init(n.ClientSealingKey)
	if err != nil {
		return err
	}
	n.serverHandle, err = rc4Init(n.ServerSealingKey)
	if err != nil {
		return err
	}

	return nil
}

func (n *V2ServerSession) computeExportedSessionKey() (err error) {
	if NTLMSSP_NEGOTIATE_KEY_EXCH.IsSet(n.NegotiateFlags) {
		n.exportedSessionKey, err = rc4K(n.keyExchangeKey, n.encryptedRandomSessionKey)
		if err != nil {
			return err
		}
		// TODO: Calculate mic correctly. This calculation is not producing the right results now
		//n.calculatedMic = HmacMd5(n.exportedSessionKey, concat(n.challengeMessage.Payload, n.authenticateMessage.Bytes))
	} else {
		n.exportedSessionKey = n.keyExchangeKey
		// TODO: Calculate mic correctly. This calculation is not producing the right results now
		// n.calculatedMic = HmacMd5(n.keyExchangeKey, concat(n.challengeMessage.Payload, n.authenticateMessage.Bytes))
	}
	return nil
}

/*************
 Client Session
**************/

type V2ClientSession struct {
	V2Session
}

func (n *V2ClientSession) GenerateNegotiateMessage() (nm *NegotiateMessage, err error) {
	flags := NegotiateFlags(0)
	flags = NTLMSSP_NEGOTIATE_KEY_EXCH.Set(flags)
	flags = NTLMSSP_NEGOTIATE_56.Set(flags)
	flags = NTLMSSP_NEGOTIATE_128.Set(flags)
	flags = NTLMSSP_NEGOTIATE_VERSION.Set(flags)
	flags = NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY.Set(flags)
	flags = NTLMSSP_NEGOTIATE_ALWAYS_SIGN.Set(flags)
	flags = NTLMSSP_NEGOTIATE_NTLM.Set(flags)
	flags = NTLMSSP_NEGOTIATE_LM_KEY.Set(flags)
	flags = NTLMSSP_NEGOTIATE_SEAL.Set(flags)
	flags = NTLMSSP_NEGOTIATE_SIGN.Set(flags)
	flags = NTLMSSP_REQUEST_TARGET.Set(flags)
	flags = NTLM_NEGOTIATE_OEM.Set(flags)
	flags = NTLMSSP_NEGOTIATE_UNICODE.Set(flags)

	neg := new(NegotiateMessage)
	neg.Signature = []byte("NTLMSSP\x00")
	neg.MessageType = 1
	neg.NegotiateFlags = flags //0xe20882b7

	//if NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
	neg.DomainNameFields = new(PayloadStruct)
	//if NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED
	neg.WorkstationFields = new(PayloadStruct)
	neg.Version = &VersionStruct{ProductMajorVersion: uint8(5), ProductMinorVersion: uint8(1), ProductBuild: uint16(2600), NTLMRevisionCurrent: 0x0F}

	n.negotiateMessage = neg

	return neg, nil
}

func (n *V2ClientSession) ProcessChallengeMessage(cm *ChallengeMessage) (err error) {
	n.challengeMessage = cm
	n.serverChallenge = cm.ServerChallenge
	n.clientChallenge = randomBytes(8)

	n.NegotiateFlags = cm.NegotiateFlags

	err = n.fetchResponseKeys()
	if err != nil {
		return err
	}

	timestamp := timeToWindowsFileTime(time.Now())

	if n.mode == ConnectionOrientedMode {
		//get current AvPairs
                pairs, err := ReadAvPairs(cm.TargetInfoPayloadStruct.Payload)
                if err != nil {
                        return err
                }
		//if TargetInfo has an MsvAvTimestamp present, the client SHOULD provide a MIC
		if pairs.Find(MsvAvTimestamp) != nil {
			if pl := pairs.Find(MsvAvFlags); pl != nil { //if MsAvFlags present, Value field, set bit 0x2 to 1
				pl.Value = uint32ToBytes(1)
			} else {
				pairs.AddAvPairPos(len(pairs.List)-1, MsvAvFlags, uint32ToBytes(2))
			}
		}
		single := &SingleHostData{Size: 48, CustomData: []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00}, MachineID: []byte{0x8a, 0xc9, 0x76, 0x46, 0xb9, 0x41, 0x62, 0xc9, 0x5b, 0x16, 0xbb, 0x6e, 0x20, 0x91, 0xbd, 0x7a, 0xd0, 0x42, 0x04, 0xaa, 0x07, 0xa6, 0x2f, 0x1a, 0x2f, 0x3e, 0xce, 0xa0, 0x75, 0x23, 0xf3, 0xef}}
		pairs.AddAvPairPos(len(pairs.List)-1, MsAvRestrictions, single.Bytes())
		pairs.AddAvPairPos(len(pairs.List)-1, MsvChannelBindings, make([]byte, 16)) //all zero
		pairs.AddAvPairPos(len(pairs.List)-1, MsvAvTargetName, utf16FromString(n.target))
		pairs.AddAvPair(MsvAvEOL, make([]byte, 0))

		err = n.computeExpectedResponses(timestamp, pairs.Bytes())
		if err != nil {
			return err
		}
	} else {
		err = n.computeExpectedResponses(timestamp, cm.TargetInfoPayloadStruct.Payload)
		if err != nil {
			return err
		}
	}
	err = n.computeKeyExchangeKey()
	if err != nil {
		return err
	}

	err = n.computeEncryptedSessionKey()
	if err != nil {
		return err
	}

	err = n.calculateKeys(cm.Version.NTLMRevisionCurrent)
	if err != nil {
		return err
	}

	n.clientHandle, err = rc4Init(n.ClientSealingKey)
	if err != nil {
		return err
	}
	n.serverHandle, err = rc4Init(n.ServerSealingKey)
	if err != nil {
		return err
	}
	return nil
}

func (n *V2ClientSession) GenerateAuthenticateMessage() (am *AuthenticateMessage, err error) {
	am = new(AuthenticateMessage)
	am.Signature = []byte("NTLMSSP\x00")
	am.MessageType = uint32(3)
	am.LmChallengeResponse, _ = CreateBytePayload(n.lmChallengeResponse)
	am.NtChallengeResponseFields, _ = CreateBytePayload(n.ntChallengeResponse)
	am.DomainName, _ = CreateStringPayload(n.userDomain)
	am.UserName, _ = CreateStringPayload(n.user)
	// [Psiphon]
	// Set a blank workstation value, which is less distinguishable than the previous hard-coded value.
	// See also: https://github.com/Azure/go-ntlmssp/commit/5e29b886690f00c76b876ae9ab8e31e7c3509203.

	am.Workstation, _ = CreateStringPayload("")
	am.EncryptedRandomSessionKey, _ = CreateBytePayload(n.encryptedRandomSessionKey)
	am.NegotiateFlags = n.NegotiateFlags
	am.Mic = make([]byte, 16)
	am.Version = &VersionStruct{ProductMajorVersion: uint8(5), ProductMinorVersion: uint8(1), ProductBuild: uint16(2600), NTLMRevisionCurrent: 0x0F}
	return am, nil
}

func (n *V2ClientSession) GenerateAuthenticateMessageAV() (am *AuthenticateMessage, err error) {
	am = new(AuthenticateMessage)
	am.Signature = []byte("NTLMSSP\x00")
	am.MessageType = uint32(3)
	am.LmChallengeResponse, _ = CreateBytePayload(n.lmChallengeResponse)
	am.NtChallengeResponseFields, _ = CreateBytePayload(n.ntChallengeResponse)
	am.DomainName, _ = CreateStringPayload(n.userDomain)
	am.UserName, _ = CreateStringPayload(n.user)
	am.Workstation, _ = CreateStringPayload("")
	am.EncryptedRandomSessionKey, _ = CreateBytePayload(n.encryptedRandomSessionKey)
	am.NegotiateFlags = n.NegotiateFlags
	am.Version = &VersionStruct{ProductMajorVersion: uint8(5), ProductMinorVersion: uint8(1), ProductBuild: uint16(2600), NTLMRevisionCurrent: 0x0F}

	//calculate the MIC if needed
	v := concat(n.negotiateMessage.Bytes(), n.challengeMessage.Bytes())
	v = concat(v, am.Bytes())
	v = hmacMd5(n.exportedSessionKey, v)
	am.Mic = v
	return am, nil
}

func (n *V2ClientSession) computeEncryptedSessionKey() (err error) {
	if NTLMSSP_NEGOTIATE_KEY_EXCH.IsSet(n.NegotiateFlags) {
		n.exportedSessionKey = randomBytes(16)
		n.encryptedRandomSessionKey, err = rc4K(n.keyExchangeKey, n.exportedSessionKey)
		if err != nil {
			return err
		}
	} else {
		n.encryptedRandomSessionKey = make([]byte, 0)
		n.exportedSessionKey = n.keyExchangeKey
	}
	return nil
}

/********************************
 NTLM V2 Password hash functions
*********************************/

// Define ntowfv2(Passwd, User, UserDom) as
func ntowfv2(user string, passwd string, userDom string) []byte {
	concat := utf16FromString(strings.ToUpper(user) + userDom)
	return hmacMd5(md4(utf16FromString(passwd)), concat)
}

// Define lmowfv2(Passwd, User, UserDom) as
func lmowfv2(user string, passwd string, userDom string) []byte {
	return ntowfv2(user, passwd, userDom)
}

/********************************
 Helper functions
*********************************/

func timeToWindowsFileTime(t time.Time) []byte {
	var ll int64
	ll = (int64(t.Unix()) * int64(10000000)) + int64(116444736000000000)
	buffer := bytes.NewBuffer(make([]byte, 0, 8))
	binary.Write(buffer, binary.LittleEndian, ll)
	return buffer.Bytes()
}
