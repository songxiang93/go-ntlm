# NTLM Implementation for Go

This is a native implementation of NTLM for Go that was implemented 
 - using the [Microsoft MS-NLMP documentation](http://msdn.microsoft.com/en-us/library/cc236621.aspx)
 - and [a comprehensive description of NTLM](https://davenport.sourceforge.net/ntlm.html) based on research by Eric Glass

## Project status

The library is used by multiple projects, e.g. [rdpgw](https://github.com/bolkedebruin/rdpgw) (a Remote Desktop Gateway server).

The major missing piece is the negotiation of capabilities between the client and the server. Currently, the negotiation flags are hardcoded, which should be fine for most (modern) clients/servers.

Currently, the project is in low maintenance mode. The NTLM protocol is being superseded by newer protocols, but is still required for good compatibility with existing client/server implementations. Feel free to submit an issue or a pull request, but new features are unlikely to be implemented without funding.

## Sample Usage as NTLM Client

```go
import "github.com/ThomsonReutersEikon/go-ntlm/ntlm"

session, err = ntlm.CreateClientSession(ntlm.Version2, ntlm.ConnectionlessMode)
session.SetUserInfo("someuser","somepassword","somedomain")

negotiate := session.GenerateNegotiateMessage()

<send negotiate to server>

challenge, err := ntlm.ParseChallengeMessage(challengeBytes)
session.ProcessChallengeMessage(challenge)

authenticate := session.GenerateAuthenticateMessage()

<send authenticate message to server>
```

## Sample Usage as NTLM Server

```go
session, err := ntlm.CreateServerSession(ntlm.Version2, ntlm.ConnectionlessMode)
session.SetUserInfo("someuser","somepassword","somedomain")
session.SetRequireNtHash(true) // enforce the use of the more secure Nt hash (instead of the accepting the old LM hash)

challenge := session.GenerateChallengeMessage()

<send challenge to client>

<receive authentication bytes>

auth, err := ntlm.ParseAuthenticateMessage(authenticateBytes)
session.ProcessAuthenticateMessage(auth)
```

## Generating a message MAC

Once a session is created you can generate the Mac for a message using:

```go
message := "this is some message to sign"
sequenceNumber := 100
signature, err := session.Mac([]byte(message), sequenceNumber)
```

## License
Copyright Thomson Reuters Global Resources 2013 (BSD-4 License)

_Note that the library was originally developed by Thomson Reuters Global Resources, but is no longer maintained by them._
