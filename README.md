# fault-tolerance-hw2

## eVoting Server

### How to configure voter
1. Create file **voters.json**
2. Add voter record, public_key is encode by base64
```json
[
    {
        "name": "voter1",
        "group": "group1",
        "public_key": "bWE2eocJ/pNkWyXiCg/CtInAAgvVPOGsvbWtti4hBws="
    }
]
```

### Voter Key
Voter's singning key is derived by secrect key, the secret key is store in **voter_key**.If key file is not exists, the key will be generated automatically when the program is executed for the first time.

And voter's verify key (public key) will show on the screen.

## Implementation

### eVoting Server
The gRPC tool generates the basic servicer class from the project proto file and we need to implement the derived classes of the basic servicer.

### Autenticator
Authenticator is a challenge-response authentication-based component that provides voter authentication. It also provide authorize token to the client and verify token.

### Election Database
The election database provides management of election creation and updates.

### Error handling
In this implementation, errors are handled by raising the Python execption, and the server captures the execption to determine how to return status codes.
