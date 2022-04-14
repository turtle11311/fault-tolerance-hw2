# fault-tolerance-hw2

# eVoting Server

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

## Getting Started

### Run the server
```
python voting-server.py
```
### Run the voter
```
python voter.py
```
### Get the public key
![](https://i.imgur.com/hsEtbpd.png)

### Configure voters
1. Create file "voters.json"
2. Add voter record, public_key is encode by base64

![](https://i.imgur.com/9OwziLW.png)

## Evaluation
* We write "voterTest.py" to test all voter request scenarios, including success and failure cases.

* The voter calls the gRPC stub, and the voter checks whether the response value is the expected value.
```python
try:
    print('\n【Test "CreateElection" function】')
    Election_stub = voting_pb2_grpc.eVotingStub(channel)
    end_time = Timestamp()
    end_time.FromJsonString('2023-01-01T00:00:00Z')
    election_status = Election_stub.CreateElection(voting_pb2.Election(
        name='Election1',
        groups=['student','teacher'],
        choices=['number1','number2'],
        end_date=end_time,
        token=voting_pb2.AuthToken(value=token)))
    if election_status.code==0:
        print('-> Test "Election create" success!')
        logging.info('Election created successfully')
except grpc.RpcError as e:
    logging.error(e)
```
## Implementation

### eVoting Server
The gRPC tool generates the basic servicer class from the project proto file and we need to implement the derived classes of the basic servicer.

### Autenticator
Authenticator is a challenge-response authentication-based component that provides voter authentication. It also provide authorize token to the client and verify token.

### Election Database
The election database provides management of election creation and updates.

### Error handling
In this implementation, errors are handled by raising the Python execption, and the server captures the execption to determine how to return status codes.
