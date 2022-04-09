from __future__ import print_function
import base64
from os import path
from google.protobuf.timestamp_pb2 import Timestamp
from nacl.public import PrivateKey
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import Base64Encoder
from google.protobuf.timestamp_pb2 import Timestamp
import logging
import grpc
import voting_pb2
import voting_pb2_grpc

voter_name = 'Hello'

"""
KeyLoader loads private key from file, and derived the signing key and verify key from private key.
"""
class KeyLoader():
    def __init__(self, key_path: str) -> None:
        sk: bytes = b''
        if path.exists(key_path):
            with open(key_path, 'r') as key_file:
                sk_b64 = key_file.read()
                sk = base64.b64decode(sk_b64)
                key_file.close()
        else:
            sk = PrivateKey.generate()
            with open(key_path, 'w') as key_file:
                sk_b64 = base64.b64encode(bytes(sk)).decode('utf-8')
                key_file.write(sk_b64)
                key_file.close()
        self._private_key = sk
        self._signing_key = SigningKey(seed=bytes(sk))
    @property
    def signing_key(self) -> SigningKey:
        return self._signing_key
    @property
    def verify_key(self) -> VerifyKey:
        return self._signing_key.verify_key

def run():
    key_loader = KeyLoader('voter_key')
    logging.debug('verifykey: {}'.format(key_loader.verify_key.encode(encoder=Base64Encoder).decode('utf-8')))

    with grpc.insecure_channel('localhost:50051') as channel:
        try:
            eVoting_stub = voting_pb2_grpc.eVotingStub(channel)
            rsp = eVoting_stub.PreAuth(voting_pb2.VoterName(name=voter_name))
            signature = key_loader.signing_key.sign(rsp.value)
            rsp = eVoting_stub.Auth(voting_pb2.AuthRequest(
                name=voting_pb2.VoterName(name=voter_name),
                response=voting_pb2.Response(value=signature.signature)
            ))
            token = rsp.value
            logging.debug('token[{}]'.format(token))
            if token != b'':
                logging.info('authorization successs')
        except grpc.RpcError as e:
            logging.error(e)

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

            end_time = Timestamp()
            end_time.FromJsonString('2022-01-01T00:00:00Z')
            election_status = Election_stub.CreateElection(voting_pb2.Election(
                name='Election2',
                groups=['teacher'],
                choices=['number1','number2'],
                end_date=end_time,
                token=voting_pb2.AuthToken(value=token)))
            if election_status.code==0:
                print('-> Test "Election create" success!')
                logging.info('Election created successfully')

            election_status = Election_stub.CreateElection(voting_pb2.Election(
                name='Election2',
                groups=['teacher'],
                choices=['number1','number2'],
                end_date=end_time,
                token=voting_pb2.AuthToken(value=b'123')))
            if election_status.code==1:
                print('-> Test "Invalid authentication token" success!')
                logging.info('Invalid authentication token')

            election_status = Election_stub.CreateElection(voting_pb2.Election(
                name='Election1',
                groups=[],
                choices=[],
                end_date=end_time,
                token=voting_pb2.AuthToken(value=token)))
            if election_status.code==2:
                print('-> Test "Missing groups or choices" success!')
                logging.warning('Missing groups or choices specification')

        except grpc.RpcError as e:
            logging.error(e)


        try:
            print('\n【Test "CastVote" function】')
            CastVote_stub = voting_pb2_grpc.eVotingStub(channel)
            castVote_status = CastVote_stub.CastVote(voting_pb2.Vote(
                election_name='Election1',
                choice_name ='number1',
                token=voting_pb2.AuthToken(value=token)))
            if castVote_status.code==0:
                print('-> Test "successful vote" success!')
                logging.info('Successful vote')

            CastVote_stub = voting_pb2_grpc.eVotingStub(channel)
            castVote_status = CastVote_stub.CastVote(voting_pb2.Vote(
                election_name='Election1000',
                choice_name ='number1',
                token=voting_pb2.AuthToken(value=token)))
            if castVote_status.code==2:
                print('-> Test "Invalid election name" success!')
                logging.warning('Invalid election name')
            
            CastVote_stub = voting_pb2_grpc.eVotingStub(channel)
            castVote_status = CastVote_stub.CastVote(voting_pb2.Vote(
                election_name='Election2',
                choice_name ='number1',
                token=voting_pb2.AuthToken(value=token)))
            if castVote_status.code==3:
                print('-> Test "wrong group" success!')
                logging.warning('The voter’s group is not allowed in the election')

            CastVote_stub = voting_pb2_grpc.eVotingStub(channel)
            castVote_status = CastVote_stub.CastVote(voting_pb2.Vote(
                election_name='Election1',
                choice_name ='number1',
                token=voting_pb2.AuthToken(value=token)))
            if castVote_status.code==4:
                print('-> Test "already voted" success!')
                logging.warning('A previous vote has been cast.')
        except grpc.RpcError as e:
            logging.error(e)

        try:
            print('\n【Test "GetResult" function】')
            GetResult_stub = voting_pb2_grpc.eVotingStub(channel)
            getResult = GetResult_stub.GetResult(voting_pb2.ElectionName(name='Election2'))
            if getResult.status:
                logging.warning('Non-existent election or The election is still ongoing. Election result is not available yet')
            else:
                print('-> Test "The list of choices and the ballot counts" success!')
                for i in range(len(getResult.count)):
                    print('choice name [{}] : {}'.format(getResult.count[i].choice_name, getResult.count[i].count))

            getResult = GetResult_stub.GetResult(voting_pb2.ElectionName(name='Election1'))
            if getResult.status==1:
                print('-> Test "Election result is not available yet" success!')
                logging.warning('The election is still ongoing. Election result is not available yet')
            
            getResult = GetResult_stub.GetResult(voting_pb2.ElectionName(name='Election3'))
            if getResult.status==1:
                print('-> Test "Non-existent election" success!')
                logging.warning('Non-existent election ')
            
        except grpc.RpcError as e:
            logging.error(e)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    run()