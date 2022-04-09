from __future__ import annotations
from array import array
import base64
from concurrent import futures
from csv import excel_tab
import logging
import json
import time
import jsonschema
from random import Random
from typing import Dict, Tuple, List
import time
from google.protobuf.timestamp_pb2 import Timestamp

from nacl.signing import VerifyKey
from nacl.exceptions import ValueError, BadSignatureError

import grpc
import voting_pb2
import voting_pb2_grpc

class TokenInvalidError(Exception):
    def __str__(self) -> str:
        return "token Invalid"

class ElectionSpecError(Exception):
    def __init__(self, election_name: str) -> None:
        super().__init__()
        self.election_name = election_name
    def __str__(self) -> str:
        return "Election[{}] provide wrong parameters".format(self.election_name)

class InvalidElecitonNameError(Exception):
    def __init__(self, election_name: str) -> None:
        super().__init__()
        self.election_name = election_name
    def __str__(self) -> str:
        return "Election[{}] not exists".format(self.election_name)

class ElectionOngoingException(Exception):
    def __init__(self, election_name: str) -> None:
        super().__init__()
        self.election_name = election_name
    def __str__(self) -> str:
        return "Election[{}] still ongoing. election result is not available yet.".format(self.voter_name, self.election_name)

class VoterGroupError(Exception):
    def __init__(self, election_name: str, voter_name: str) -> None:
        super().__init__()
        self.election_name = election_name
        self.voter_name = voter_name
    def __str__(self) -> str:
        return "Voter[{}] isn't allow for election {}".format(self.voter_name, self.election_name)

class HasBeenVotedError(Exception):
    def __init__(self, election_name: str, voter_name: str) -> None:
        super().__init__()
        self.election_name = election_name
        self.voter_name = voter_name
    def __str__(self) -> str:
        return "Voter[{}] is casted before in election {}".format(self.voter_name, self.election_name)

class Voter():
    def __init__(self, name: str, group: str, pub_key: bytes) -> None:
        self.name = name
        self.group = group
        self.pub_key = pub_key
        self._auth_state: AuthState = UnAuthenticatedState(self)
        
    class JSONEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, Voter):
                return {'name': obj.name, 'group': obj.group, 'public_key': base64.b64encode(obj.pub_key).decode('utf-8')}
            # Let the base class default method raise the TypeError
            return json.JSONEncoder.default(self, obj)
    
class AuthState():
    def __init__(self, voter: Voter) -> None:
        self.context: Voter = voter
        self._state_name: str = "UNSPECIFY"
    def __str__(self) -> str:
        return self._state_name
    def set_state(self, state: AuthState) -> None:
        logging.debug('Voter[{}] from {} to {}'.format(self.context.name, self.context._auth_state, state))
        self.context._auth_state = state

class UnAuthenticatedState(AuthState):
    def __init__(self, voter: Voter) -> None:
        super().__init__(voter)
        self._state_name: str = "UNAUTHENTICATE"
    def raise_challange(self) -> bytes:
        challange = Random().randbytes(32)
        self.set_state(RaiseChallangeState(self.context, challange))
        return challange

class RaiseChallangeState(AuthState):
    def __init__(self, voter: Voter, challange: bytes) -> None:
        super().__init__(voter)
        self.challange: bytes = challange
        self._state_name: str = "CHALLANGING CLIENT"
    def check_response(self, response: bytes) -> Tuple[bool,bytes]:
        try:
            VerifyKey(self.context.pub_key).verify(smessage=self.challange, signature=response)
            authorized_token = Random().randbytes(32)
            self.set_state(AuthenticatedState(self.context, authorized_token))
            return True, authorized_token
        except ValueError as e:
            logging.warning("Voter[{}] authorize fail: {}".format(self.name, e))
            return False, b''
        except TypeError as e:
            logging.warning("Voter[{}] authorize fail: {}".format(self.name, e))
            return False, b''
        except BadSignatureError as e:
            logging.warning("Voter[{}] authorize fail: {}".format(self.name, e))
            return False, b''
        except:
            logging.warning("Voter[{}] authorize fail: UNSPECIFY".format(self.name))
            return False, b''

class AuthenticatedState(AuthState):
    def __init__(self, voter: Voter, token: bytes) -> None:
        super().__init__(voter)
        self._state_name: str = "AUTHENTICATE"
        self.token = token
        self.expiry_time = time.time() + (60 * 60)
    def verify_token(self, token: bytes) -> None:
        if self.expiry_time < time.time():
            self.set_state(UnAuthenticatedState(self.context))
            raise TokenInvalidError()
        if token != self.token:
            raise TokenInvalidError()

class Authenticator():
    def __init__(self, db_loc: str):
        self.db_loc = db_loc
        self.voters: Dict[str, Voter] = dict()
        self.token_owner: Dict[bytes, str] = dict()
        self.schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "VoterDB",
            "type": "array",
            "items": {
                "$ref": "#/definitions/voter"
            },
            "definitions": {
                "voter": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string"
                        },
                        "group": {
                            "type": "string"
                        },
                        "public_key": {
                            "type": "string",
                            "pattern": "^(?:[A-Za-z0-9+/]{4}){10}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
                        }
                    }
                }
            }
        }
        try:
            with open(self.db_loc, 'r') as voter_dbs:
                voter_collections = json.load(voter_dbs)
                jsonschema.validate(voter_collections, schema=self.schema)
                for voter_data in voter_collections:
                    name = voter_data['name']
                    group = voter_data['group']
                    pub_key = base64.b64decode(voter_data['public_key'])
                    self.voters[name] = Voter(name=name, group=group, pub_key=pub_key)
        except FileNotFoundError:
            with open(self.db_loc, 'w') as voter_dbs:
                voter_dbs.close()
                logging.warning('{} not exist, create it'.format(self.db_loc))
        except jsonschema.ValidationError as e:
            logging.error('db file is corrupted: {}'.format(e))
            exit(1)
    def save(self):
        with open(self.db_loc, 'w') as voter_dbs:
            json.dump(list(map(lambda v: v[1],self.voters.items())),fp=voter_dbs,cls=Voter.JSONEncoder)
            voter_dbs.close()
    def raise_challange(self, name: str) -> bytes:
        voter = self.voters[name]
        if not isinstance(voter._auth_state, UnAuthenticatedState):
            voter._auth_state.set_state(UnAuthenticatedState(voter))
        return voter._auth_state.raise_challange()
    def authorize(self, name: str, sign: bytes) -> Tuple[bool, bytes]:
        voter = self.voters[name]
        if isinstance(voter._auth_state, RaiseChallangeState):
            ok, token = voter._auth_state.check_response(sign)
            if ok:
                self.token_owner[token] = name
            return ok, token
        else:
            return False, b''
    def verify_token(self, token: bytes) -> Voter:
        name = self.token_owner[token]
        voter = self.voters[name]
        if isinstance(voter._auth_state, AuthenticatedState):
            voter._auth_state.verify_token(token)
        else:
            raise TokenInvalidError()

class Election():
    def __init__(self, name: str, groups: array, choices: array, end_date: str) -> None:
        self.name = name
        self.groups = groups
        self.choices = choices
        self.end_date = end_date
        
    class JSONEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, Election):
                return {'name': obj.name, 'groups': obj.groups, 'choices': obj.choices, 'end_date': obj.end_date}
            # Let the base class default method raise the TypeError
            return json.JSONEncoder.default(self, obj)

class ElectDataLoader():
    def __init__(self, db_loc: str):
        self.db_loc = db_loc
        self.Result_loc = 'electionResult.json'
        self.elections: Dict[str, Election] = dict()
        self.schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "ElectDB",
            "type": "array",
            "items": {
                "$ref": "#/definitions/election"
            },
            "definitions": {
                "election": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string"
                        },
                        "groups": {
                            "type": "array"
                        },
                        "choices": {
                            "type": "array"
                        },
                        "end_date": {
                            "type": "string"
                        }
                    }
                }
            }
        }
        try:
            with open(self.db_loc, 'r') as elect_dbs:
                elect_collections = json.load(elect_dbs)
                jsonschema.validate( elect_collections, schema=self.schema)
                for elect_data in elect_collections:
                    name = elect_data['name']
                    groups = elect_data['groups']
                    choices = elect_data['choices']
                    end_date = elect_data['end_date']
                    self.elections[name] = Election(name=name, groups=groups, choices=choices ,end_date=end_date)
        except FileNotFoundError:
            with open(self.db_loc, 'w') as elect_dbs:
                elect_dbs.close()
                logging.warning('{} not exist, create it'.format(self.db_loc))
            with open(self.Result_loc, 'w') as electResult_dbs:
                json.dump([], electResult_dbs)
                electResult_dbs.close()
                logging.warning('{} not exist, create it'.format(self.Result_loc))
        except jsonschema.ValidationError as e:
            logging.error('db file is corrupted: {}'.format(e))
            exit(1)

    def CreateResultList(self, name: str, choices: array):
        with open(self.Result_loc, 'r') as electResult_dbs:
            data = json.load(electResult_dbs)
            electResult_dbs.close()
        with open(self.Result_loc, 'w') as electResult_dbs:
            dict_choices = dict.fromkeys(choices,0) # list convert to dict
            data.append({ \
                'name': name, \
                'choices': dict_choices, \
                'voters' : []
            })
            json.dump(data, fp=electResult_dbs)
            electResult_dbs.close()

    def CreateElect(self, name: str, groups: array, choices: array, end_date: array):
        # election is existing error
        if name in self.elections:
            raise ElectionSpecError(name)
        # at least one group and one choice 
        if not len(groups) or not len(choices):
            raise ElectionSpecError(name)
        self.elections[name] = Election(name=name, groups=list(groups), choices=list(choices) ,end_date=str(end_date.ToJsonString()))
        with open(self.db_loc, 'w') as elect_dbs:
            json.dump(list(map(lambda v: v[1],self.elections.items())),fp=elect_dbs,cls=Election.JSONEncoder)
            elect_dbs.close()
        self.CreateResultList(name=name, choices=list(choices))
    
    def UpdateResultList(self, voter: Voter, election_name: str, choice_name: str):
        try:
            election = self.elections[election_name]
        except KeyError:
            raise InvalidElecitonNameError(election_name)
        
        if voter.group not in election.groups:
            raise VoterGroupError(election_name, voter)
        election_index = list(self.elections).index(election_name)
        with open(self.Result_loc, 'r') as electResult_dbs:
            data = json.load(electResult_dbs)
            electResult_dbs.close()
        if voter.name in data[election_index]['voters']:
            raise HasBeenVotedError(election_name, voter.name)
        with open(self.Result_loc, 'w') as electResult_dbs:
            data[election_index]['choices'][ choice_name]+=1
            data[election_index]['voters'].append(voter.name)
            json.dump(data, fp=electResult_dbs)
            electResult_dbs.close()
            
    def GetResultList(self, election_name: str) -> List[Election]:
        if election_name not in self.elections:
            raise InvalidElecitonNameError(election_name)

        election_index = list(self.elections).index(election_name)
        elecTime = Timestamp()
        CurrentTime = time.time()
        elecTime.FromJsonString(self.elections[election_name].end_date)
        if int(elecTime.seconds) > int(CurrentTime): 
            # The election is still ongoing. Election result is not available yet.
            return 1,[]
        with open(self.Result_loc, 'r') as electResult_dbs:
            data = json.load(electResult_dbs)
            electResult_dbs.close()
        return data[election_index]['choices']

class eVotingServer(voting_pb2_grpc.eVotingServicer):
    def __init__(self) -> None:
        self.authenticator = Authenticator('voters.json')
        self.electDB = ElectDataLoader('elections.json')
    def PreAuth(self, request, context):
        name = request.name
        try: 
            challange = self.authenticator.raise_challange(name)
            return voting_pb2.Challenge(value=challange)
        except KeyError:
            logging.warning('voter[{}] is not registed in server'.format(name))
            return voting_pb2.Challenge(value=b'')
    def Auth(self, request, context):
        name = request.name.name
        signature = request.response.value
        try:
            authorized, token = self.authenticator.authorize(name, signature)
            if authorized:
                logging.info('voter[{}] is authorize with token'.format(name))
                return voting_pb2.AuthToken(value=token)
            else:
                logging.warning('voter[{}] is authentication failed'.format(name))
                return voting_pb2.AuthToken(value=b'')
        except KeyError:
            logging.warning('voter[{}] is not registed in server'.format(name))
            return voting_pb2.AuthToken(value=b'')

    def CreateElection(self, request, context):
        status = 0
        try:
            token = request.token.value
            self.authenticator.verify_token(token)
            self.electDB.CreateElect(request.name, request.groups, request.choices, request.end_date)
        except TokenInvalidError as e:
            logging.warning(e)
            status = 1
        except ElectionSpecError as e:
            logging.warning(e)
            status = 2
        except Exception as e:
            logging.warning(e)
            # Unknown error
            status = 3
        finally:
            return voting_pb2.Status(code=status)

    def CastVote(self, request, context):
        status = 0
        try:
            token = request.token.value
            voter = self.authenticator.verify_token(token)
            self.electDB.UpdateResultList(voter, request.election_name, request.choice_name)
            return voting_pb2.Status(code=0)
        except TokenInvalidError as e:
            logging.warning(e)
            status = 1
        except InvalidElecitonNameError as e:
            logging.warning(e)
            status = 2
        except VoterGroupError as e:
            logging.warning(e)
            status = 3
        except HasBeenVotedError as e:
            logging.warning(e)
            status = 4
        except Exception as e:
            logging.warning(e.with_traceback())
            # Unknown error
            status = 5
        finally:
            return voting_pb2.Status(code=status)

    def GetResult(self,request, context):
        status = 0
        count = []
        try:
            GetResult_dic = self.electDB.GetResultList(request.name)
            count = []
            for key in GetResult_dic:
                count.append(voting_pb2.VoteCount(choice_name=key, count=GetResult_dic[key]))
        except InvalidElecitonNameError as e:
            logging.warning(e)
            status = 1
        finally:
            return voting_pb2.ElectionResult( \
                status = status, \
                count = count)
    
    def serve(self):
        try:
            self._grpc_server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
            voting_pb2_grpc.add_eVotingServicer_to_server(self, self._grpc_server)
            self._grpc_server.add_insecure_port('[::]:50051')
            self._grpc_server.start()
            self._grpc_server.wait_for_termination()
        except KeyboardInterrupt:
            self.authenticator.save()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    srv = eVotingServer()
    srv.serve()
        
