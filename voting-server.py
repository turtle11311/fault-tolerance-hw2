from array import array
import base64
from concurrent import futures
from dataclasses import dataclass
from logging import INFO
import logging
import json
import jsonschema
from random import Random
from typing import Dict, Tuple
import time
from google.protobuf.timestamp_pb2 import Timestamp

from nacl.signing import VerifyKey
from nacl.exceptions import ValueError, BadSignatureError

import grpc
import voting_pb2
import voting_pb2_grpc

class Voter():
    def __init__(self, name: str, group: str, pub_key: bytes) -> None:
        self.name = name
        self.group = group
        self.pub_key = pub_key
    def raise_challange(self) -> bytes:
        self.challange = Random().randbytes(32)
        return self.challange
    def authorize(self, sign: bytes) -> Tuple[bool, bytes]:
        try:
            VerifyKey(self.pub_key).verify(smessage=self.challange, signature=sign)
            self.token = Random().randbytes(32)
            return True, self.token
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

    class JSONEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, Voter):
                return {'name': obj.name, 'group': obj.group, 'public_key': base64.b64encode(obj.pub_key).decode('utf-8')}
            # Let the base class default method raise the TypeError
            return json.JSONEncoder.default(self, obj)

class VotersDataLoader():
    def __init__(self, db_loc: str):
        self.db_loc = db_loc
        self.voters: Dict[str][Voter] = dict()
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
    def voter(self, name: str) -> Voter:
        return self.voters[name]
    def save(self):
        with open(self.db_loc, 'w') as voter_dbs:
            json.dump(list(map(lambda v: v[1],self.voters.items())),fp=voter_dbs,cls=Voter.JSONEncoder)
            voter_dbs.close()

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
        self.elections: Dict[str][Election] = dict()
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
                for elect_data in  elect_collections:
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

    def CreateResultList(self,  name: str, choices: array):
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
        if 0:# check authentication token
            return 1
        elif name not in list(self.elections):# Check if election already exists
            # at least one group and one choice 
            if len(groups) and len(choices):
                self.elections[name] = Election(name=name, groups=list(groups), choices=list(choices) ,end_date=str(end_date.ToJsonString()))
                with open(self.db_loc, 'w') as elect_dbs:
                    json.dump(list(map(lambda v: v[1],self.elections.items())),fp=elect_dbs,cls=Election.JSONEncoder)
                    elect_dbs.close()
                self.CreateResultList(name=name, choices=list(choices))
                return 0
            elif not len(groups) or not len(choices):
                return 2
        else:
            return 3
    
    def UpdateResultList(self,election_name:str, choice_name: str):
        if 0: # check authentication token
            return 1
        elif election_name not in list(self.elections):
            return 2
        elif 0: # check if group is  allowed
            return 3
        else:
            election_index = list(self.elections).index(election_name)
            with open(self.Result_loc, 'r') as electResult_dbs:
                data = json.load(electResult_dbs)
                electResult_dbs.close()
            if 'Voter_name' in data[election_index]['voters']: # insert Voter_name
                return 4
            else:
                with open(self.Result_loc, 'w') as electResult_dbs:
                    data[election_index]['voters'].append('Voter_name') # insert Voter_name
                    json.dump(data, fp=electResult_dbs)
                    electResult_dbs.close()
                return 0
            
    def GetResultList(self, election_name:str):
        if election_name not in list(self.elections):
            # Non-existent election
            return 1,[]
        else:
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
            return 0,data[election_index]['choices']

class eVotingServer(voting_pb2_grpc.eVotingServicer):
    def __init__(self) -> None:
        self.db = VotersDataLoader('voters.json')
        self.electDB = ElectDataLoader('elections.json')
    def PreAuth(self, request, context):
        name = request.name
        try: 
            challange = self.db.voter(name).raise_challange()
            return voting_pb2.Challenge(value=challange)
        except KeyError:
            logging.warning('voter[{}] is not registed in server'.format(name))
            return voting_pb2.Challenge(value=b'')
    def Auth(self, request, context):
        name = request.name.name
        try:
            authorized, token = self.db.voter(name).authorize(request.response.value)
            if authorized:
                logging.info('voter[{}] is authorize with token'.format(name))
            else:
                logging.warning('voter[{}] is authentication failed'.format(name))
            return voting_pb2.AuthToken(value=token)
        except KeyError:
            logging.warning('voter[{}] is not registed in server'.format(name))
            return voting_pb2.AuthToken(value=b'')

    def CreateElection(self,request, context):
        ElectionStatus = self.electDB.CreateElect(request.name, request.groups, request.choices, request.end_date)
        if ElectionStatus==0:
            return voting_pb2.Status(code=ElectionStatus)
        elif ElectionStatus==1:
            return voting_pb2.Status(code=ElectionStatus)
        elif ElectionStatus==2:
            return voting_pb2.Status(code=ElectionStatus)
        else:
            return voting_pb2.Status(code=ElectionStatus)

    def CastVote(self,request, context):
        CastVote_status = self.electDB.UpdateResultList(request.election_name,request.choice_name)
        return voting_pb2.Status(code=CastVote_status)

    def GetResult(self,request, context):
        GetResult_status,GetResult_dic = self.electDB.GetResultList(request.name)
        count = []
        for key in GetResult_dic:
            count.append(voting_pb2.VoteCount(choice_name=key, count=GetResult_dic[key]))
        return voting_pb2.ElectionResult( \
            status = GetResult_status, \
            count = count)    
    
    def serve(self):
        try:
            self._grpc_server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
            voting_pb2_grpc.add_eVotingServicer_to_server(self, self._grpc_server)
            self._grpc_server.add_insecure_port('[::]:50051')
            self._grpc_server.start()
            self._grpc_server.wait_for_termination()
        except KeyboardInterrupt:
            self.db.save()

if __name__ == '__main__':
    logging.basicConfig(level=INFO)
    srv = eVotingServer()
    srv.serve()
        
