import base64
from concurrent import futures
from dataclasses import dataclass
from logging import INFO
import logging
import json
import jsonschema
from random import Random
from typing import Dict, Tuple

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

class eVotingServer(voting_pb2_grpc.eVotingServicer):
    def __init__(self) -> None:
        self.db = VotersDataLoader('voters.json')
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
        
