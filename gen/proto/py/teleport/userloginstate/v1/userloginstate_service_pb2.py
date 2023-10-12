# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: teleport/userloginstate/v1/userloginstate_service.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import empty_pb2 as google_dot_protobuf_dot_empty__pb2
from teleport.userloginstate.v1 import userloginstate_pb2 as teleport_dot_userloginstate_dot_v1_dot_userloginstate__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n7teleport/userloginstate/v1/userloginstate_service.proto\x12\x1ateleport.userloginstate.v1\x1a\x1bgoogle/protobuf/empty.proto\x1a/teleport/userloginstate/v1/userloginstate.proto\"\x1b\n\x19GetUserLoginStatesRequest\"t\n\x1aGetUserLoginStatesResponse\x12V\n\x11user_login_states\x18\x01 \x03(\x0b\x32*.teleport.userloginstate.v1.UserLoginStateR\x0fuserLoginStates\".\n\x18GetUserLoginStateRequest\x12\x12\n\x04name\x18\x01 \x01(\tR\x04name\"s\n\x1bUpsertUserLoginStateRequest\x12T\n\x10user_login_state\x18\x01 \x01(\x0b\x32*.teleport.userloginstate.v1.UserLoginStateR\x0euserLoginState\"1\n\x1b\x44\x65leteUserLoginStateRequest\x12\x12\n\x04name\x18\x01 \x01(\tR\x04name\"!\n\x1f\x44\x65leteAllUserLoginStatesRequest2\xeb\x04\n\x15UserLoginStateService\x12\x83\x01\n\x12GetUserLoginStates\x12\x35.teleport.userloginstate.v1.GetUserLoginStatesRequest\x1a\x36.teleport.userloginstate.v1.GetUserLoginStatesResponse\x12u\n\x11GetUserLoginState\x12\x34.teleport.userloginstate.v1.GetUserLoginStateRequest\x1a*.teleport.userloginstate.v1.UserLoginState\x12{\n\x14UpsertUserLoginState\x12\x37.teleport.userloginstate.v1.UpsertUserLoginStateRequest\x1a*.teleport.userloginstate.v1.UserLoginState\x12g\n\x14\x44\x65leteUserLoginState\x12\x37.teleport.userloginstate.v1.DeleteUserLoginStateRequest\x1a\x16.google.protobuf.Empty\x12o\n\x18\x44\x65leteAllUserLoginStates\x12;.teleport.userloginstate.v1.DeleteAllUserLoginStatesRequest\x1a\x16.google.protobuf.EmptyB`Z^github.com/gravitational/teleport/api/gen/proto/go/teleport/userloginstate/v1;userloginstatev1b\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'teleport.userloginstate.v1.userloginstate_service_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'Z^github.com/gravitational/teleport/api/gen/proto/go/teleport/userloginstate/v1;userloginstatev1'
  _GETUSERLOGINSTATESREQUEST._serialized_start=165
  _GETUSERLOGINSTATESREQUEST._serialized_end=192
  _GETUSERLOGINSTATESRESPONSE._serialized_start=194
  _GETUSERLOGINSTATESRESPONSE._serialized_end=310
  _GETUSERLOGINSTATEREQUEST._serialized_start=312
  _GETUSERLOGINSTATEREQUEST._serialized_end=358
  _UPSERTUSERLOGINSTATEREQUEST._serialized_start=360
  _UPSERTUSERLOGINSTATEREQUEST._serialized_end=475
  _DELETEUSERLOGINSTATEREQUEST._serialized_start=477
  _DELETEUSERLOGINSTATEREQUEST._serialized_end=526
  _DELETEALLUSERLOGINSTATESREQUEST._serialized_start=528
  _DELETEALLUSERLOGINSTATESREQUEST._serialized_end=561
  _USERLOGINSTATESERVICE._serialized_start=564
  _USERLOGINSTATESERVICE._serialized_end=1183
# @@protoc_insertion_point(module_scope)
