# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: teleport/plugins/v1/plugin_service.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import empty_pb2 as google_dot_protobuf_dot_empty__pb2
from teleport.legacy.types import types_pb2 as teleport_dot_legacy_dot_types_dot_types__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n(teleport/plugins/v1/plugin_service.proto\x12\x13teleport.plugins.v1\x1a\x1bgoogle/protobuf/empty.proto\x1a!teleport/legacy/types/types.proto\"H\n\nPluginType\x12\x12\n\x04type\x18\x01 \x01(\tR\x04type\x12&\n\x0foauth_client_id\x18\x02 \x01(\tR\roauthClientId\"\xe9\x01\n\x13\x43reatePluginRequest\x12\'\n\x06plugin\x18\x01 \x01(\x0b\x32\x0f.types.PluginV1R\x06plugin\x12X\n\x15\x62ootstrap_credentials\x18\x02 \x01(\x0b\x32#.types.PluginBootstrapCredentialsV1R\x14\x62ootstrapCredentials\x12O\n\x12static_credentials\x18\x03 \x01(\x0b\x32 .types.PluginStaticCredentialsV1R\x11staticCredentials\"I\n\x10GetPluginRequest\x12\x12\n\x04name\x18\x01 \x01(\tR\x04name\x12!\n\x0cwith_secrets\x18\x02 \x01(\x08R\x0bwithSecrets\"q\n\x12ListPluginsRequest\x12\x1b\n\tpage_size\x18\x01 \x01(\x05R\x08pageSize\x12\x1b\n\tstart_key\x18\x02 \x01(\tR\x08startKey\x12!\n\x0cwith_secrets\x18\x03 \x01(\x08R\x0bwithSecrets\"[\n\x13ListPluginsResponse\x12)\n\x07plugins\x18\x01 \x03(\x0b\x32\x0f.types.PluginV1R\x07plugins\x12\x19\n\x08next_key\x18\x02 \x01(\tR\x07nextKey\")\n\x13\x44\x65letePluginRequest\x12\x12\n\x04name\x18\x01 \x01(\tR\x04name\"o\n\x1bSetPluginCredentialsRequest\x12\x12\n\x04name\x18\x01 \x01(\tR\x04name\x12<\n\x0b\x63redentials\x18\x02 \x01(\x0b\x32\x1a.types.PluginCredentialsV1R\x0b\x63redentials\"[\n\x16SetPluginStatusRequest\x12\x12\n\x04name\x18\x01 \x01(\tR\x04name\x12-\n\x06status\x18\x02 \x01(\x0b\x32\x15.types.PluginStatusV1R\x06status\" \n\x1eGetAvailablePluginTypesRequest\"e\n\x1fGetAvailablePluginTypesResponse\x12\x42\n\x0cplugin_types\x18\x01 \x03(\x0b\x32\x1f.teleport.plugins.v1.PluginTypeR\x0bpluginTypes\"\xc0\x01\n$SearchPluginStaticCredentialsRequest\x12]\n\x06labels\x18\x01 \x03(\x0b\x32\x45.teleport.plugins.v1.SearchPluginStaticCredentialsRequest.LabelsEntryR\x06labels\x1a\x39\n\x0bLabelsEntry\x12\x10\n\x03key\x18\x01 \x01(\tR\x03key\x12\x14\n\x05value\x18\x02 \x01(\tR\x05value:\x02\x38\x01\"k\n%SearchPluginStaticCredentialsResponse\x12\x42\n\x0b\x63redentials\x18\x01 \x03(\x0b\x32 .types.PluginStaticCredentialsV1R\x0b\x63redentials2\xb4\x06\n\rPluginService\x12P\n\x0c\x43reatePlugin\x12(.teleport.plugins.v1.CreatePluginRequest\x1a\x16.google.protobuf.Empty\x12\x43\n\tGetPlugin\x12%.teleport.plugins.v1.GetPluginRequest\x1a\x0f.types.PluginV1\x12P\n\x0c\x44\x65letePlugin\x12(.teleport.plugins.v1.DeletePluginRequest\x1a\x16.google.protobuf.Empty\x12`\n\x0bListPlugins\x12\'.teleport.plugins.v1.ListPluginsRequest\x1a(.teleport.plugins.v1.ListPluginsResponse\x12`\n\x14SetPluginCredentials\x12\x30.teleport.plugins.v1.SetPluginCredentialsRequest\x1a\x16.google.protobuf.Empty\x12V\n\x0fSetPluginStatus\x12+.teleport.plugins.v1.SetPluginStatusRequest\x1a\x16.google.protobuf.Empty\x12\x84\x01\n\x17GetAvailablePluginTypes\x12\x33.teleport.plugins.v1.GetAvailablePluginTypesRequest\x1a\x34.teleport.plugins.v1.GetAvailablePluginTypesResponse\x12\x96\x01\n\x1dSearchPluginStaticCredentials\x12\x39.teleport.plugins.v1.SearchPluginStaticCredentialsRequest\x1a:.teleport.plugins.v1.SearchPluginStaticCredentialsResponseBRZPgithub.com/gravitational/teleport/api/gen/proto/go/teleport/plugins/v1;pluginsv1b\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'teleport.plugins.v1.plugin_service_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'ZPgithub.com/gravitational/teleport/api/gen/proto/go/teleport/plugins/v1;pluginsv1'
  _SEARCHPLUGINSTATICCREDENTIALSREQUEST_LABELSENTRY._options = None
  _SEARCHPLUGINSTATICCREDENTIALSREQUEST_LABELSENTRY._serialized_options = b'8\001'
  _PLUGINTYPE._serialized_start=129
  _PLUGINTYPE._serialized_end=201
  _CREATEPLUGINREQUEST._serialized_start=204
  _CREATEPLUGINREQUEST._serialized_end=437
  _GETPLUGINREQUEST._serialized_start=439
  _GETPLUGINREQUEST._serialized_end=512
  _LISTPLUGINSREQUEST._serialized_start=514
  _LISTPLUGINSREQUEST._serialized_end=627
  _LISTPLUGINSRESPONSE._serialized_start=629
  _LISTPLUGINSRESPONSE._serialized_end=720
  _DELETEPLUGINREQUEST._serialized_start=722
  _DELETEPLUGINREQUEST._serialized_end=763
  _SETPLUGINCREDENTIALSREQUEST._serialized_start=765
  _SETPLUGINCREDENTIALSREQUEST._serialized_end=876
  _SETPLUGINSTATUSREQUEST._serialized_start=878
  _SETPLUGINSTATUSREQUEST._serialized_end=969
  _GETAVAILABLEPLUGINTYPESREQUEST._serialized_start=971
  _GETAVAILABLEPLUGINTYPESREQUEST._serialized_end=1003
  _GETAVAILABLEPLUGINTYPESRESPONSE._serialized_start=1005
  _GETAVAILABLEPLUGINTYPESRESPONSE._serialized_end=1106
  _SEARCHPLUGINSTATICCREDENTIALSREQUEST._serialized_start=1109
  _SEARCHPLUGINSTATICCREDENTIALSREQUEST._serialized_end=1301
  _SEARCHPLUGINSTATICCREDENTIALSREQUEST_LABELSENTRY._serialized_start=1244
  _SEARCHPLUGINSTATICCREDENTIALSREQUEST_LABELSENTRY._serialized_end=1301
  _SEARCHPLUGINSTATICCREDENTIALSRESPONSE._serialized_start=1303
  _SEARCHPLUGINSTATICCREDENTIALSRESPONSE._serialized_end=1410
  _PLUGINSERVICE._serialized_start=1413
  _PLUGINSERVICE._serialized_end=2233
# @@protoc_insertion_point(module_scope)
