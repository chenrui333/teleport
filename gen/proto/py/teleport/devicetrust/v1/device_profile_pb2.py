# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: teleport/devicetrust/v1/device_profile.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from google.protobuf import timestamp_pb2 as google_dot_protobuf_dot_timestamp__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n,teleport/devicetrust/v1/device_profile.proto\x12\x17teleport.devicetrust.v1\x1a\x1fgoogle/protobuf/timestamp.proto\"\xd9\x02\n\rDeviceProfile\x12;\n\x0bupdate_time\x18\x01 \x01(\x0b\x32\x1a.google.protobuf.TimestampR\nupdateTime\x12)\n\x10model_identifier\x18\x02 \x01(\tR\x0fmodelIdentifier\x12\x1d\n\nos_version\x18\x03 \x01(\tR\tosVersion\x12\x19\n\x08os_build\x18\x04 \x01(\tR\x07osBuild\x12!\n\x0cos_usernames\x18\x05 \x03(\tR\x0bosUsernames\x12.\n\x13jamf_binary_version\x18\x06 \x01(\tR\x11jamfBinaryVersion\x12\x1f\n\x0b\x65xternal_id\x18\x07 \x01(\tR\nexternalId\x12\x32\n\x15os_build_supplemental\x18\x08 \x01(\tR\x13osBuildSupplementalBZZXgithub.com/gravitational/teleport/api/gen/proto/go/teleport/devicetrust/v1;devicetrustv1b\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'teleport.devicetrust.v1.device_profile_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  DESCRIPTOR._serialized_options = b'ZXgithub.com/gravitational/teleport/api/gen/proto/go/teleport/devicetrust/v1;devicetrustv1'
  _DEVICEPROFILE._serialized_start=107
  _DEVICEPROFILE._serialized_end=452
# @@protoc_insertion_point(module_scope)
