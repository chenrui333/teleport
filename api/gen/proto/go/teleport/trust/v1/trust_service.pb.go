// Copyright 2023 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.32.0
// 	protoc        (unknown)
// source: teleport/trust/v1/trust_service.proto

package trustv1

import (
	types "github.com/gravitational/teleport/api/types"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Request for GetCertAuthority
type GetCertAuthorityRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Type of certificate authority.
	Type string `protobuf:"bytes,1,opt,name=type,proto3" json:"type,omitempty"`
	// The domain for the certificate authority.
	Domain string `protobuf:"bytes,2,opt,name=domain,proto3" json:"domain,omitempty"`
	// Whether the private key should be included in the response.
	IncludeKey bool `protobuf:"varint,3,opt,name=include_key,json=includeKey,proto3" json:"include_key,omitempty"`
}

func (x *GetCertAuthorityRequest) Reset() {
	*x = GetCertAuthorityRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_trust_v1_trust_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetCertAuthorityRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetCertAuthorityRequest) ProtoMessage() {}

func (x *GetCertAuthorityRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_trust_v1_trust_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetCertAuthorityRequest.ProtoReflect.Descriptor instead.
func (*GetCertAuthorityRequest) Descriptor() ([]byte, []int) {
	return file_teleport_trust_v1_trust_service_proto_rawDescGZIP(), []int{0}
}

func (x *GetCertAuthorityRequest) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *GetCertAuthorityRequest) GetDomain() string {
	if x != nil {
		return x.Domain
	}
	return ""
}

func (x *GetCertAuthorityRequest) GetIncludeKey() bool {
	if x != nil {
		return x.IncludeKey
	}
	return false
}

// Request for GetCertAuthorities
type GetCertAuthoritiesRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Type of certificate authority.
	Type string `protobuf:"bytes,1,opt,name=type,proto3" json:"type,omitempty"`
	// Whether the private key should be included in the response.
	IncludeKey bool `protobuf:"varint,2,opt,name=include_key,json=includeKey,proto3" json:"include_key,omitempty"`
}

func (x *GetCertAuthoritiesRequest) Reset() {
	*x = GetCertAuthoritiesRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_trust_v1_trust_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetCertAuthoritiesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetCertAuthoritiesRequest) ProtoMessage() {}

func (x *GetCertAuthoritiesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_trust_v1_trust_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetCertAuthoritiesRequest.ProtoReflect.Descriptor instead.
func (*GetCertAuthoritiesRequest) Descriptor() ([]byte, []int) {
	return file_teleport_trust_v1_trust_service_proto_rawDescGZIP(), []int{1}
}

func (x *GetCertAuthoritiesRequest) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *GetCertAuthoritiesRequest) GetIncludeKey() bool {
	if x != nil {
		return x.IncludeKey
	}
	return false
}

// Response for GetCertAuthorities
type GetCertAuthoritiesResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The matching certificate authorities.
	CertAuthoritiesV2 []*types.CertAuthorityV2 `protobuf:"bytes,1,rep,name=cert_authorities_v2,json=certAuthoritiesV2,proto3" json:"cert_authorities_v2,omitempty"`
}

func (x *GetCertAuthoritiesResponse) Reset() {
	*x = GetCertAuthoritiesResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_trust_v1_trust_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetCertAuthoritiesResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetCertAuthoritiesResponse) ProtoMessage() {}

func (x *GetCertAuthoritiesResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_trust_v1_trust_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetCertAuthoritiesResponse.ProtoReflect.Descriptor instead.
func (*GetCertAuthoritiesResponse) Descriptor() ([]byte, []int) {
	return file_teleport_trust_v1_trust_service_proto_rawDescGZIP(), []int{2}
}

func (x *GetCertAuthoritiesResponse) GetCertAuthoritiesV2() []*types.CertAuthorityV2 {
	if x != nil {
		return x.CertAuthoritiesV2
	}
	return nil
}

// Request for DeleteCertAuthority
type DeleteCertAuthorityRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Type of certificate authority.
	Type string `protobuf:"bytes,1,opt,name=type,proto3" json:"type,omitempty"`
	// The domain for the certificate authority.
	Domain string `protobuf:"bytes,2,opt,name=domain,proto3" json:"domain,omitempty"`
}

func (x *DeleteCertAuthorityRequest) Reset() {
	*x = DeleteCertAuthorityRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_trust_v1_trust_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteCertAuthorityRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteCertAuthorityRequest) ProtoMessage() {}

func (x *DeleteCertAuthorityRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_trust_v1_trust_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteCertAuthorityRequest.ProtoReflect.Descriptor instead.
func (*DeleteCertAuthorityRequest) Descriptor() ([]byte, []int) {
	return file_teleport_trust_v1_trust_service_proto_rawDescGZIP(), []int{3}
}

func (x *DeleteCertAuthorityRequest) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *DeleteCertAuthorityRequest) GetDomain() string {
	if x != nil {
		return x.Domain
	}
	return ""
}

// Request for UpsertCertAuthority
type UpsertCertAuthorityRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The certificate authority to create or update.
	CertAuthority *types.CertAuthorityV2 `protobuf:"bytes,1,opt,name=cert_authority,json=certAuthority,proto3" json:"cert_authority,omitempty"`
}

func (x *UpsertCertAuthorityRequest) Reset() {
	*x = UpsertCertAuthorityRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_trust_v1_trust_service_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpsertCertAuthorityRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpsertCertAuthorityRequest) ProtoMessage() {}

func (x *UpsertCertAuthorityRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_trust_v1_trust_service_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpsertCertAuthorityRequest.ProtoReflect.Descriptor instead.
func (*UpsertCertAuthorityRequest) Descriptor() ([]byte, []int) {
	return file_teleport_trust_v1_trust_service_proto_rawDescGZIP(), []int{4}
}

func (x *UpsertCertAuthorityRequest) GetCertAuthority() *types.CertAuthorityV2 {
	if x != nil {
		return x.CertAuthority
	}
	return nil
}

var File_teleport_trust_v1_trust_service_proto protoreflect.FileDescriptor

var file_teleport_trust_v1_trust_service_proto_rawDesc = []byte{
	0x0a, 0x25, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x74, 0x72, 0x75, 0x73, 0x74,
	0x2f, 0x76, 0x31, 0x2f, 0x74, 0x72, 0x75, 0x73, 0x74, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x11, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x76, 0x31, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74,
	0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x21, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2f, 0x6c, 0x65, 0x67, 0x61, 0x63, 0x79, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2f, 0x74,
	0x79, 0x70, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x66, 0x0a, 0x17, 0x47, 0x65,
	0x74, 0x43, 0x65, 0x72, 0x74, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x64, 0x6f, 0x6d,
	0x61, 0x69, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x64, 0x6f, 0x6d, 0x61, 0x69,
	0x6e, 0x12, 0x1f, 0x0a, 0x0b, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x5f, 0x6b, 0x65, 0x79,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0a, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x4b,
	0x65, 0x79, 0x22, 0x50, 0x0a, 0x19, 0x47, 0x65, 0x74, 0x43, 0x65, 0x72, 0x74, 0x41, 0x75, 0x74,
	0x68, 0x6f, 0x72, 0x69, 0x74, 0x69, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12,
	0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74,
	0x79, 0x70, 0x65, 0x12, 0x1f, 0x0a, 0x0b, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x5f, 0x6b,
	0x65, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0a, 0x69, 0x6e, 0x63, 0x6c, 0x75, 0x64,
	0x65, 0x4b, 0x65, 0x79, 0x22, 0x64, 0x0a, 0x1a, 0x47, 0x65, 0x74, 0x43, 0x65, 0x72, 0x74, 0x41,
	0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x69, 0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x46, 0x0a, 0x13, 0x63, 0x65, 0x72, 0x74, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x6f,
	0x72, 0x69, 0x74, 0x69, 0x65, 0x73, 0x5f, 0x76, 0x32, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x16, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x43, 0x65, 0x72, 0x74, 0x41, 0x75, 0x74, 0x68,
	0x6f, 0x72, 0x69, 0x74, 0x79, 0x56, 0x32, 0x52, 0x11, 0x63, 0x65, 0x72, 0x74, 0x41, 0x75, 0x74,
	0x68, 0x6f, 0x72, 0x69, 0x74, 0x69, 0x65, 0x73, 0x56, 0x32, 0x22, 0x48, 0x0a, 0x1a, 0x44, 0x65,
	0x6c, 0x65, 0x74, 0x65, 0x43, 0x65, 0x72, 0x74, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74,
	0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x16, 0x0a, 0x06,
	0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x64, 0x6f,
	0x6d, 0x61, 0x69, 0x6e, 0x22, 0x5b, 0x0a, 0x1a, 0x55, 0x70, 0x73, 0x65, 0x72, 0x74, 0x43, 0x65,
	0x72, 0x74, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x3d, 0x0a, 0x0e, 0x63, 0x65, 0x72, 0x74, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x6f,
	0x72, 0x69, 0x74, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x74, 0x79, 0x70,
	0x65, 0x73, 0x2e, 0x43, 0x65, 0x72, 0x74, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79,
	0x56, 0x32, 0x52, 0x0d, 0x63, 0x65, 0x72, 0x74, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74,
	0x79, 0x32, 0x95, 0x03, 0x0a, 0x0c, 0x54, 0x72, 0x75, 0x73, 0x74, 0x53, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x12, 0x56, 0x0a, 0x10, 0x47, 0x65, 0x74, 0x43, 0x65, 0x72, 0x74, 0x41, 0x75, 0x74,
	0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x12, 0x2a, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x43, 0x65,
	0x72, 0x74, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x16, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x43, 0x65, 0x72, 0x74, 0x41,
	0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x56, 0x32, 0x12, 0x71, 0x0a, 0x12, 0x47, 0x65,
	0x74, 0x43, 0x65, 0x72, 0x74, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x69, 0x65, 0x73,
	0x12, 0x2c, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x74, 0x72, 0x75, 0x73,
	0x74, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x43, 0x65, 0x72, 0x74, 0x41, 0x75, 0x74, 0x68,
	0x6f, 0x72, 0x69, 0x74, 0x69, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2d,
	0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e,
	0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x43, 0x65, 0x72, 0x74, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72,
	0x69, 0x74, 0x69, 0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x5c, 0x0a,
	0x13, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x43, 0x65, 0x72, 0x74, 0x41, 0x75, 0x74, 0x68, 0x6f,
	0x72, 0x69, 0x74, 0x79, 0x12, 0x2d, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e,
	0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x43,
	0x65, 0x72, 0x74, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x12, 0x5c, 0x0a, 0x13, 0x55,
	0x70, 0x73, 0x65, 0x72, 0x74, 0x43, 0x65, 0x72, 0x74, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69,
	0x74, 0x79, 0x12, 0x2d, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x74, 0x72,
	0x75, 0x73, 0x74, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x73, 0x65, 0x72, 0x74, 0x43, 0x65, 0x72,
	0x74, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x16, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2e, 0x43, 0x65, 0x72, 0x74, 0x41, 0x75,
	0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x56, 0x32, 0x42, 0x4e, 0x5a, 0x4c, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61,
	0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f,
	0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2f, 0x76,
	0x31, 0x3b, 0x74, 0x72, 0x75, 0x73, 0x74, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_teleport_trust_v1_trust_service_proto_rawDescOnce sync.Once
	file_teleport_trust_v1_trust_service_proto_rawDescData = file_teleport_trust_v1_trust_service_proto_rawDesc
)

func file_teleport_trust_v1_trust_service_proto_rawDescGZIP() []byte {
	file_teleport_trust_v1_trust_service_proto_rawDescOnce.Do(func() {
		file_teleport_trust_v1_trust_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_trust_v1_trust_service_proto_rawDescData)
	})
	return file_teleport_trust_v1_trust_service_proto_rawDescData
}

var file_teleport_trust_v1_trust_service_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_teleport_trust_v1_trust_service_proto_goTypes = []interface{}{
	(*GetCertAuthorityRequest)(nil),    // 0: teleport.trust.v1.GetCertAuthorityRequest
	(*GetCertAuthoritiesRequest)(nil),  // 1: teleport.trust.v1.GetCertAuthoritiesRequest
	(*GetCertAuthoritiesResponse)(nil), // 2: teleport.trust.v1.GetCertAuthoritiesResponse
	(*DeleteCertAuthorityRequest)(nil), // 3: teleport.trust.v1.DeleteCertAuthorityRequest
	(*UpsertCertAuthorityRequest)(nil), // 4: teleport.trust.v1.UpsertCertAuthorityRequest
	(*types.CertAuthorityV2)(nil),      // 5: types.CertAuthorityV2
	(*emptypb.Empty)(nil),              // 6: google.protobuf.Empty
}
var file_teleport_trust_v1_trust_service_proto_depIdxs = []int32{
	5, // 0: teleport.trust.v1.GetCertAuthoritiesResponse.cert_authorities_v2:type_name -> types.CertAuthorityV2
	5, // 1: teleport.trust.v1.UpsertCertAuthorityRequest.cert_authority:type_name -> types.CertAuthorityV2
	0, // 2: teleport.trust.v1.TrustService.GetCertAuthority:input_type -> teleport.trust.v1.GetCertAuthorityRequest
	1, // 3: teleport.trust.v1.TrustService.GetCertAuthorities:input_type -> teleport.trust.v1.GetCertAuthoritiesRequest
	3, // 4: teleport.trust.v1.TrustService.DeleteCertAuthority:input_type -> teleport.trust.v1.DeleteCertAuthorityRequest
	4, // 5: teleport.trust.v1.TrustService.UpsertCertAuthority:input_type -> teleport.trust.v1.UpsertCertAuthorityRequest
	5, // 6: teleport.trust.v1.TrustService.GetCertAuthority:output_type -> types.CertAuthorityV2
	2, // 7: teleport.trust.v1.TrustService.GetCertAuthorities:output_type -> teleport.trust.v1.GetCertAuthoritiesResponse
	6, // 8: teleport.trust.v1.TrustService.DeleteCertAuthority:output_type -> google.protobuf.Empty
	5, // 9: teleport.trust.v1.TrustService.UpsertCertAuthority:output_type -> types.CertAuthorityV2
	6, // [6:10] is the sub-list for method output_type
	2, // [2:6] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_teleport_trust_v1_trust_service_proto_init() }
func file_teleport_trust_v1_trust_service_proto_init() {
	if File_teleport_trust_v1_trust_service_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_teleport_trust_v1_trust_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetCertAuthorityRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_teleport_trust_v1_trust_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetCertAuthoritiesRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_teleport_trust_v1_trust_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetCertAuthoritiesResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_teleport_trust_v1_trust_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteCertAuthorityRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_teleport_trust_v1_trust_service_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpsertCertAuthorityRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_teleport_trust_v1_trust_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_teleport_trust_v1_trust_service_proto_goTypes,
		DependencyIndexes: file_teleport_trust_v1_trust_service_proto_depIdxs,
		MessageInfos:      file_teleport_trust_v1_trust_service_proto_msgTypes,
	}.Build()
	File_teleport_trust_v1_trust_service_proto = out.File
	file_teleport_trust_v1_trust_service_proto_rawDesc = nil
	file_teleport_trust_v1_trust_service_proto_goTypes = nil
	file_teleport_trust_v1_trust_service_proto_depIdxs = nil
}
