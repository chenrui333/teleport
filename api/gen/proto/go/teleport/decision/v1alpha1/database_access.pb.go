// Copyright 2024 Gravitational, Inc
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
// 	protoc-gen-go v1.35.1
// 	protoc        (unknown)
// source: teleport/decision/v1alpha1/database_access.proto

package decisionv1alpha1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// EvaluateDatabaseAccessRequest describes a request to evaluate wether or not a given
// database access attempt should be permitted.
type EvaluateDatabaseAccessRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Metadata    *RequestMetadata `protobuf:"bytes,1,opt,name=metadata,proto3" json:"metadata,omitempty"`
	TlsIdentity *TLSIdentity     `protobuf:"bytes,2,opt,name=tls_identity,json=tlsIdentity,proto3" json:"tls_identity,omitempty"`
}

func (x *EvaluateDatabaseAccessRequest) Reset() {
	*x = EvaluateDatabaseAccessRequest{}
	mi := &file_teleport_decision_v1alpha1_database_access_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *EvaluateDatabaseAccessRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EvaluateDatabaseAccessRequest) ProtoMessage() {}

func (x *EvaluateDatabaseAccessRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_decision_v1alpha1_database_access_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EvaluateDatabaseAccessRequest.ProtoReflect.Descriptor instead.
func (*EvaluateDatabaseAccessRequest) Descriptor() ([]byte, []int) {
	return file_teleport_decision_v1alpha1_database_access_proto_rawDescGZIP(), []int{0}
}

func (x *EvaluateDatabaseAccessRequest) GetMetadata() *RequestMetadata {
	if x != nil {
		return x.Metadata
	}
	return nil
}

func (x *EvaluateDatabaseAccessRequest) GetTlsIdentity() *TLSIdentity {
	if x != nil {
		return x.TlsIdentity
	}
	return nil
}

// EvaluateDatabaseAccessResponse describes the result of a database access evaluation.
type EvaluateDatabaseAccessResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Result:
	//
	//	*EvaluateDatabaseAccessResponse_Permit
	//	*EvaluateDatabaseAccessResponse_Denial
	Result isEvaluateDatabaseAccessResponse_Result `protobuf_oneof:"result"`
}

func (x *EvaluateDatabaseAccessResponse) Reset() {
	*x = EvaluateDatabaseAccessResponse{}
	mi := &file_teleport_decision_v1alpha1_database_access_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *EvaluateDatabaseAccessResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EvaluateDatabaseAccessResponse) ProtoMessage() {}

func (x *EvaluateDatabaseAccessResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_decision_v1alpha1_database_access_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EvaluateDatabaseAccessResponse.ProtoReflect.Descriptor instead.
func (*EvaluateDatabaseAccessResponse) Descriptor() ([]byte, []int) {
	return file_teleport_decision_v1alpha1_database_access_proto_rawDescGZIP(), []int{1}
}

func (m *EvaluateDatabaseAccessResponse) GetResult() isEvaluateDatabaseAccessResponse_Result {
	if m != nil {
		return m.Result
	}
	return nil
}

func (x *EvaluateDatabaseAccessResponse) GetPermit() *DatabaseAccessPermit {
	if x, ok := x.GetResult().(*EvaluateDatabaseAccessResponse_Permit); ok {
		return x.Permit
	}
	return nil
}

func (x *EvaluateDatabaseAccessResponse) GetDenial() *DatabaseAccessDenial {
	if x, ok := x.GetResult().(*EvaluateDatabaseAccessResponse_Denial); ok {
		return x.Denial
	}
	return nil
}

type isEvaluateDatabaseAccessResponse_Result interface {
	isEvaluateDatabaseAccessResponse_Result()
}

type EvaluateDatabaseAccessResponse_Permit struct {
	Permit *DatabaseAccessPermit `protobuf:"bytes,1,opt,name=permit,proto3,oneof"`
}

type EvaluateDatabaseAccessResponse_Denial struct {
	Denial *DatabaseAccessDenial `protobuf:"bytes,2,opt,name=denial,proto3,oneof"`
}

func (*EvaluateDatabaseAccessResponse_Permit) isEvaluateDatabaseAccessResponse_Result() {}

func (*EvaluateDatabaseAccessResponse_Denial) isEvaluateDatabaseAccessResponse_Result() {}

// DatabaseAccessPermit describes the parameters/constraints of a permissible database access attempt.
type DatabaseAccessPermit struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Metadata *PermitMetadata `protobuf:"bytes,1,opt,name=metadata,proto3" json:"metadata,omitempty"`
}

func (x *DatabaseAccessPermit) Reset() {
	*x = DatabaseAccessPermit{}
	mi := &file_teleport_decision_v1alpha1_database_access_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DatabaseAccessPermit) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DatabaseAccessPermit) ProtoMessage() {}

func (x *DatabaseAccessPermit) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_decision_v1alpha1_database_access_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DatabaseAccessPermit.ProtoReflect.Descriptor instead.
func (*DatabaseAccessPermit) Descriptor() ([]byte, []int) {
	return file_teleport_decision_v1alpha1_database_access_proto_rawDescGZIP(), []int{2}
}

func (x *DatabaseAccessPermit) GetMetadata() *PermitMetadata {
	if x != nil {
		return x.Metadata
	}
	return nil
}

// DatabaseAccessDenial describes the details of a database access denial.
type DatabaseAccessDenial struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Metadata *DenialMetadata `protobuf:"bytes,1,opt,name=metadata,proto3" json:"metadata,omitempty"`
}

func (x *DatabaseAccessDenial) Reset() {
	*x = DatabaseAccessDenial{}
	mi := &file_teleport_decision_v1alpha1_database_access_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DatabaseAccessDenial) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DatabaseAccessDenial) ProtoMessage() {}

func (x *DatabaseAccessDenial) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_decision_v1alpha1_database_access_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DatabaseAccessDenial.ProtoReflect.Descriptor instead.
func (*DatabaseAccessDenial) Descriptor() ([]byte, []int) {
	return file_teleport_decision_v1alpha1_database_access_proto_rawDescGZIP(), []int{3}
}

func (x *DatabaseAccessDenial) GetMetadata() *DenialMetadata {
	if x != nil {
		return x.Metadata
	}
	return nil
}

var File_teleport_decision_v1alpha1_database_access_proto protoreflect.FileDescriptor

var file_teleport_decision_v1alpha1_database_access_proto_rawDesc = []byte{
	0x0a, 0x30, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x64, 0x65, 0x63, 0x69, 0x73,
	0x69, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2f, 0x64, 0x61, 0x74,
	0x61, 0x62, 0x61, 0x73, 0x65, 0x5f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x1a, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x64, 0x65, 0x63,
	0x69, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x1a, 0x29,
	0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x64, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f,
	0x6e, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2f, 0x69, 0x64, 0x65, 0x6e, 0x74,
	0x69, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x29, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2f, 0x64, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x61,
	0x6c, 0x70, 0x68, 0x61, 0x31, 0x2f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0xb4, 0x01, 0x0a, 0x1d, 0x45, 0x76, 0x61, 0x6c, 0x75, 0x61, 0x74,
	0x65, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x47, 0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61,
	0x74, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2b, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2e, 0x64, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x61,
	0x6c, 0x70, 0x68, 0x61, 0x31, 0x2e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x4d, 0x65, 0x74,
	0x61, 0x64, 0x61, 0x74, 0x61, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x12,
	0x4a, 0x0a, 0x0c, 0x74, 0x6c, 0x73, 0x5f, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74,
	0x2e, 0x64, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68,
	0x61, 0x31, 0x2e, 0x54, 0x4c, 0x53, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x52, 0x0b,
	0x74, 0x6c, 0x73, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x22, 0xc2, 0x01, 0x0a, 0x1e,
	0x45, 0x76, 0x61, 0x6c, 0x75, 0x61, 0x74, 0x65, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65,
	0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x4a,
	0x0a, 0x06, 0x70, 0x65, 0x72, 0x6d, 0x69, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x30,
	0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x64, 0x65, 0x63, 0x69, 0x73, 0x69,
	0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2e, 0x44, 0x61, 0x74, 0x61,
	0x62, 0x61, 0x73, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x50, 0x65, 0x72, 0x6d, 0x69, 0x74,
	0x48, 0x00, 0x52, 0x06, 0x70, 0x65, 0x72, 0x6d, 0x69, 0x74, 0x12, 0x4a, 0x0a, 0x06, 0x64, 0x65,
	0x6e, 0x69, 0x61, 0x6c, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x30, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x64, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x76,
	0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2e, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65,
	0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x44, 0x65, 0x6e, 0x69, 0x61, 0x6c, 0x48, 0x00, 0x52, 0x06,
	0x64, 0x65, 0x6e, 0x69, 0x61, 0x6c, 0x42, 0x08, 0x0a, 0x06, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74,
	0x22, 0x5e, 0x0a, 0x14, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x41, 0x63, 0x63, 0x65,
	0x73, 0x73, 0x50, 0x65, 0x72, 0x6d, 0x69, 0x74, 0x12, 0x46, 0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61,
	0x64, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x64, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x76,
	0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2e, 0x50, 0x65, 0x72, 0x6d, 0x69, 0x74, 0x4d, 0x65,
	0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61,
	0x22, 0x5e, 0x0a, 0x14, 0x44, 0x61, 0x74, 0x61, 0x62, 0x61, 0x73, 0x65, 0x41, 0x63, 0x63, 0x65,
	0x73, 0x73, 0x44, 0x65, 0x6e, 0x69, 0x61, 0x6c, 0x12, 0x46, 0x0a, 0x08, 0x6d, 0x65, 0x74, 0x61,
	0x64, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x64, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x76,
	0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2e, 0x44, 0x65, 0x6e, 0x69, 0x61, 0x6c, 0x4d, 0x65,
	0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x52, 0x08, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61,
	0x42, 0x60, 0x5a, 0x5e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67,
	0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f,
	0x64, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61,
	0x31, 0x3b, 0x64, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68,
	0x61, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_decision_v1alpha1_database_access_proto_rawDescOnce sync.Once
	file_teleport_decision_v1alpha1_database_access_proto_rawDescData = file_teleport_decision_v1alpha1_database_access_proto_rawDesc
)

func file_teleport_decision_v1alpha1_database_access_proto_rawDescGZIP() []byte {
	file_teleport_decision_v1alpha1_database_access_proto_rawDescOnce.Do(func() {
		file_teleport_decision_v1alpha1_database_access_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_decision_v1alpha1_database_access_proto_rawDescData)
	})
	return file_teleport_decision_v1alpha1_database_access_proto_rawDescData
}

var file_teleport_decision_v1alpha1_database_access_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_teleport_decision_v1alpha1_database_access_proto_goTypes = []any{
	(*EvaluateDatabaseAccessRequest)(nil),  // 0: teleport.decision.v1alpha1.EvaluateDatabaseAccessRequest
	(*EvaluateDatabaseAccessResponse)(nil), // 1: teleport.decision.v1alpha1.EvaluateDatabaseAccessResponse
	(*DatabaseAccessPermit)(nil),           // 2: teleport.decision.v1alpha1.DatabaseAccessPermit
	(*DatabaseAccessDenial)(nil),           // 3: teleport.decision.v1alpha1.DatabaseAccessDenial
	(*RequestMetadata)(nil),                // 4: teleport.decision.v1alpha1.RequestMetadata
	(*TLSIdentity)(nil),                    // 5: teleport.decision.v1alpha1.TLSIdentity
	(*PermitMetadata)(nil),                 // 6: teleport.decision.v1alpha1.PermitMetadata
	(*DenialMetadata)(nil),                 // 7: teleport.decision.v1alpha1.DenialMetadata
}
var file_teleport_decision_v1alpha1_database_access_proto_depIdxs = []int32{
	4, // 0: teleport.decision.v1alpha1.EvaluateDatabaseAccessRequest.metadata:type_name -> teleport.decision.v1alpha1.RequestMetadata
	5, // 1: teleport.decision.v1alpha1.EvaluateDatabaseAccessRequest.tls_identity:type_name -> teleport.decision.v1alpha1.TLSIdentity
	2, // 2: teleport.decision.v1alpha1.EvaluateDatabaseAccessResponse.permit:type_name -> teleport.decision.v1alpha1.DatabaseAccessPermit
	3, // 3: teleport.decision.v1alpha1.EvaluateDatabaseAccessResponse.denial:type_name -> teleport.decision.v1alpha1.DatabaseAccessDenial
	6, // 4: teleport.decision.v1alpha1.DatabaseAccessPermit.metadata:type_name -> teleport.decision.v1alpha1.PermitMetadata
	7, // 5: teleport.decision.v1alpha1.DatabaseAccessDenial.metadata:type_name -> teleport.decision.v1alpha1.DenialMetadata
	6, // [6:6] is the sub-list for method output_type
	6, // [6:6] is the sub-list for method input_type
	6, // [6:6] is the sub-list for extension type_name
	6, // [6:6] is the sub-list for extension extendee
	0, // [0:6] is the sub-list for field type_name
}

func init() { file_teleport_decision_v1alpha1_database_access_proto_init() }
func file_teleport_decision_v1alpha1_database_access_proto_init() {
	if File_teleport_decision_v1alpha1_database_access_proto != nil {
		return
	}
	file_teleport_decision_v1alpha1_identity_proto_init()
	file_teleport_decision_v1alpha1_metadata_proto_init()
	file_teleport_decision_v1alpha1_database_access_proto_msgTypes[1].OneofWrappers = []any{
		(*EvaluateDatabaseAccessResponse_Permit)(nil),
		(*EvaluateDatabaseAccessResponse_Denial)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_teleport_decision_v1alpha1_database_access_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_teleport_decision_v1alpha1_database_access_proto_goTypes,
		DependencyIndexes: file_teleport_decision_v1alpha1_database_access_proto_depIdxs,
		MessageInfos:      file_teleport_decision_v1alpha1_database_access_proto_msgTypes,
	}.Build()
	File_teleport_decision_v1alpha1_database_access_proto = out.File
	file_teleport_decision_v1alpha1_database_access_proto_rawDesc = nil
	file_teleport_decision_v1alpha1_database_access_proto_goTypes = nil
	file_teleport_decision_v1alpha1_database_access_proto_depIdxs = nil
}
