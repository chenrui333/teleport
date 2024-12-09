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
// 	protoc-gen-go v1.35.2
// 	protoc        (unknown)
// source: teleport/workloadidentity/v1/issuer_service.proto

package workloadidentityv1pb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// TODO: Comment
type X509SVIDParams struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The PKIX, ASN.1 DER public key to encode into the X509 SVID.
	PublicKey []byte `protobuf:"bytes,1,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	// The requested TTL for the X509 SVID. This request may be modified by
	// the server according to its policies. It is the client's responsibility
	// to check the TTL of the returned workload identity credential.
	Ttl *durationpb.Duration `protobuf:"bytes,2,opt,name=ttl,proto3" json:"ttl,omitempty"`
}

func (x *X509SVIDParams) Reset() {
	*x = X509SVIDParams{}
	mi := &file_teleport_workloadidentity_v1_issuer_service_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *X509SVIDParams) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*X509SVIDParams) ProtoMessage() {}

func (x *X509SVIDParams) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_workloadidentity_v1_issuer_service_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use X509SVIDParams.ProtoReflect.Descriptor instead.
func (*X509SVIDParams) Descriptor() ([]byte, []int) {
	return file_teleport_workloadidentity_v1_issuer_service_proto_rawDescGZIP(), []int{0}
}

func (x *X509SVIDParams) GetPublicKey() []byte {
	if x != nil {
		return x.PublicKey
	}
	return nil
}

func (x *X509SVIDParams) GetTtl() *durationpb.Duration {
	if x != nil {
		return x.Ttl
	}
	return nil
}

// TODO: Comment
type JWTSVIDParams struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The audiences to encode into the JWT SVID as the `aud` claim.
	Audiences []string `protobuf:"bytes,1,rep,name=audiences,proto3" json:"audiences,omitempty"`
	// The requested TTL for the JWT SVID. This request may be modified by
	// the server according to its policies. It is the client's responsibility
	// to check the TTL of the returned workload identity credential.
	Ttl *durationpb.Duration `protobuf:"bytes,2,opt,name=ttl,proto3" json:"ttl,omitempty"`
}

func (x *JWTSVIDParams) Reset() {
	*x = JWTSVIDParams{}
	mi := &file_teleport_workloadidentity_v1_issuer_service_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *JWTSVIDParams) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*JWTSVIDParams) ProtoMessage() {}

func (x *JWTSVIDParams) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_workloadidentity_v1_issuer_service_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use JWTSVIDParams.ProtoReflect.Descriptor instead.
func (*JWTSVIDParams) Descriptor() ([]byte, []int) {
	return file_teleport_workloadidentity_v1_issuer_service_proto_rawDescGZIP(), []int{1}
}

func (x *JWTSVIDParams) GetAudiences() []string {
	if x != nil {
		return x.Audiences
	}
	return nil
}

func (x *JWTSVIDParams) GetTtl() *durationpb.Duration {
	if x != nil {
		return x.Ttl
	}
	return nil
}

// TODO: Comment
type SVID struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The TTL that was chosen by the server.
	Ttl *durationpb.Duration `protobuf:"bytes,1,opt,name=ttl,proto3" json:"ttl,omitempty"`
	// The time that the TTL is reached for this credential.
	Expiry *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=expiry,proto3" json:"expiry,omitempty"`
	// The hint configured for this Workload Identity - if any. This is provided
	// to workloads using the SPIFFE Workload API to fetch credentials.
	Hint string `protobuf:"bytes,3,opt,name=hint,proto3" json:"hint,omitempty"`
	// The name of the Workload Identity resource used to issue this credential.
	WorkloadIdentityName string `protobuf:"bytes,4,opt,name=workload_identity_name,json=workloadIdentityName,proto3" json:"workload_identity_name,omitempty"`
	// The revision of the Workload Identity resource used to issue this
	// credential.
	WorkloadIdentityRevision string `protobuf:"bytes,5,opt,name=workload_identity_revision,json=workloadIdentityRevision,proto3" json:"workload_identity_revision,omitempty"`
	// The fully qualified SPIFFE ID that was encoded into the SVID.
	SpiffeId string `protobuf:"bytes,6,opt,name=spiffe_id,json=spiffeId,proto3" json:"spiffe_id,omitempty"`
	// Types that are assignable to Credential:
	//
	//	*SVID_X509
	//	*SVID_Jwt
	Credential isSVID_Credential `protobuf_oneof:"credential"`
}

func (x *SVID) Reset() {
	*x = SVID{}
	mi := &file_teleport_workloadidentity_v1_issuer_service_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SVID) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SVID) ProtoMessage() {}

func (x *SVID) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_workloadidentity_v1_issuer_service_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SVID.ProtoReflect.Descriptor instead.
func (*SVID) Descriptor() ([]byte, []int) {
	return file_teleport_workloadidentity_v1_issuer_service_proto_rawDescGZIP(), []int{2}
}

func (x *SVID) GetTtl() *durationpb.Duration {
	if x != nil {
		return x.Ttl
	}
	return nil
}

func (x *SVID) GetExpiry() *timestamppb.Timestamp {
	if x != nil {
		return x.Expiry
	}
	return nil
}

func (x *SVID) GetHint() string {
	if x != nil {
		return x.Hint
	}
	return ""
}

func (x *SVID) GetWorkloadIdentityName() string {
	if x != nil {
		return x.WorkloadIdentityName
	}
	return ""
}

func (x *SVID) GetWorkloadIdentityRevision() string {
	if x != nil {
		return x.WorkloadIdentityRevision
	}
	return ""
}

func (x *SVID) GetSpiffeId() string {
	if x != nil {
		return x.SpiffeId
	}
	return ""
}

func (m *SVID) GetCredential() isSVID_Credential {
	if m != nil {
		return m.Credential
	}
	return nil
}

func (x *SVID) GetX509() []byte {
	if x, ok := x.GetCredential().(*SVID_X509); ok {
		return x.X509
	}
	return nil
}

func (x *SVID) GetJwt() string {
	if x, ok := x.GetCredential().(*SVID_Jwt); ok {
		return x.Jwt
	}
	return ""
}

type isSVID_Credential interface {
	isSVID_Credential()
}

type SVID_X509 struct {
	// The X509 SVID that was issued.
	// ASN.1 DER encoded X.509 certificate. No PEM.
	X509 []byte `protobuf:"bytes,7,opt,name=x509,proto3,oneof"`
}

type SVID_Jwt struct {
	// The JWT SVID that was issued.
	Jwt string `protobuf:"bytes,8,opt,name=jwt,proto3,oneof"`
}

func (*SVID_X509) isSVID_Credential() {}

func (*SVID_Jwt) isSVID_Credential() {}

// TODO: Comment
type IssueWorkloadIdentityRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The name of the workload identity to issue.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Types that are assignable to Credential:
	//
	//	*IssueWorkloadIdentityRequest_X509SvidParams
	//	*IssueWorkloadIdentityRequest_JwtSvidParams
	Credential    isIssueWorkloadIdentityRequest_Credential `protobuf_oneof:"credential"`
	WorkloadAttrs *WorkloadAttrs                            `protobuf:"bytes,4,opt,name=workload_attrs,json=workloadAttrs,proto3" json:"workload_attrs,omitempty"`
}

func (x *IssueWorkloadIdentityRequest) Reset() {
	*x = IssueWorkloadIdentityRequest{}
	mi := &file_teleport_workloadidentity_v1_issuer_service_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *IssueWorkloadIdentityRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IssueWorkloadIdentityRequest) ProtoMessage() {}

func (x *IssueWorkloadIdentityRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_workloadidentity_v1_issuer_service_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IssueWorkloadIdentityRequest.ProtoReflect.Descriptor instead.
func (*IssueWorkloadIdentityRequest) Descriptor() ([]byte, []int) {
	return file_teleport_workloadidentity_v1_issuer_service_proto_rawDescGZIP(), []int{3}
}

func (x *IssueWorkloadIdentityRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (m *IssueWorkloadIdentityRequest) GetCredential() isIssueWorkloadIdentityRequest_Credential {
	if m != nil {
		return m.Credential
	}
	return nil
}

func (x *IssueWorkloadIdentityRequest) GetX509SvidParams() *X509SVIDParams {
	if x, ok := x.GetCredential().(*IssueWorkloadIdentityRequest_X509SvidParams); ok {
		return x.X509SvidParams
	}
	return nil
}

func (x *IssueWorkloadIdentityRequest) GetJwtSvidParams() *JWTSVIDParams {
	if x, ok := x.GetCredential().(*IssueWorkloadIdentityRequest_JwtSvidParams); ok {
		return x.JwtSvidParams
	}
	return nil
}

func (x *IssueWorkloadIdentityRequest) GetWorkloadAttrs() *WorkloadAttrs {
	if x != nil {
		return x.WorkloadAttrs
	}
	return nil
}

type isIssueWorkloadIdentityRequest_Credential interface {
	isIssueWorkloadIdentityRequest_Credential()
}

type IssueWorkloadIdentityRequest_X509SvidParams struct {
	X509SvidParams *X509SVIDParams `protobuf:"bytes,2,opt,name=x509_svid_params,json=x509SvidParams,proto3,oneof"`
}

type IssueWorkloadIdentityRequest_JwtSvidParams struct {
	JwtSvidParams *JWTSVIDParams `protobuf:"bytes,3,opt,name=jwt_svid_params,json=jwtSvidParams,proto3,oneof"`
}

func (*IssueWorkloadIdentityRequest_X509SvidParams) isIssueWorkloadIdentityRequest_Credential() {}

func (*IssueWorkloadIdentityRequest_JwtSvidParams) isIssueWorkloadIdentityRequest_Credential() {}

// TODO: Comment
type IssueWorkloadIdentityResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Svid *SVID `protobuf:"bytes,1,opt,name=svid,proto3" json:"svid,omitempty"`
}

func (x *IssueWorkloadIdentityResponse) Reset() {
	*x = IssueWorkloadIdentityResponse{}
	mi := &file_teleport_workloadidentity_v1_issuer_service_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *IssueWorkloadIdentityResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IssueWorkloadIdentityResponse) ProtoMessage() {}

func (x *IssueWorkloadIdentityResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_workloadidentity_v1_issuer_service_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IssueWorkloadIdentityResponse.ProtoReflect.Descriptor instead.
func (*IssueWorkloadIdentityResponse) Descriptor() ([]byte, []int) {
	return file_teleport_workloadidentity_v1_issuer_service_proto_rawDescGZIP(), []int{4}
}

func (x *IssueWorkloadIdentityResponse) GetSvid() *SVID {
	if x != nil {
		return x.Svid
	}
	return nil
}

// The attributes provided by `tbot` regarding the workload's attestation.
type WorkloadAttrs struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *WorkloadAttrs) Reset() {
	*x = WorkloadAttrs{}
	mi := &file_teleport_workloadidentity_v1_issuer_service_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *WorkloadAttrs) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WorkloadAttrs) ProtoMessage() {}

func (x *WorkloadAttrs) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_workloadidentity_v1_issuer_service_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WorkloadAttrs.ProtoReflect.Descriptor instead.
func (*WorkloadAttrs) Descriptor() ([]byte, []int) {
	return file_teleport_workloadidentity_v1_issuer_service_proto_rawDescGZIP(), []int{5}
}

// TODO: Comment
type JoinAttrs struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *JoinAttrs) Reset() {
	*x = JoinAttrs{}
	mi := &file_teleport_workloadidentity_v1_issuer_service_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *JoinAttrs) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*JoinAttrs) ProtoMessage() {}

func (x *JoinAttrs) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_workloadidentity_v1_issuer_service_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use JoinAttrs.ProtoReflect.Descriptor instead.
func (*JoinAttrs) Descriptor() ([]byte, []int) {
	return file_teleport_workloadidentity_v1_issuer_service_proto_rawDescGZIP(), []int{6}
}

// TODO: Comment
type UserAttrs struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The username of the user.
	Username string `protobuf:"bytes,1,opt,name=username,proto3" json:"username,omitempty"`
}

func (x *UserAttrs) Reset() {
	*x = UserAttrs{}
	mi := &file_teleport_workloadidentity_v1_issuer_service_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *UserAttrs) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UserAttrs) ProtoMessage() {}

func (x *UserAttrs) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_workloadidentity_v1_issuer_service_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UserAttrs.ProtoReflect.Descriptor instead.
func (*UserAttrs) Descriptor() ([]byte, []int) {
	return file_teleport_workloadidentity_v1_issuer_service_proto_rawDescGZIP(), []int{7}
}

func (x *UserAttrs) GetUsername() string {
	if x != nil {
		return x.Username
	}
	return ""
}

// TODO: Comment
type Attrs struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Join     *JoinAttrs     `protobuf:"bytes,1,opt,name=join,proto3" json:"join,omitempty"`
	Workload *WorkloadAttrs `protobuf:"bytes,2,opt,name=workload,proto3" json:"workload,omitempty"`
	User     *UserAttrs     `protobuf:"bytes,3,opt,name=user,proto3" json:"user,omitempty"`
}

func (x *Attrs) Reset() {
	*x = Attrs{}
	mi := &file_teleport_workloadidentity_v1_issuer_service_proto_msgTypes[8]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Attrs) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Attrs) ProtoMessage() {}

func (x *Attrs) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_workloadidentity_v1_issuer_service_proto_msgTypes[8]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Attrs.ProtoReflect.Descriptor instead.
func (*Attrs) Descriptor() ([]byte, []int) {
	return file_teleport_workloadidentity_v1_issuer_service_proto_rawDescGZIP(), []int{8}
}

func (x *Attrs) GetJoin() *JoinAttrs {
	if x != nil {
		return x.Join
	}
	return nil
}

func (x *Attrs) GetWorkload() *WorkloadAttrs {
	if x != nil {
		return x.Workload
	}
	return nil
}

func (x *Attrs) GetUser() *UserAttrs {
	if x != nil {
		return x.User
	}
	return nil
}

var File_teleport_workloadidentity_v1_issuer_service_proto protoreflect.FileDescriptor

var file_teleport_workloadidentity_v1_issuer_service_proto_rawDesc = []byte{
	0x0a, 0x31, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x77, 0x6f, 0x72, 0x6b, 0x6c,
	0x6f, 0x61, 0x64, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2f, 0x76, 0x31, 0x2f, 0x69,
	0x73, 0x73, 0x75, 0x65, 0x72, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x1c, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x77, 0x6f,
	0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2e, 0x76,
	0x31, 0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2f, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0x5c, 0x0a, 0x0e, 0x58, 0x35, 0x30, 0x39, 0x53, 0x56, 0x49, 0x44, 0x50, 0x61,
	0x72, 0x61, 0x6d, 0x73, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b,
	0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
	0x4b, 0x65, 0x79, 0x12, 0x2b, 0x0a, 0x03, 0x74, 0x74, 0x6c, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x19, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x03, 0x74, 0x74, 0x6c,
	0x22, 0x5a, 0x0a, 0x0d, 0x4a, 0x57, 0x54, 0x53, 0x56, 0x49, 0x44, 0x50, 0x61, 0x72, 0x61, 0x6d,
	0x73, 0x12, 0x1c, 0x0a, 0x09, 0x61, 0x75, 0x64, 0x69, 0x65, 0x6e, 0x63, 0x65, 0x73, 0x18, 0x01,
	0x20, 0x03, 0x28, 0x09, 0x52, 0x09, 0x61, 0x75, 0x64, 0x69, 0x65, 0x6e, 0x63, 0x65, 0x73, 0x12,
	0x2b, 0x0a, 0x03, 0x74, 0x74, 0x6c, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x44,
	0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x03, 0x74, 0x74, 0x6c, 0x22, 0xc4, 0x02, 0x0a,
	0x04, 0x53, 0x56, 0x49, 0x44, 0x12, 0x2b, 0x0a, 0x03, 0x74, 0x74, 0x6c, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x19, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x03, 0x74,
	0x74, 0x6c, 0x12, 0x32, 0x0a, 0x06, 0x65, 0x78, 0x70, 0x69, 0x72, 0x79, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x06,
	0x65, 0x78, 0x70, 0x69, 0x72, 0x79, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x69, 0x6e, 0x74, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x68, 0x69, 0x6e, 0x74, 0x12, 0x34, 0x0a, 0x16, 0x77, 0x6f,
	0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x5f, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x5f,
	0x6e, 0x61, 0x6d, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x14, 0x77, 0x6f, 0x72, 0x6b,
	0x6c, 0x6f, 0x61, 0x64, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x4e, 0x61, 0x6d, 0x65,
	0x12, 0x3c, 0x0a, 0x1a, 0x77, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x5f, 0x69, 0x64, 0x65,
	0x6e, 0x74, 0x69, 0x74, 0x79, 0x5f, 0x72, 0x65, 0x76, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x18, 0x77, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x49, 0x64,
	0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x52, 0x65, 0x76, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x1b,
	0x0a, 0x09, 0x73, 0x70, 0x69, 0x66, 0x66, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x06, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x08, 0x73, 0x70, 0x69, 0x66, 0x66, 0x65, 0x49, 0x64, 0x12, 0x14, 0x0a, 0x04, 0x78,
	0x35, 0x30, 0x39, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0c, 0x48, 0x00, 0x52, 0x04, 0x78, 0x35, 0x30,
	0x39, 0x12, 0x12, 0x0a, 0x03, 0x6a, 0x77, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00,
	0x52, 0x03, 0x6a, 0x77, 0x74, 0x42, 0x0c, 0x0a, 0x0a, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74,
	0x69, 0x61, 0x6c, 0x22, 0xc5, 0x02, 0x0a, 0x1c, 0x49, 0x73, 0x73, 0x75, 0x65, 0x57, 0x6f, 0x72,
	0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x58, 0x0a, 0x10, 0x78, 0x35, 0x30, 0x39,
	0x5f, 0x73, 0x76, 0x69, 0x64, 0x5f, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x2c, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x77, 0x6f,
	0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2e, 0x76,
	0x31, 0x2e, 0x58, 0x35, 0x30, 0x39, 0x53, 0x56, 0x49, 0x44, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x73,
	0x48, 0x00, 0x52, 0x0e, 0x78, 0x35, 0x30, 0x39, 0x53, 0x76, 0x69, 0x64, 0x50, 0x61, 0x72, 0x61,
	0x6d, 0x73, 0x12, 0x55, 0x0a, 0x0f, 0x6a, 0x77, 0x74, 0x5f, 0x73, 0x76, 0x69, 0x64, 0x5f, 0x70,
	0x61, 0x72, 0x61, 0x6d, 0x73, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2b, 0x2e, 0x74, 0x65,
	0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x77, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x69,
	0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x4a, 0x57, 0x54, 0x53, 0x56,
	0x49, 0x44, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x48, 0x00, 0x52, 0x0d, 0x6a, 0x77, 0x74, 0x53,
	0x76, 0x69, 0x64, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x12, 0x52, 0x0a, 0x0e, 0x77, 0x6f, 0x72,
	0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x5f, 0x61, 0x74, 0x74, 0x72, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x2b, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x77, 0x6f, 0x72,
	0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2e, 0x76, 0x31,
	0x2e, 0x57, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x41, 0x74, 0x74, 0x72, 0x73, 0x52, 0x0d,
	0x77, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x41, 0x74, 0x74, 0x72, 0x73, 0x42, 0x0c, 0x0a,
	0x0a, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x22, 0x57, 0x0a, 0x1d, 0x49,
	0x73, 0x73, 0x75, 0x65, 0x57, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x49, 0x64, 0x65, 0x6e,
	0x74, 0x69, 0x74, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x36, 0x0a, 0x04,
	0x73, 0x76, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x77, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x69, 0x64,
	0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x56, 0x49, 0x44, 0x52, 0x04,
	0x73, 0x76, 0x69, 0x64, 0x22, 0x0f, 0x0a, 0x0d, 0x57, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64,
	0x41, 0x74, 0x74, 0x72, 0x73, 0x22, 0x0b, 0x0a, 0x09, 0x4a, 0x6f, 0x69, 0x6e, 0x41, 0x74, 0x74,
	0x72, 0x73, 0x22, 0x27, 0x0a, 0x09, 0x55, 0x73, 0x65, 0x72, 0x41, 0x74, 0x74, 0x72, 0x73, 0x12,
	0x1a, 0x0a, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0xca, 0x01, 0x0a, 0x05,
	0x41, 0x74, 0x74, 0x72, 0x73, 0x12, 0x3b, 0x0a, 0x04, 0x6a, 0x6f, 0x69, 0x6e, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x77,
	0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2e,
	0x76, 0x31, 0x2e, 0x4a, 0x6f, 0x69, 0x6e, 0x41, 0x74, 0x74, 0x72, 0x73, 0x52, 0x04, 0x6a, 0x6f,
	0x69, 0x6e, 0x12, 0x47, 0x0a, 0x08, 0x77, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x2b, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e,
	0x77, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79,
	0x2e, 0x76, 0x31, 0x2e, 0x57, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x41, 0x74, 0x74, 0x72,
	0x73, 0x52, 0x08, 0x77, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x3b, 0x0a, 0x04, 0x75,
	0x73, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x74, 0x65, 0x6c, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x2e, 0x77, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x69, 0x64, 0x65,
	0x6e, 0x74, 0x69, 0x74, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x41, 0x74, 0x74,
	0x72, 0x73, 0x52, 0x04, 0x75, 0x73, 0x65, 0x72, 0x32, 0xb4, 0x01, 0x0a, 0x1f, 0x57, 0x6f, 0x72,
	0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x49, 0x73, 0x73,
	0x75, 0x61, 0x6e, 0x63, 0x65, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x90, 0x01, 0x0a,
	0x15, 0x49, 0x73, 0x73, 0x75, 0x65, 0x57, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x49, 0x64,
	0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x12, 0x3a, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x77, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69,
	0x74, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x49, 0x73, 0x73, 0x75, 0x65, 0x57, 0x6f, 0x72, 0x6b, 0x6c,
	0x6f, 0x61, 0x64, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x1a, 0x3b, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x77, 0x6f,
	0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2e, 0x76,
	0x31, 0x2e, 0x49, 0x73, 0x73, 0x75, 0x65, 0x57, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x49,
	0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42,
	0x66, 0x5a, 0x64, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72,
	0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x77,
	0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2f,
	0x76, 0x31, 0x3b, 0x77, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x69, 0x64, 0x65, 0x6e, 0x74,
	0x69, 0x74, 0x79, 0x76, 0x31, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_workloadidentity_v1_issuer_service_proto_rawDescOnce sync.Once
	file_teleport_workloadidentity_v1_issuer_service_proto_rawDescData = file_teleport_workloadidentity_v1_issuer_service_proto_rawDesc
)

func file_teleport_workloadidentity_v1_issuer_service_proto_rawDescGZIP() []byte {
	file_teleport_workloadidentity_v1_issuer_service_proto_rawDescOnce.Do(func() {
		file_teleport_workloadidentity_v1_issuer_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_workloadidentity_v1_issuer_service_proto_rawDescData)
	})
	return file_teleport_workloadidentity_v1_issuer_service_proto_rawDescData
}

var file_teleport_workloadidentity_v1_issuer_service_proto_msgTypes = make([]protoimpl.MessageInfo, 9)
var file_teleport_workloadidentity_v1_issuer_service_proto_goTypes = []any{
	(*X509SVIDParams)(nil),                // 0: teleport.workloadidentity.v1.X509SVIDParams
	(*JWTSVIDParams)(nil),                 // 1: teleport.workloadidentity.v1.JWTSVIDParams
	(*SVID)(nil),                          // 2: teleport.workloadidentity.v1.SVID
	(*IssueWorkloadIdentityRequest)(nil),  // 3: teleport.workloadidentity.v1.IssueWorkloadIdentityRequest
	(*IssueWorkloadIdentityResponse)(nil), // 4: teleport.workloadidentity.v1.IssueWorkloadIdentityResponse
	(*WorkloadAttrs)(nil),                 // 5: teleport.workloadidentity.v1.WorkloadAttrs
	(*JoinAttrs)(nil),                     // 6: teleport.workloadidentity.v1.JoinAttrs
	(*UserAttrs)(nil),                     // 7: teleport.workloadidentity.v1.UserAttrs
	(*Attrs)(nil),                         // 8: teleport.workloadidentity.v1.Attrs
	(*durationpb.Duration)(nil),           // 9: google.protobuf.Duration
	(*timestamppb.Timestamp)(nil),         // 10: google.protobuf.Timestamp
}
var file_teleport_workloadidentity_v1_issuer_service_proto_depIdxs = []int32{
	9,  // 0: teleport.workloadidentity.v1.X509SVIDParams.ttl:type_name -> google.protobuf.Duration
	9,  // 1: teleport.workloadidentity.v1.JWTSVIDParams.ttl:type_name -> google.protobuf.Duration
	9,  // 2: teleport.workloadidentity.v1.SVID.ttl:type_name -> google.protobuf.Duration
	10, // 3: teleport.workloadidentity.v1.SVID.expiry:type_name -> google.protobuf.Timestamp
	0,  // 4: teleport.workloadidentity.v1.IssueWorkloadIdentityRequest.x509_svid_params:type_name -> teleport.workloadidentity.v1.X509SVIDParams
	1,  // 5: teleport.workloadidentity.v1.IssueWorkloadIdentityRequest.jwt_svid_params:type_name -> teleport.workloadidentity.v1.JWTSVIDParams
	5,  // 6: teleport.workloadidentity.v1.IssueWorkloadIdentityRequest.workload_attrs:type_name -> teleport.workloadidentity.v1.WorkloadAttrs
	2,  // 7: teleport.workloadidentity.v1.IssueWorkloadIdentityResponse.svid:type_name -> teleport.workloadidentity.v1.SVID
	6,  // 8: teleport.workloadidentity.v1.Attrs.join:type_name -> teleport.workloadidentity.v1.JoinAttrs
	5,  // 9: teleport.workloadidentity.v1.Attrs.workload:type_name -> teleport.workloadidentity.v1.WorkloadAttrs
	7,  // 10: teleport.workloadidentity.v1.Attrs.user:type_name -> teleport.workloadidentity.v1.UserAttrs
	3,  // 11: teleport.workloadidentity.v1.WorkloadIdentityIssuanceService.IssueWorkloadIdentity:input_type -> teleport.workloadidentity.v1.IssueWorkloadIdentityRequest
	4,  // 12: teleport.workloadidentity.v1.WorkloadIdentityIssuanceService.IssueWorkloadIdentity:output_type -> teleport.workloadidentity.v1.IssueWorkloadIdentityResponse
	12, // [12:13] is the sub-list for method output_type
	11, // [11:12] is the sub-list for method input_type
	11, // [11:11] is the sub-list for extension type_name
	11, // [11:11] is the sub-list for extension extendee
	0,  // [0:11] is the sub-list for field type_name
}

func init() { file_teleport_workloadidentity_v1_issuer_service_proto_init() }
func file_teleport_workloadidentity_v1_issuer_service_proto_init() {
	if File_teleport_workloadidentity_v1_issuer_service_proto != nil {
		return
	}
	file_teleport_workloadidentity_v1_issuer_service_proto_msgTypes[2].OneofWrappers = []any{
		(*SVID_X509)(nil),
		(*SVID_Jwt)(nil),
	}
	file_teleport_workloadidentity_v1_issuer_service_proto_msgTypes[3].OneofWrappers = []any{
		(*IssueWorkloadIdentityRequest_X509SvidParams)(nil),
		(*IssueWorkloadIdentityRequest_JwtSvidParams)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_teleport_workloadidentity_v1_issuer_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   9,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_teleport_workloadidentity_v1_issuer_service_proto_goTypes,
		DependencyIndexes: file_teleport_workloadidentity_v1_issuer_service_proto_depIdxs,
		MessageInfos:      file_teleport_workloadidentity_v1_issuer_service_proto_msgTypes,
	}.Build()
	File_teleport_workloadidentity_v1_issuer_service_proto = out.File
	file_teleport_workloadidentity_v1_issuer_service_proto_rawDesc = nil
	file_teleport_workloadidentity_v1_issuer_service_proto_goTypes = nil
	file_teleport_workloadidentity_v1_issuer_service_proto_depIdxs = nil
}
