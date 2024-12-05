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
// source: teleport/decision/v1alpha1/metadata.proto

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

// DecisionFeature is an enum representing PDP features.
type DecisionFeature int32

const (
	// DECISION_FEATURE_UNSPECIFIED is the default/unspecified value for DecisionFeature. Asserting this feature has no effect.
	DecisionFeature_DECISION_FEATURE_UNSPECIFIED DecisionFeature = 0
)

// Enum value maps for DecisionFeature.
var (
	DecisionFeature_name = map[int32]string{
		0: "DECISION_FEATURE_UNSPECIFIED",
	}
	DecisionFeature_value = map[string]int32{
		"DECISION_FEATURE_UNSPECIFIED": 0,
	}
)

func (x DecisionFeature) Enum() *DecisionFeature {
	p := new(DecisionFeature)
	*p = x
	return p
}

func (x DecisionFeature) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (DecisionFeature) Descriptor() protoreflect.EnumDescriptor {
	return file_teleport_decision_v1alpha1_metadata_proto_enumTypes[0].Descriptor()
}

func (DecisionFeature) Type() protoreflect.EnumType {
	return &file_teleport_decision_v1alpha1_metadata_proto_enumTypes[0]
}

func (x DecisionFeature) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use DecisionFeature.Descriptor instead.
func (DecisionFeature) EnumDescriptor() ([]byte, []int) {
	return file_teleport_decision_v1alpha1_metadata_proto_rawDescGZIP(), []int{0}
}

// EnforcementFeature is the enum representing PEP features.
type EnforcementFeature int32

const (
	// ENFORCEMENT_FEATURE_UNSPECIFIED is the default/unspecified value for EnforcementFeature. Asserting this feature has no effect.
	EnforcementFeature_ENFORCEMENT_FEATURE_UNSPECIFIED EnforcementFeature = 0
)

// Enum value maps for EnforcementFeature.
var (
	EnforcementFeature_name = map[int32]string{
		0: "ENFORCEMENT_FEATURE_UNSPECIFIED",
	}
	EnforcementFeature_value = map[string]int32{
		"ENFORCEMENT_FEATURE_UNSPECIFIED": 0,
	}
)

func (x EnforcementFeature) Enum() *EnforcementFeature {
	p := new(EnforcementFeature)
	*p = x
	return p
}

func (x EnforcementFeature) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (EnforcementFeature) Descriptor() protoreflect.EnumDescriptor {
	return file_teleport_decision_v1alpha1_metadata_proto_enumTypes[1].Descriptor()
}

func (EnforcementFeature) Type() protoreflect.EnumType {
	return &file_teleport_decision_v1alpha1_metadata_proto_enumTypes[1]
}

func (x EnforcementFeature) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use EnforcementFeature.Descriptor instead.
func (EnforcementFeature) EnumDescriptor() ([]byte, []int) {
	return file_teleport_decision_v1alpha1_metadata_proto_rawDescGZIP(), []int{1}
}

// Metadata common for authorization decision request operations.
type RequestMetadata struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// FeatureAssertions is a list of DecisionFeature that the PDP *must* implement in order to correctly
	// evaluate the decision request. Note that changes that require new features in the PDP in order for
	// it to understand a decision request are rare and should be avoided if possible.
	FeatureAssertions []DecisionFeature `protobuf:"varint,1,rep,packed,name=feature_assertions,json=featureAssertions,proto3,enum=teleport.decision.v1alpha1.DecisionFeature" json:"feature_assertions,omitempty"`
	// PepVersionHint is the *likely* version of the PEP that will enforce the decision. Not all decision
	// requests can guarantee that the expected PEP version will actually be the version that ends up enforcing
	// the decision. Hard compatibility requirements must be enforced via feature assertions so that PEPs can
	// correctly reject decisions that they cannot enforce.
	PepVersionHint string `protobuf:"bytes,2,opt,name=pep_version_hint,json=pepVersionHint,proto3" json:"pep_version_hint,omitempty"`
}

func (x *RequestMetadata) Reset() {
	*x = RequestMetadata{}
	mi := &file_teleport_decision_v1alpha1_metadata_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RequestMetadata) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RequestMetadata) ProtoMessage() {}

func (x *RequestMetadata) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_decision_v1alpha1_metadata_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RequestMetadata.ProtoReflect.Descriptor instead.
func (*RequestMetadata) Descriptor() ([]byte, []int) {
	return file_teleport_decision_v1alpha1_metadata_proto_rawDescGZIP(), []int{0}
}

func (x *RequestMetadata) GetFeatureAssertions() []DecisionFeature {
	if x != nil {
		return x.FeatureAssertions
	}
	return nil
}

func (x *RequestMetadata) GetPepVersionHint() string {
	if x != nil {
		return x.PepVersionHint
	}
	return ""
}

// Metadata common for access permits.
type PermitMetadata struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// FeatureAssertions is a list of EnforcementFeature that the PEP *must* implement in order to correctly
	// enforce the decision. Note that where possible new features should be structured to "fail safe" rather
	// than relying on feature assertions.
	FeatureAssertions []EnforcementFeature `protobuf:"varint,1,rep,packed,name=feature_assertions,json=featureAssertions,proto3,enum=teleport.decision.v1alpha1.EnforcementFeature" json:"feature_assertions,omitempty"`
	// PdpVersion is the version of the PDP that evaluated the decision request.
	PdpVersion string `protobuf:"bytes,2,opt,name=pdp_version,json=pdpVersion,proto3" json:"pdp_version,omitempty"`
}

func (x *PermitMetadata) Reset() {
	*x = PermitMetadata{}
	mi := &file_teleport_decision_v1alpha1_metadata_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *PermitMetadata) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PermitMetadata) ProtoMessage() {}

func (x *PermitMetadata) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_decision_v1alpha1_metadata_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PermitMetadata.ProtoReflect.Descriptor instead.
func (*PermitMetadata) Descriptor() ([]byte, []int) {
	return file_teleport_decision_v1alpha1_metadata_proto_rawDescGZIP(), []int{1}
}

func (x *PermitMetadata) GetFeatureAssertions() []EnforcementFeature {
	if x != nil {
		return x.FeatureAssertions
	}
	return nil
}

func (x *PermitMetadata) GetPdpVersion() string {
	if x != nil {
		return x.PdpVersion
	}
	return ""
}

// Metadata common for access denials.
type DenialMetadata struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// FeatureAssertions is a list of EnforcementFeature that the PEP *must* implement in order to correctly
	// enforce the decision. Note that denials rarely need feature assertions since they typically "fail safe"
	// anyway.
	FeatureAssertions []EnforcementFeature `protobuf:"varint,1,rep,packed,name=feature_assertions,json=featureAssertions,proto3,enum=teleport.decision.v1alpha1.EnforcementFeature" json:"feature_assertions,omitempty"`
	// PdpVersion is the version of the PDP that evaluated the decision request.
	PdpVersion string `protobuf:"bytes,2,opt,name=pdp_version,json=pdpVersion,proto3" json:"pdp_version,omitempty"`
	// UserMessage is a sanitized message safe for return to the subject identity of the decision request.
	UserMessage string `protobuf:"bytes,3,opt,name=user_message,json=userMessage,proto3" json:"user_message,omitempty"`
}

func (x *DenialMetadata) Reset() {
	*x = DenialMetadata{}
	mi := &file_teleport_decision_v1alpha1_metadata_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DenialMetadata) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DenialMetadata) ProtoMessage() {}

func (x *DenialMetadata) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_decision_v1alpha1_metadata_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DenialMetadata.ProtoReflect.Descriptor instead.
func (*DenialMetadata) Descriptor() ([]byte, []int) {
	return file_teleport_decision_v1alpha1_metadata_proto_rawDescGZIP(), []int{2}
}

func (x *DenialMetadata) GetFeatureAssertions() []EnforcementFeature {
	if x != nil {
		return x.FeatureAssertions
	}
	return nil
}

func (x *DenialMetadata) GetPdpVersion() string {
	if x != nil {
		return x.PdpVersion
	}
	return ""
}

func (x *DenialMetadata) GetUserMessage() string {
	if x != nil {
		return x.UserMessage
	}
	return ""
}

var File_teleport_decision_v1alpha1_metadata_proto protoreflect.FileDescriptor

var file_teleport_decision_v1alpha1_metadata_proto_rawDesc = []byte{
	0x0a, 0x29, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x64, 0x65, 0x63, 0x69, 0x73,
	0x69, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2f, 0x6d, 0x65, 0x74,
	0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1a, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x64, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x76,
	0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x22, 0x97, 0x01, 0x0a, 0x0f, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x12, 0x5a, 0x0a, 0x12, 0x66,
	0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x5f, 0x61, 0x73, 0x73, 0x65, 0x72, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0e, 0x32, 0x2b, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f,
	0x72, 0x74, 0x2e, 0x64, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x61, 0x6c,
	0x70, 0x68, 0x61, 0x31, 0x2e, 0x44, 0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x46, 0x65, 0x61,
	0x74, 0x75, 0x72, 0x65, 0x52, 0x11, 0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x41, 0x73, 0x73,
	0x65, 0x72, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x28, 0x0a, 0x10, 0x70, 0x65, 0x70, 0x5f, 0x76,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x68, 0x69, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0e, 0x70, 0x65, 0x70, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x48, 0x69, 0x6e,
	0x74, 0x22, 0x90, 0x01, 0x0a, 0x0e, 0x50, 0x65, 0x72, 0x6d, 0x69, 0x74, 0x4d, 0x65, 0x74, 0x61,
	0x64, 0x61, 0x74, 0x61, 0x12, 0x5d, 0x0a, 0x12, 0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x5f,
	0x61, 0x73, 0x73, 0x65, 0x72, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0e,
	0x32, 0x2e, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x64, 0x65, 0x63, 0x69,
	0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2e, 0x45, 0x6e,
	0x66, 0x6f, 0x72, 0x63, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x46, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65,
	0x52, 0x11, 0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x41, 0x73, 0x73, 0x65, 0x72, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x12, 0x1f, 0x0a, 0x0b, 0x70, 0x64, 0x70, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x70, 0x64, 0x70, 0x56, 0x65, 0x72,
	0x73, 0x69, 0x6f, 0x6e, 0x22, 0xb3, 0x01, 0x0a, 0x0e, 0x44, 0x65, 0x6e, 0x69, 0x61, 0x6c, 0x4d,
	0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x12, 0x5d, 0x0a, 0x12, 0x66, 0x65, 0x61, 0x74, 0x75,
	0x72, 0x65, 0x5f, 0x61, 0x73, 0x73, 0x65, 0x72, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x0e, 0x32, 0x2e, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x64,
	0x65, 0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31,
	0x2e, 0x45, 0x6e, 0x66, 0x6f, 0x72, 0x63, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x46, 0x65, 0x61, 0x74,
	0x75, 0x72, 0x65, 0x52, 0x11, 0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x41, 0x73, 0x73, 0x65,
	0x72, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x1f, 0x0a, 0x0b, 0x70, 0x64, 0x70, 0x5f, 0x76, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x70, 0x64, 0x70,
	0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x21, 0x0a, 0x0c, 0x75, 0x73, 0x65, 0x72, 0x5f,
	0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x75,
	0x73, 0x65, 0x72, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2a, 0x33, 0x0a, 0x0f, 0x44, 0x65,
	0x63, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x46, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12, 0x20, 0x0a,
	0x1c, 0x44, 0x45, 0x43, 0x49, 0x53, 0x49, 0x4f, 0x4e, 0x5f, 0x46, 0x45, 0x41, 0x54, 0x55, 0x52,
	0x45, 0x5f, 0x55, 0x4e, 0x53, 0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x2a,
	0x39, 0x0a, 0x12, 0x45, 0x6e, 0x66, 0x6f, 0x72, 0x63, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x46, 0x65,
	0x61, 0x74, 0x75, 0x72, 0x65, 0x12, 0x23, 0x0a, 0x1f, 0x45, 0x4e, 0x46, 0x4f, 0x52, 0x43, 0x45,
	0x4d, 0x45, 0x4e, 0x54, 0x5f, 0x46, 0x45, 0x41, 0x54, 0x55, 0x52, 0x45, 0x5f, 0x55, 0x4e, 0x53,
	0x50, 0x45, 0x43, 0x49, 0x46, 0x49, 0x45, 0x44, 0x10, 0x00, 0x42, 0x60, 0x5a, 0x5e, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76, 0x69, 0x74, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f,
	0x61, 0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f,
	0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x64, 0x65, 0x63, 0x69, 0x73, 0x69,
	0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x3b, 0x64, 0x65, 0x63, 0x69,
	0x73, 0x69, 0x6f, 0x6e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_decision_v1alpha1_metadata_proto_rawDescOnce sync.Once
	file_teleport_decision_v1alpha1_metadata_proto_rawDescData = file_teleport_decision_v1alpha1_metadata_proto_rawDesc
)

func file_teleport_decision_v1alpha1_metadata_proto_rawDescGZIP() []byte {
	file_teleport_decision_v1alpha1_metadata_proto_rawDescOnce.Do(func() {
		file_teleport_decision_v1alpha1_metadata_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_decision_v1alpha1_metadata_proto_rawDescData)
	})
	return file_teleport_decision_v1alpha1_metadata_proto_rawDescData
}

var file_teleport_decision_v1alpha1_metadata_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_teleport_decision_v1alpha1_metadata_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_teleport_decision_v1alpha1_metadata_proto_goTypes = []any{
	(DecisionFeature)(0),    // 0: teleport.decision.v1alpha1.DecisionFeature
	(EnforcementFeature)(0), // 1: teleport.decision.v1alpha1.EnforcementFeature
	(*RequestMetadata)(nil), // 2: teleport.decision.v1alpha1.RequestMetadata
	(*PermitMetadata)(nil),  // 3: teleport.decision.v1alpha1.PermitMetadata
	(*DenialMetadata)(nil),  // 4: teleport.decision.v1alpha1.DenialMetadata
}
var file_teleport_decision_v1alpha1_metadata_proto_depIdxs = []int32{
	0, // 0: teleport.decision.v1alpha1.RequestMetadata.feature_assertions:type_name -> teleport.decision.v1alpha1.DecisionFeature
	1, // 1: teleport.decision.v1alpha1.PermitMetadata.feature_assertions:type_name -> teleport.decision.v1alpha1.EnforcementFeature
	1, // 2: teleport.decision.v1alpha1.DenialMetadata.feature_assertions:type_name -> teleport.decision.v1alpha1.EnforcementFeature
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_teleport_decision_v1alpha1_metadata_proto_init() }
func file_teleport_decision_v1alpha1_metadata_proto_init() {
	if File_teleport_decision_v1alpha1_metadata_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_teleport_decision_v1alpha1_metadata_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_teleport_decision_v1alpha1_metadata_proto_goTypes,
		DependencyIndexes: file_teleport_decision_v1alpha1_metadata_proto_depIdxs,
		EnumInfos:         file_teleport_decision_v1alpha1_metadata_proto_enumTypes,
		MessageInfos:      file_teleport_decision_v1alpha1_metadata_proto_msgTypes,
	}.Build()
	File_teleport_decision_v1alpha1_metadata_proto = out.File
	file_teleport_decision_v1alpha1_metadata_proto_rawDesc = nil
	file_teleport_decision_v1alpha1_metadata_proto_goTypes = nil
	file_teleport_decision_v1alpha1_metadata_proto_depIdxs = nil
}
