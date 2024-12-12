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
// source: teleport/workloadidentity/v1/attrs.proto

package workloadidentityv1pb

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

// Attributes sourced from the Kubernetes workload attestor.
type WorkloadAttrsKubernetes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Whether the workload passed Kubernetes attestation.
	Attested bool `protobuf:"varint,1,opt,name=attested,proto3" json:"attested,omitempty"`
	// The namespace of the workload pod.
	Namespace string `protobuf:"bytes,2,opt,name=namespace,proto3" json:"namespace,omitempty"`
	// The name of the workload pod.
	PodName string `protobuf:"bytes,3,opt,name=pod_name,json=podName,proto3" json:"pod_name,omitempty"`
	// The service account of the workload pod.
	ServiceAccount string `protobuf:"bytes,4,opt,name=service_account,json=serviceAccount,proto3" json:"service_account,omitempty"`
	// The UID of the workload pod.
	PodUid string `protobuf:"bytes,5,opt,name=pod_uid,json=podUid,proto3" json:"pod_uid,omitempty"`
	// The labels of the workload pod.
	Labels map[string]string `protobuf:"bytes,6,rep,name=labels,proto3" json:"labels,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *WorkloadAttrsKubernetes) Reset() {
	*x = WorkloadAttrsKubernetes{}
	mi := &file_teleport_workloadidentity_v1_attrs_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *WorkloadAttrsKubernetes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WorkloadAttrsKubernetes) ProtoMessage() {}

func (x *WorkloadAttrsKubernetes) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_workloadidentity_v1_attrs_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WorkloadAttrsKubernetes.ProtoReflect.Descriptor instead.
func (*WorkloadAttrsKubernetes) Descriptor() ([]byte, []int) {
	return file_teleport_workloadidentity_v1_attrs_proto_rawDescGZIP(), []int{0}
}

func (x *WorkloadAttrsKubernetes) GetAttested() bool {
	if x != nil {
		return x.Attested
	}
	return false
}

func (x *WorkloadAttrsKubernetes) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}

func (x *WorkloadAttrsKubernetes) GetPodName() string {
	if x != nil {
		return x.PodName
	}
	return ""
}

func (x *WorkloadAttrsKubernetes) GetServiceAccount() string {
	if x != nil {
		return x.ServiceAccount
	}
	return ""
}

func (x *WorkloadAttrsKubernetes) GetPodUid() string {
	if x != nil {
		return x.PodUid
	}
	return ""
}

func (x *WorkloadAttrsKubernetes) GetLabels() map[string]string {
	if x != nil {
		return x.Labels
	}
	return nil
}

// Attributes sourced from the Unix workload attestor.
type WorkloadAttrsUnix struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Whether the workload passed Kubernetes attestation.
	Attested bool `protobuf:"varint,1,opt,name=attested,proto3" json:"attested,omitempty"`
	// The PID of the workload process.
	Pid int32 `protobuf:"varint,2,opt,name=pid,proto3" json:"pid,omitempty"`
	// The primary user ID of the workload process.
	Gid uint32 `protobuf:"varint,3,opt,name=gid,proto3" json:"gid,omitempty"`
	// The primary group ID of the workload process.
	Uid uint32 `protobuf:"varint,4,opt,name=uid,proto3" json:"uid,omitempty"`
}

func (x *WorkloadAttrsUnix) Reset() {
	*x = WorkloadAttrsUnix{}
	mi := &file_teleport_workloadidentity_v1_attrs_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *WorkloadAttrsUnix) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WorkloadAttrsUnix) ProtoMessage() {}

func (x *WorkloadAttrsUnix) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_workloadidentity_v1_attrs_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use WorkloadAttrsUnix.ProtoReflect.Descriptor instead.
func (*WorkloadAttrsUnix) Descriptor() ([]byte, []int) {
	return file_teleport_workloadidentity_v1_attrs_proto_rawDescGZIP(), []int{1}
}

func (x *WorkloadAttrsUnix) GetAttested() bool {
	if x != nil {
		return x.Attested
	}
	return false
}

func (x *WorkloadAttrsUnix) GetPid() int32 {
	if x != nil {
		return x.Pid
	}
	return 0
}

func (x *WorkloadAttrsUnix) GetGid() uint32 {
	if x != nil {
		return x.Gid
	}
	return 0
}

func (x *WorkloadAttrsUnix) GetUid() uint32 {
	if x != nil {
		return x.Uid
	}
	return 0
}

// The attributes provided by `tbot` regarding the workload's attestation.
// This will be mostly unset if the workload has not requested credentials via
// the SPIFFE Workload API.
type WorkloadAttrs struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The Unix-specific attributes.
	Unix *WorkloadAttrsUnix `protobuf:"bytes,1,opt,name=unix,proto3" json:"unix,omitempty"`
	// The Kubernetes-specific attributes.
	Kubernetes *WorkloadAttrsKubernetes `protobuf:"bytes,2,opt,name=kubernetes,proto3" json:"kubernetes,omitempty"`
}

func (x *WorkloadAttrs) Reset() {
	*x = WorkloadAttrs{}
	mi := &file_teleport_workloadidentity_v1_attrs_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *WorkloadAttrs) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*WorkloadAttrs) ProtoMessage() {}

func (x *WorkloadAttrs) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_workloadidentity_v1_attrs_proto_msgTypes[2]
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
	return file_teleport_workloadidentity_v1_attrs_proto_rawDescGZIP(), []int{2}
}

func (x *WorkloadAttrs) GetUnix() *WorkloadAttrsUnix {
	if x != nil {
		return x.Unix
	}
	return nil
}

func (x *WorkloadAttrs) GetKubernetes() *WorkloadAttrsKubernetes {
	if x != nil {
		return x.Kubernetes
	}
	return nil
}

// TODO: Comment
type JoinAttrs struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *JoinAttrs) Reset() {
	*x = JoinAttrs{}
	mi := &file_teleport_workloadidentity_v1_attrs_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *JoinAttrs) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*JoinAttrs) ProtoMessage() {}

func (x *JoinAttrs) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_workloadidentity_v1_attrs_proto_msgTypes[3]
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
	return file_teleport_workloadidentity_v1_attrs_proto_rawDescGZIP(), []int{3}
}

// Attributes related to the user/bot making the request for a workload
// identity.
type UserAttrs struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The name of the user.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Whether the user is a bot.
	IsBot bool `protobuf:"varint,2,opt,name=is_bot,json=isBot,proto3" json:"is_bot,omitempty"`
	// If the user is a bot, the name of the bot.
	BotName string `protobuf:"bytes,3,opt,name=bot_name,json=botName,proto3" json:"bot_name,omitempty"`
	// If the user is a bot, the instance ID of the bot.
	BotInstanceId string `protobuf:"bytes,4,opt,name=bot_instance_id,json=botInstanceId,proto3" json:"bot_instance_id,omitempty"`
	// Labels of the user.
	Labels map[string]string `protobuf:"bytes,5,rep,name=labels,proto3" json:"labels,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *UserAttrs) Reset() {
	*x = UserAttrs{}
	mi := &file_teleport_workloadidentity_v1_attrs_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *UserAttrs) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UserAttrs) ProtoMessage() {}

func (x *UserAttrs) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_workloadidentity_v1_attrs_proto_msgTypes[4]
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
	return file_teleport_workloadidentity_v1_attrs_proto_rawDescGZIP(), []int{4}
}

func (x *UserAttrs) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *UserAttrs) GetIsBot() bool {
	if x != nil {
		return x.IsBot
	}
	return false
}

func (x *UserAttrs) GetBotName() string {
	if x != nil {
		return x.BotName
	}
	return ""
}

func (x *UserAttrs) GetBotInstanceId() string {
	if x != nil {
		return x.BotInstanceId
	}
	return ""
}

func (x *UserAttrs) GetLabels() map[string]string {
	if x != nil {
		return x.Labels
	}
	return nil
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
	mi := &file_teleport_workloadidentity_v1_attrs_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Attrs) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Attrs) ProtoMessage() {}

func (x *Attrs) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_workloadidentity_v1_attrs_proto_msgTypes[5]
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
	return file_teleport_workloadidentity_v1_attrs_proto_rawDescGZIP(), []int{5}
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

var File_teleport_workloadidentity_v1_attrs_proto protoreflect.FileDescriptor

var file_teleport_workloadidentity_v1_attrs_proto_rawDesc = []byte{
	0x0a, 0x28, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x77, 0x6f, 0x72, 0x6b, 0x6c,
	0x6f, 0x61, 0x64, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2f, 0x76, 0x31, 0x2f, 0x61,
	0x74, 0x74, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1c, 0x74, 0x65, 0x6c, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x2e, 0x77, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x69, 0x64, 0x65,
	0x6e, 0x74, 0x69, 0x74, 0x79, 0x2e, 0x76, 0x31, 0x22, 0xc6, 0x02, 0x0a, 0x17, 0x57, 0x6f, 0x72,
	0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x41, 0x74, 0x74, 0x72, 0x73, 0x4b, 0x75, 0x62, 0x65, 0x72, 0x6e,
	0x65, 0x74, 0x65, 0x73, 0x12, 0x1a, 0x0a, 0x08, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x65, 0x64,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x08, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x65, 0x64,
	0x12, 0x1c, 0x0a, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x12, 0x19,
	0x0a, 0x08, 0x70, 0x6f, 0x64, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x07, 0x70, 0x6f, 0x64, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x27, 0x0a, 0x0f, 0x73, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x5f, 0x61, 0x63, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x41, 0x63, 0x63, 0x6f, 0x75,
	0x6e, 0x74, 0x12, 0x17, 0x0a, 0x07, 0x70, 0x6f, 0x64, 0x5f, 0x75, 0x69, 0x64, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x06, 0x70, 0x6f, 0x64, 0x55, 0x69, 0x64, 0x12, 0x59, 0x0a, 0x06, 0x6c,
	0x61, 0x62, 0x65, 0x6c, 0x73, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x41, 0x2e, 0x74, 0x65,
	0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x77, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x69,
	0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x57, 0x6f, 0x72, 0x6b, 0x6c,
	0x6f, 0x61, 0x64, 0x41, 0x74, 0x74, 0x72, 0x73, 0x4b, 0x75, 0x62, 0x65, 0x72, 0x6e, 0x65, 0x74,
	0x65, 0x73, 0x2e, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x06,
	0x6c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x1a, 0x39, 0x0a, 0x0b, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73,
	0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38,
	0x01, 0x22, 0x65, 0x0a, 0x11, 0x57, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x41, 0x74, 0x74,
	0x72, 0x73, 0x55, 0x6e, 0x69, 0x78, 0x12, 0x1a, 0x0a, 0x08, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74,
	0x65, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x08, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74,
	0x65, 0x64, 0x12, 0x10, 0x0a, 0x03, 0x70, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x05, 0x52,
	0x03, 0x70, 0x69, 0x64, 0x12, 0x10, 0x0a, 0x03, 0x67, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x03, 0x67, 0x69, 0x64, 0x12, 0x10, 0x0a, 0x03, 0x75, 0x69, 0x64, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x03, 0x75, 0x69, 0x64, 0x22, 0xab, 0x01, 0x0a, 0x0d, 0x57, 0x6f, 0x72,
	0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x41, 0x74, 0x74, 0x72, 0x73, 0x12, 0x43, 0x0a, 0x04, 0x75, 0x6e,
	0x69, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2f, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2e, 0x77, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x69, 0x64, 0x65, 0x6e,
	0x74, 0x69, 0x74, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x57, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64,
	0x41, 0x74, 0x74, 0x72, 0x73, 0x55, 0x6e, 0x69, 0x78, 0x52, 0x04, 0x75, 0x6e, 0x69, 0x78, 0x12,
	0x55, 0x0a, 0x0a, 0x6b, 0x75, 0x62, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x65, 0x73, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x35, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x77,
	0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2e,
	0x76, 0x31, 0x2e, 0x57, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x41, 0x74, 0x74, 0x72, 0x73,
	0x4b, 0x75, 0x62, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x65, 0x73, 0x52, 0x0a, 0x6b, 0x75, 0x62, 0x65,
	0x72, 0x6e, 0x65, 0x74, 0x65, 0x73, 0x22, 0x0b, 0x0a, 0x09, 0x4a, 0x6f, 0x69, 0x6e, 0x41, 0x74,
	0x74, 0x72, 0x73, 0x22, 0x81, 0x02, 0x0a, 0x09, 0x55, 0x73, 0x65, 0x72, 0x41, 0x74, 0x74, 0x72,
	0x73, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x15, 0x0a, 0x06, 0x69, 0x73, 0x5f, 0x62, 0x6f, 0x74, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x05, 0x69, 0x73, 0x42, 0x6f, 0x74, 0x12, 0x19, 0x0a, 0x08,
	0x62, 0x6f, 0x74, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07,
	0x62, 0x6f, 0x74, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x26, 0x0a, 0x0f, 0x62, 0x6f, 0x74, 0x5f, 0x69,
	0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0d, 0x62, 0x6f, 0x74, 0x49, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x49, 0x64, 0x12,
	0x4b, 0x0a, 0x06, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x33, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x77, 0x6f, 0x72, 0x6b, 0x6c,
	0x6f, 0x61, 0x64, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x55,
	0x73, 0x65, 0x72, 0x41, 0x74, 0x74, 0x72, 0x73, 0x2e, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x52, 0x06, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x1a, 0x39, 0x0a, 0x0b,
	0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b,
	0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14, 0x0a,
	0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76, 0x61,
	0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0xca, 0x01, 0x0a, 0x05, 0x41, 0x74, 0x74, 0x72,
	0x73, 0x12, 0x3b, 0x0a, 0x04, 0x6a, 0x6f, 0x69, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x27, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x77, 0x6f, 0x72, 0x6b, 0x6c,
	0x6f, 0x61, 0x64, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2e, 0x76, 0x31, 0x2e, 0x4a,
	0x6f, 0x69, 0x6e, 0x41, 0x74, 0x74, 0x72, 0x73, 0x52, 0x04, 0x6a, 0x6f, 0x69, 0x6e, 0x12, 0x47,
	0x0a, 0x08, 0x77, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x2b, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x77, 0x6f, 0x72, 0x6b,
	0x6c, 0x6f, 0x61, 0x64, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x2e, 0x76, 0x31, 0x2e,
	0x57, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x41, 0x74, 0x74, 0x72, 0x73, 0x52, 0x08, 0x77,
	0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x3b, 0x0a, 0x04, 0x75, 0x73, 0x65, 0x72, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74,
	0x2e, 0x77, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74,
	0x79, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x41, 0x74, 0x74, 0x72, 0x73, 0x52, 0x04,
	0x75, 0x73, 0x65, 0x72, 0x42, 0x66, 0x5a, 0x64, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c,
	0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x65,
	0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2f, 0x77, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64, 0x69, 0x64, 0x65, 0x6e,
	0x74, 0x69, 0x74, 0x79, 0x2f, 0x76, 0x31, 0x3b, 0x77, 0x6f, 0x72, 0x6b, 0x6c, 0x6f, 0x61, 0x64,
	0x69, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x76, 0x31, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_workloadidentity_v1_attrs_proto_rawDescOnce sync.Once
	file_teleport_workloadidentity_v1_attrs_proto_rawDescData = file_teleport_workloadidentity_v1_attrs_proto_rawDesc
)

func file_teleport_workloadidentity_v1_attrs_proto_rawDescGZIP() []byte {
	file_teleport_workloadidentity_v1_attrs_proto_rawDescOnce.Do(func() {
		file_teleport_workloadidentity_v1_attrs_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_workloadidentity_v1_attrs_proto_rawDescData)
	})
	return file_teleport_workloadidentity_v1_attrs_proto_rawDescData
}

var file_teleport_workloadidentity_v1_attrs_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_teleport_workloadidentity_v1_attrs_proto_goTypes = []any{
	(*WorkloadAttrsKubernetes)(nil), // 0: teleport.workloadidentity.v1.WorkloadAttrsKubernetes
	(*WorkloadAttrsUnix)(nil),       // 1: teleport.workloadidentity.v1.WorkloadAttrsUnix
	(*WorkloadAttrs)(nil),           // 2: teleport.workloadidentity.v1.WorkloadAttrs
	(*JoinAttrs)(nil),               // 3: teleport.workloadidentity.v1.JoinAttrs
	(*UserAttrs)(nil),               // 4: teleport.workloadidentity.v1.UserAttrs
	(*Attrs)(nil),                   // 5: teleport.workloadidentity.v1.Attrs
	nil,                             // 6: teleport.workloadidentity.v1.WorkloadAttrsKubernetes.LabelsEntry
	nil,                             // 7: teleport.workloadidentity.v1.UserAttrs.LabelsEntry
}
var file_teleport_workloadidentity_v1_attrs_proto_depIdxs = []int32{
	6, // 0: teleport.workloadidentity.v1.WorkloadAttrsKubernetes.labels:type_name -> teleport.workloadidentity.v1.WorkloadAttrsKubernetes.LabelsEntry
	1, // 1: teleport.workloadidentity.v1.WorkloadAttrs.unix:type_name -> teleport.workloadidentity.v1.WorkloadAttrsUnix
	0, // 2: teleport.workloadidentity.v1.WorkloadAttrs.kubernetes:type_name -> teleport.workloadidentity.v1.WorkloadAttrsKubernetes
	7, // 3: teleport.workloadidentity.v1.UserAttrs.labels:type_name -> teleport.workloadidentity.v1.UserAttrs.LabelsEntry
	3, // 4: teleport.workloadidentity.v1.Attrs.join:type_name -> teleport.workloadidentity.v1.JoinAttrs
	2, // 5: teleport.workloadidentity.v1.Attrs.workload:type_name -> teleport.workloadidentity.v1.WorkloadAttrs
	4, // 6: teleport.workloadidentity.v1.Attrs.user:type_name -> teleport.workloadidentity.v1.UserAttrs
	7, // [7:7] is the sub-list for method output_type
	7, // [7:7] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_teleport_workloadidentity_v1_attrs_proto_init() }
func file_teleport_workloadidentity_v1_attrs_proto_init() {
	if File_teleport_workloadidentity_v1_attrs_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_teleport_workloadidentity_v1_attrs_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_teleport_workloadidentity_v1_attrs_proto_goTypes,
		DependencyIndexes: file_teleport_workloadidentity_v1_attrs_proto_depIdxs,
		MessageInfos:      file_teleport_workloadidentity_v1_attrs_proto_msgTypes,
	}.Build()
	File_teleport_workloadidentity_v1_attrs_proto = out.File
	file_teleport_workloadidentity_v1_attrs_proto_rawDesc = nil
	file_teleport_workloadidentity_v1_attrs_proto_goTypes = nil
	file_teleport_workloadidentity_v1_attrs_proto_depIdxs = nil
}
