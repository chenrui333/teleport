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
// source: teleport/userloginstate/v1/userloginstate_service.proto

package userloginstatev1

import (
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

// GetUserLoginStatesRequest is the request for getting all user login states.
type GetUserLoginStatesRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *GetUserLoginStatesRequest) Reset() {
	*x = GetUserLoginStatesRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_userloginstate_v1_userloginstate_service_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetUserLoginStatesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetUserLoginStatesRequest) ProtoMessage() {}

func (x *GetUserLoginStatesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_userloginstate_v1_userloginstate_service_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetUserLoginStatesRequest.ProtoReflect.Descriptor instead.
func (*GetUserLoginStatesRequest) Descriptor() ([]byte, []int) {
	return file_teleport_userloginstate_v1_userloginstate_service_proto_rawDescGZIP(), []int{0}
}

// GetUserLoginStatesResponse is the response for getting all user login states.
type GetUserLoginStatesResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// user_login_states is the list of user login states.
	UserLoginStates []*UserLoginState `protobuf:"bytes,1,rep,name=user_login_states,json=userLoginStates,proto3" json:"user_login_states,omitempty"`
}

func (x *GetUserLoginStatesResponse) Reset() {
	*x = GetUserLoginStatesResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_userloginstate_v1_userloginstate_service_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetUserLoginStatesResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetUserLoginStatesResponse) ProtoMessage() {}

func (x *GetUserLoginStatesResponse) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_userloginstate_v1_userloginstate_service_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetUserLoginStatesResponse.ProtoReflect.Descriptor instead.
func (*GetUserLoginStatesResponse) Descriptor() ([]byte, []int) {
	return file_teleport_userloginstate_v1_userloginstate_service_proto_rawDescGZIP(), []int{1}
}

func (x *GetUserLoginStatesResponse) GetUserLoginStates() []*UserLoginState {
	if x != nil {
		return x.UserLoginStates
	}
	return nil
}

// GetUserLoginStateRequest is the request for retrieving a user login state.
type GetUserLoginStateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// name is the name of the user login state to retrieve.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *GetUserLoginStateRequest) Reset() {
	*x = GetUserLoginStateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_userloginstate_v1_userloginstate_service_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetUserLoginStateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetUserLoginStateRequest) ProtoMessage() {}

func (x *GetUserLoginStateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_userloginstate_v1_userloginstate_service_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetUserLoginStateRequest.ProtoReflect.Descriptor instead.
func (*GetUserLoginStateRequest) Descriptor() ([]byte, []int) {
	return file_teleport_userloginstate_v1_userloginstate_service_proto_rawDescGZIP(), []int{2}
}

func (x *GetUserLoginStateRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

// UpsertUserLoginStateRequest is the request for upserting a user login state.
type UpsertUserLoginStateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// user_login_state is the user login state to upsert.
	UserLoginState *UserLoginState `protobuf:"bytes,1,opt,name=user_login_state,json=userLoginState,proto3" json:"user_login_state,omitempty"`
}

func (x *UpsertUserLoginStateRequest) Reset() {
	*x = UpsertUserLoginStateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_userloginstate_v1_userloginstate_service_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UpsertUserLoginStateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UpsertUserLoginStateRequest) ProtoMessage() {}

func (x *UpsertUserLoginStateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_userloginstate_v1_userloginstate_service_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UpsertUserLoginStateRequest.ProtoReflect.Descriptor instead.
func (*UpsertUserLoginStateRequest) Descriptor() ([]byte, []int) {
	return file_teleport_userloginstate_v1_userloginstate_service_proto_rawDescGZIP(), []int{3}
}

func (x *UpsertUserLoginStateRequest) GetUserLoginState() *UserLoginState {
	if x != nil {
		return x.UserLoginState
	}
	return nil
}

// DeleteUserLoginStateRequest is the request for deleting a user login state.
type DeleteUserLoginStateRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// name is the name of the user login state to delete.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *DeleteUserLoginStateRequest) Reset() {
	*x = DeleteUserLoginStateRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_userloginstate_v1_userloginstate_service_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteUserLoginStateRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteUserLoginStateRequest) ProtoMessage() {}

func (x *DeleteUserLoginStateRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_userloginstate_v1_userloginstate_service_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteUserLoginStateRequest.ProtoReflect.Descriptor instead.
func (*DeleteUserLoginStateRequest) Descriptor() ([]byte, []int) {
	return file_teleport_userloginstate_v1_userloginstate_service_proto_rawDescGZIP(), []int{4}
}

func (x *DeleteUserLoginStateRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

// DeleteAllUserLoginStatesRequest is the request for deleting all user login states.
type DeleteAllUserLoginStatesRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *DeleteAllUserLoginStatesRequest) Reset() {
	*x = DeleteAllUserLoginStatesRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_userloginstate_v1_userloginstate_service_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteAllUserLoginStatesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteAllUserLoginStatesRequest) ProtoMessage() {}

func (x *DeleteAllUserLoginStatesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_userloginstate_v1_userloginstate_service_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteAllUserLoginStatesRequest.ProtoReflect.Descriptor instead.
func (*DeleteAllUserLoginStatesRequest) Descriptor() ([]byte, []int) {
	return file_teleport_userloginstate_v1_userloginstate_service_proto_rawDescGZIP(), []int{5}
}

var File_teleport_userloginstate_v1_userloginstate_service_proto protoreflect.FileDescriptor

var file_teleport_userloginstate_v1_userloginstate_service_proto_rawDesc = []byte{
	0x0a, 0x37, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x75, 0x73, 0x65, 0x72, 0x6c,
	0x6f, 0x67, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x75, 0x73, 0x65,
	0x72, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x74, 0x65, 0x5f, 0x73, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1a, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x73, 0x74, 0x61,
	0x74, 0x65, 0x2e, 0x76, 0x31, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x75, 0x73, 0x65,
	0x72, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x31, 0x2f, 0x75,
	0x73, 0x65, 0x72, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0x1b, 0x0a, 0x19, 0x47, 0x65, 0x74, 0x55, 0x73, 0x65, 0x72, 0x4c, 0x6f,
	0x67, 0x69, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x22, 0x74, 0x0a, 0x1a, 0x47, 0x65, 0x74, 0x55, 0x73, 0x65, 0x72, 0x4c, 0x6f, 0x67, 0x69, 0x6e,
	0x53, 0x74, 0x61, 0x74, 0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x56,
	0x0a, 0x11, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x5f, 0x73, 0x74, 0x61,
	0x74, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2a, 0x2e, 0x74, 0x65, 0x6c, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x73, 0x74,
	0x61, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x4c, 0x6f, 0x67, 0x69, 0x6e,
	0x53, 0x74, 0x61, 0x74, 0x65, 0x52, 0x0f, 0x75, 0x73, 0x65, 0x72, 0x4c, 0x6f, 0x67, 0x69, 0x6e,
	0x53, 0x74, 0x61, 0x74, 0x65, 0x73, 0x22, 0x2e, 0x0a, 0x18, 0x47, 0x65, 0x74, 0x55, 0x73, 0x65,
	0x72, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x73, 0x0a, 0x1b, 0x55, 0x70, 0x73, 0x65, 0x72, 0x74,
	0x55, 0x73, 0x65, 0x72, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x54, 0x0a, 0x10, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x6c, 0x6f,
	0x67, 0x69, 0x6e, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x2a, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x6c,
	0x6f, 0x67, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x73, 0x65,
	0x72, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x52, 0x0e, 0x75, 0x73, 0x65,
	0x72, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x22, 0x31, 0x0a, 0x1b, 0x44,
	0x65, 0x6c, 0x65, 0x74, 0x65, 0x55, 0x73, 0x65, 0x72, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x53, 0x74,
	0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x21,
	0x0a, 0x1f, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x41, 0x6c, 0x6c, 0x55, 0x73, 0x65, 0x72, 0x4c,
	0x6f, 0x67, 0x69, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x32, 0xeb, 0x04, 0x0a, 0x15, 0x55, 0x73, 0x65, 0x72, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x53,
	0x74, 0x61, 0x74, 0x65, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x83, 0x01, 0x0a, 0x12,
	0x47, 0x65, 0x74, 0x55, 0x73, 0x65, 0x72, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x53, 0x74, 0x61, 0x74,
	0x65, 0x73, 0x12, 0x35, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x75, 0x73,
	0x65, 0x72, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x2e,
	0x47, 0x65, 0x74, 0x55, 0x73, 0x65, 0x72, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x53, 0x74, 0x61, 0x74,
	0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x36, 0x2e, 0x74, 0x65, 0x6c, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x73, 0x74,
	0x61, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x55, 0x73, 0x65, 0x72, 0x4c, 0x6f,
	0x67, 0x69, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x75, 0x0a, 0x11, 0x47, 0x65, 0x74, 0x55, 0x73, 0x65, 0x72, 0x4c, 0x6f, 0x67, 0x69,
	0x6e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x34, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x74, 0x65,
	0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x55, 0x73, 0x65, 0x72, 0x4c, 0x6f, 0x67, 0x69, 0x6e,
	0x53, 0x74, 0x61, 0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2a, 0x2e, 0x74,
	0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x6c, 0x6f, 0x67, 0x69,
	0x6e, 0x73, 0x74, 0x61, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x4c, 0x6f,
	0x67, 0x69, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x7b, 0x0a, 0x14, 0x55, 0x70, 0x73, 0x65,
	0x72, 0x74, 0x55, 0x73, 0x65, 0x72, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x65,
	0x12, 0x37, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72,
	0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70,
	0x73, 0x65, 0x72, 0x74, 0x55, 0x73, 0x65, 0x72, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x53, 0x74, 0x61,
	0x74, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x2a, 0x2e, 0x74, 0x65, 0x6c, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x73, 0x74,
	0x61, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x4c, 0x6f, 0x67, 0x69, 0x6e,
	0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x67, 0x0a, 0x14, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x55,
	0x73, 0x65, 0x72, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x12, 0x37, 0x2e,
	0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x6c, 0x6f, 0x67,
	0x69, 0x6e, 0x73, 0x74, 0x61, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74,
	0x65, 0x55, 0x73, 0x65, 0x72, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x12, 0x6f,
	0x0a, 0x18, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x41, 0x6c, 0x6c, 0x55, 0x73, 0x65, 0x72, 0x4c,
	0x6f, 0x67, 0x69, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x73, 0x12, 0x3b, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x72, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x73,
	0x74, 0x61, 0x74, 0x65, 0x2e, 0x76, 0x31, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x41, 0x6c,
	0x6c, 0x55, 0x73, 0x65, 0x72, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x53, 0x74, 0x61, 0x74, 0x65, 0x73,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x42,
	0x60, 0x5a, 0x5e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72,
	0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x75,
	0x73, 0x65, 0x72, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x31,
	0x3b, 0x75, 0x73, 0x65, 0x72, 0x6c, 0x6f, 0x67, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x74, 0x65, 0x76,
	0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_userloginstate_v1_userloginstate_service_proto_rawDescOnce sync.Once
	file_teleport_userloginstate_v1_userloginstate_service_proto_rawDescData = file_teleport_userloginstate_v1_userloginstate_service_proto_rawDesc
)

func file_teleport_userloginstate_v1_userloginstate_service_proto_rawDescGZIP() []byte {
	file_teleport_userloginstate_v1_userloginstate_service_proto_rawDescOnce.Do(func() {
		file_teleport_userloginstate_v1_userloginstate_service_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_userloginstate_v1_userloginstate_service_proto_rawDescData)
	})
	return file_teleport_userloginstate_v1_userloginstate_service_proto_rawDescData
}

var file_teleport_userloginstate_v1_userloginstate_service_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_teleport_userloginstate_v1_userloginstate_service_proto_goTypes = []interface{}{
	(*GetUserLoginStatesRequest)(nil),       // 0: teleport.userloginstate.v1.GetUserLoginStatesRequest
	(*GetUserLoginStatesResponse)(nil),      // 1: teleport.userloginstate.v1.GetUserLoginStatesResponse
	(*GetUserLoginStateRequest)(nil),        // 2: teleport.userloginstate.v1.GetUserLoginStateRequest
	(*UpsertUserLoginStateRequest)(nil),     // 3: teleport.userloginstate.v1.UpsertUserLoginStateRequest
	(*DeleteUserLoginStateRequest)(nil),     // 4: teleport.userloginstate.v1.DeleteUserLoginStateRequest
	(*DeleteAllUserLoginStatesRequest)(nil), // 5: teleport.userloginstate.v1.DeleteAllUserLoginStatesRequest
	(*UserLoginState)(nil),                  // 6: teleport.userloginstate.v1.UserLoginState
	(*emptypb.Empty)(nil),                   // 7: google.protobuf.Empty
}
var file_teleport_userloginstate_v1_userloginstate_service_proto_depIdxs = []int32{
	6, // 0: teleport.userloginstate.v1.GetUserLoginStatesResponse.user_login_states:type_name -> teleport.userloginstate.v1.UserLoginState
	6, // 1: teleport.userloginstate.v1.UpsertUserLoginStateRequest.user_login_state:type_name -> teleport.userloginstate.v1.UserLoginState
	0, // 2: teleport.userloginstate.v1.UserLoginStateService.GetUserLoginStates:input_type -> teleport.userloginstate.v1.GetUserLoginStatesRequest
	2, // 3: teleport.userloginstate.v1.UserLoginStateService.GetUserLoginState:input_type -> teleport.userloginstate.v1.GetUserLoginStateRequest
	3, // 4: teleport.userloginstate.v1.UserLoginStateService.UpsertUserLoginState:input_type -> teleport.userloginstate.v1.UpsertUserLoginStateRequest
	4, // 5: teleport.userloginstate.v1.UserLoginStateService.DeleteUserLoginState:input_type -> teleport.userloginstate.v1.DeleteUserLoginStateRequest
	5, // 6: teleport.userloginstate.v1.UserLoginStateService.DeleteAllUserLoginStates:input_type -> teleport.userloginstate.v1.DeleteAllUserLoginStatesRequest
	1, // 7: teleport.userloginstate.v1.UserLoginStateService.GetUserLoginStates:output_type -> teleport.userloginstate.v1.GetUserLoginStatesResponse
	6, // 8: teleport.userloginstate.v1.UserLoginStateService.GetUserLoginState:output_type -> teleport.userloginstate.v1.UserLoginState
	6, // 9: teleport.userloginstate.v1.UserLoginStateService.UpsertUserLoginState:output_type -> teleport.userloginstate.v1.UserLoginState
	7, // 10: teleport.userloginstate.v1.UserLoginStateService.DeleteUserLoginState:output_type -> google.protobuf.Empty
	7, // 11: teleport.userloginstate.v1.UserLoginStateService.DeleteAllUserLoginStates:output_type -> google.protobuf.Empty
	7, // [7:12] is the sub-list for method output_type
	2, // [2:7] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_teleport_userloginstate_v1_userloginstate_service_proto_init() }
func file_teleport_userloginstate_v1_userloginstate_service_proto_init() {
	if File_teleport_userloginstate_v1_userloginstate_service_proto != nil {
		return
	}
	file_teleport_userloginstate_v1_userloginstate_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_teleport_userloginstate_v1_userloginstate_service_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetUserLoginStatesRequest); i {
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
		file_teleport_userloginstate_v1_userloginstate_service_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetUserLoginStatesResponse); i {
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
		file_teleport_userloginstate_v1_userloginstate_service_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetUserLoginStateRequest); i {
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
		file_teleport_userloginstate_v1_userloginstate_service_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UpsertUserLoginStateRequest); i {
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
		file_teleport_userloginstate_v1_userloginstate_service_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteUserLoginStateRequest); i {
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
		file_teleport_userloginstate_v1_userloginstate_service_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DeleteAllUserLoginStatesRequest); i {
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
			RawDescriptor: file_teleport_userloginstate_v1_userloginstate_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_teleport_userloginstate_v1_userloginstate_service_proto_goTypes,
		DependencyIndexes: file_teleport_userloginstate_v1_userloginstate_service_proto_depIdxs,
		MessageInfos:      file_teleport_userloginstate_v1_userloginstate_service_proto_msgTypes,
	}.Build()
	File_teleport_userloginstate_v1_userloginstate_service_proto = out.File
	file_teleport_userloginstate_v1_userloginstate_service_proto_rawDesc = nil
	file_teleport_userloginstate_v1_userloginstate_service_proto_goTypes = nil
	file_teleport_userloginstate_v1_userloginstate_service_proto_depIdxs = nil
}
