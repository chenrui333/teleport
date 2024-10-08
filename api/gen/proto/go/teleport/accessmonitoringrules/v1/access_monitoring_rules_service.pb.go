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
// source: teleport/accessmonitoringrules/v1/access_monitoring_rules_service.proto

package accessmonitoringrulesv1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	reflect "reflect"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

var File_teleport_accessmonitoringrules_v1_access_monitoring_rules_service_proto protoreflect.FileDescriptor

var file_teleport_accessmonitoringrules_v1_access_monitoring_rules_service_proto_rawDesc = []byte{
	0x0a, 0x47, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x72, 0x75, 0x6c, 0x65, 0x73,
	0x2f, 0x76, 0x31, 0x2f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x6d, 0x6f, 0x6e, 0x69, 0x74,
	0x6f, 0x72, 0x69, 0x6e, 0x67, 0x5f, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x5f, 0x73, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x21, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f,
	0x72, 0x69, 0x6e, 0x67, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x1a, 0x1b, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d,
	0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x3f, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f,
	0x72, 0x69, 0x6e, 0x67, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x63, 0x63,
	0x65, 0x73, 0x73, 0x5f, 0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x5f, 0x72,
	0x75, 0x6c, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x32, 0xfc, 0x08, 0x0a, 0x1c, 0x41,
	0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x52,
	0x75, 0x6c, 0x65, 0x73, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x9b, 0x01, 0x0a, 0x1a,
	0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69,
	0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x12, 0x44, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6d, 0x6f, 0x6e, 0x69,
	0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x43,
	0x72, 0x65, 0x61, 0x74, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74,
	0x6f, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x37, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x63, 0x63, 0x65,
	0x73, 0x73, 0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x72, 0x75, 0x6c, 0x65,
	0x73, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74,
	0x6f, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x12, 0x9b, 0x01, 0x0a, 0x1a, 0x55, 0x70,
	0x64, 0x61, 0x74, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f,
	0x72, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x12, 0x44, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70,
	0x6f, 0x72, 0x74, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f,
	0x72, 0x69, 0x6e, 0x67, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x64,
	0x61, 0x74, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72,
	0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x37,
	0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73,
	0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x2e,
	0x76, 0x31, 0x2e, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72,
	0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x12, 0x9b, 0x01, 0x0a, 0x1a, 0x55, 0x70, 0x73, 0x65,
	0x72, 0x74, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69,
	0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x12, 0x44, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72,
	0x74, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69,
	0x6e, 0x67, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x73, 0x65, 0x72,
	0x74, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e,
	0x67, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x37, 0x2e, 0x74,
	0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6d, 0x6f,
	0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x2e, 0x76, 0x31,
	0x2e, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e,
	0x67, 0x52, 0x75, 0x6c, 0x65, 0x12, 0x95, 0x01, 0x0a, 0x17, 0x47, 0x65, 0x74, 0x41, 0x63, 0x63,
	0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c,
	0x65, 0x12, 0x41, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x63, 0x63,
	0x65, 0x73, 0x73, 0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x72, 0x75, 0x6c,
	0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x47, 0x65, 0x74, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d,
	0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x37, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e,
	0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67,
	0x72, 0x75, 0x6c, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d,
	0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x12, 0x7a, 0x0a,
	0x1a, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e,
	0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x12, 0x44, 0x2e, 0x74, 0x65,
	0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6d, 0x6f, 0x6e,
	0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e,
	0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69,
	0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x12, 0xa6, 0x01, 0x0a, 0x19, 0x4c, 0x69,
	0x73, 0x74, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69,
	0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x73, 0x12, 0x43, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f,
	0x72, 0x74, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72,
	0x69, 0x6e, 0x67, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69, 0x73, 0x74,
	0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67,
	0x52, 0x75, 0x6c, 0x65, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x44, 0x2e, 0x74,
	0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6d, 0x6f,
	0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x2e, 0x76, 0x31,
	0x2e, 0x4c, 0x69, 0x73, 0x74, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74,
	0x6f, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0xc4, 0x01, 0x0a, 0x23, 0x4c, 0x69, 0x73, 0x74, 0x41, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x73,
	0x57, 0x69, 0x74, 0x68, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x12, 0x4d, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6d, 0x6f, 0x6e, 0x69,
	0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x4c,
	0x69, 0x73, 0x74, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72,
	0x69, 0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x73, 0x57, 0x69, 0x74, 0x68, 0x46, 0x69, 0x6c, 0x74,
	0x65, 0x72, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x4e, 0x2e, 0x74, 0x65, 0x6c, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x2e, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6d, 0x6f, 0x6e, 0x69, 0x74,
	0x6f, 0x72, 0x69, 0x6e, 0x67, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x4c, 0x69,
	0x73, 0x74, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69,
	0x6e, 0x67, 0x52, 0x75, 0x6c, 0x65, 0x73, 0x57, 0x69, 0x74, 0x68, 0x46, 0x69, 0x6c, 0x74, 0x65,
	0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x6e, 0x5a, 0x6c, 0x67, 0x69, 0x74,
	0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61,
	0x70, 0x69, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f,
	0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6d,
	0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69, 0x6e, 0x67, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x2f, 0x76,
	0x31, 0x3b, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x6d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x69,
	0x6e, 0x67, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var file_teleport_accessmonitoringrules_v1_access_monitoring_rules_service_proto_goTypes = []any{
	(*CreateAccessMonitoringRuleRequest)(nil),           // 0: teleport.accessmonitoringrules.v1.CreateAccessMonitoringRuleRequest
	(*UpdateAccessMonitoringRuleRequest)(nil),           // 1: teleport.accessmonitoringrules.v1.UpdateAccessMonitoringRuleRequest
	(*UpsertAccessMonitoringRuleRequest)(nil),           // 2: teleport.accessmonitoringrules.v1.UpsertAccessMonitoringRuleRequest
	(*GetAccessMonitoringRuleRequest)(nil),              // 3: teleport.accessmonitoringrules.v1.GetAccessMonitoringRuleRequest
	(*DeleteAccessMonitoringRuleRequest)(nil),           // 4: teleport.accessmonitoringrules.v1.DeleteAccessMonitoringRuleRequest
	(*ListAccessMonitoringRulesRequest)(nil),            // 5: teleport.accessmonitoringrules.v1.ListAccessMonitoringRulesRequest
	(*ListAccessMonitoringRulesWithFilterRequest)(nil),  // 6: teleport.accessmonitoringrules.v1.ListAccessMonitoringRulesWithFilterRequest
	(*AccessMonitoringRule)(nil),                        // 7: teleport.accessmonitoringrules.v1.AccessMonitoringRule
	(*emptypb.Empty)(nil),                               // 8: google.protobuf.Empty
	(*ListAccessMonitoringRulesResponse)(nil),           // 9: teleport.accessmonitoringrules.v1.ListAccessMonitoringRulesResponse
	(*ListAccessMonitoringRulesWithFilterResponse)(nil), // 10: teleport.accessmonitoringrules.v1.ListAccessMonitoringRulesWithFilterResponse
}
var file_teleport_accessmonitoringrules_v1_access_monitoring_rules_service_proto_depIdxs = []int32{
	0,  // 0: teleport.accessmonitoringrules.v1.AccessMonitoringRulesService.CreateAccessMonitoringRule:input_type -> teleport.accessmonitoringrules.v1.CreateAccessMonitoringRuleRequest
	1,  // 1: teleport.accessmonitoringrules.v1.AccessMonitoringRulesService.UpdateAccessMonitoringRule:input_type -> teleport.accessmonitoringrules.v1.UpdateAccessMonitoringRuleRequest
	2,  // 2: teleport.accessmonitoringrules.v1.AccessMonitoringRulesService.UpsertAccessMonitoringRule:input_type -> teleport.accessmonitoringrules.v1.UpsertAccessMonitoringRuleRequest
	3,  // 3: teleport.accessmonitoringrules.v1.AccessMonitoringRulesService.GetAccessMonitoringRule:input_type -> teleport.accessmonitoringrules.v1.GetAccessMonitoringRuleRequest
	4,  // 4: teleport.accessmonitoringrules.v1.AccessMonitoringRulesService.DeleteAccessMonitoringRule:input_type -> teleport.accessmonitoringrules.v1.DeleteAccessMonitoringRuleRequest
	5,  // 5: teleport.accessmonitoringrules.v1.AccessMonitoringRulesService.ListAccessMonitoringRules:input_type -> teleport.accessmonitoringrules.v1.ListAccessMonitoringRulesRequest
	6,  // 6: teleport.accessmonitoringrules.v1.AccessMonitoringRulesService.ListAccessMonitoringRulesWithFilter:input_type -> teleport.accessmonitoringrules.v1.ListAccessMonitoringRulesWithFilterRequest
	7,  // 7: teleport.accessmonitoringrules.v1.AccessMonitoringRulesService.CreateAccessMonitoringRule:output_type -> teleport.accessmonitoringrules.v1.AccessMonitoringRule
	7,  // 8: teleport.accessmonitoringrules.v1.AccessMonitoringRulesService.UpdateAccessMonitoringRule:output_type -> teleport.accessmonitoringrules.v1.AccessMonitoringRule
	7,  // 9: teleport.accessmonitoringrules.v1.AccessMonitoringRulesService.UpsertAccessMonitoringRule:output_type -> teleport.accessmonitoringrules.v1.AccessMonitoringRule
	7,  // 10: teleport.accessmonitoringrules.v1.AccessMonitoringRulesService.GetAccessMonitoringRule:output_type -> teleport.accessmonitoringrules.v1.AccessMonitoringRule
	8,  // 11: teleport.accessmonitoringrules.v1.AccessMonitoringRulesService.DeleteAccessMonitoringRule:output_type -> google.protobuf.Empty
	9,  // 12: teleport.accessmonitoringrules.v1.AccessMonitoringRulesService.ListAccessMonitoringRules:output_type -> teleport.accessmonitoringrules.v1.ListAccessMonitoringRulesResponse
	10, // 13: teleport.accessmonitoringrules.v1.AccessMonitoringRulesService.ListAccessMonitoringRulesWithFilter:output_type -> teleport.accessmonitoringrules.v1.ListAccessMonitoringRulesWithFilterResponse
	7,  // [7:14] is the sub-list for method output_type
	0,  // [0:7] is the sub-list for method input_type
	0,  // [0:0] is the sub-list for extension type_name
	0,  // [0:0] is the sub-list for extension extendee
	0,  // [0:0] is the sub-list for field type_name
}

func init() { file_teleport_accessmonitoringrules_v1_access_monitoring_rules_service_proto_init() }
func file_teleport_accessmonitoringrules_v1_access_monitoring_rules_service_proto_init() {
	if File_teleport_accessmonitoringrules_v1_access_monitoring_rules_service_proto != nil {
		return
	}
	file_teleport_accessmonitoringrules_v1_access_monitoring_rules_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_teleport_accessmonitoringrules_v1_access_monitoring_rules_service_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_teleport_accessmonitoringrules_v1_access_monitoring_rules_service_proto_goTypes,
		DependencyIndexes: file_teleport_accessmonitoringrules_v1_access_monitoring_rules_service_proto_depIdxs,
	}.Build()
	File_teleport_accessmonitoringrules_v1_access_monitoring_rules_service_proto = out.File
	file_teleport_accessmonitoringrules_v1_access_monitoring_rules_service_proto_rawDesc = nil
	file_teleport_accessmonitoringrules_v1_access_monitoring_rules_service_proto_goTypes = nil
	file_teleport_accessmonitoringrules_v1_access_monitoring_rules_service_proto_depIdxs = nil
}
