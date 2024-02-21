//
// Teleport
// Copyright (C) 2023  Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.32.0
// 	protoc        (unknown)
// source: teleport/lib/teleterm/v1/auth_settings.proto

package teletermv1

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

// AuthSettings contains the form of authentication the auth server supports.
type AuthSettings struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// local_auth_enabled is a flag that enables local authentication
	LocalAuthEnabled bool `protobuf:"varint,1,opt,name=local_auth_enabled,json=localAuthEnabled,proto3" json:"local_auth_enabled,omitempty"`
	// second_factor is the type of second factor to use in authentication.
	SecondFactor string `protobuf:"bytes,2,opt,name=second_factor,json=secondFactor,proto3" json:"second_factor,omitempty"`
	// preferred_mfa is the prefered mfa for local logins
	PreferredMfa string `protobuf:"bytes,3,opt,name=preferred_mfa,json=preferredMfa,proto3" json:"preferred_mfa,omitempty"`
	// auth_providers contains a list of auth providers
	AuthProviders []*AuthProvider `protobuf:"bytes,4,rep,name=auth_providers,json=authProviders,proto3" json:"auth_providers,omitempty"`
	// has_message_of_the_day is a flag indicating that the cluster has MOTD
	// banner text that must be retrieved, displayed and acknowledged by
	// the user.
	HasMessageOfTheDay bool `protobuf:"varint,5,opt,name=has_message_of_the_day,json=hasMessageOfTheDay,proto3" json:"has_message_of_the_day,omitempty"`
	// auth_type is the authentication type e.g. "local", "github", "saml", "oidc"
	AuthType string `protobuf:"bytes,6,opt,name=auth_type,json=authType,proto3" json:"auth_type,omitempty"`
	// allow_passwordless is true if passwordless logins are allowed.
	AllowPasswordless bool `protobuf:"varint,7,opt,name=allow_passwordless,json=allowPasswordless,proto3" json:"allow_passwordless,omitempty"`
	// local_connector_name is the name of the local connector.
	LocalConnectorName string `protobuf:"bytes,8,opt,name=local_connector_name,json=localConnectorName,proto3" json:"local_connector_name,omitempty"`
}

func (x *AuthSettings) Reset() {
	*x = AuthSettings{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_lib_teleterm_v1_auth_settings_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthSettings) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthSettings) ProtoMessage() {}

func (x *AuthSettings) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_lib_teleterm_v1_auth_settings_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthSettings.ProtoReflect.Descriptor instead.
func (*AuthSettings) Descriptor() ([]byte, []int) {
	return file_teleport_lib_teleterm_v1_auth_settings_proto_rawDescGZIP(), []int{0}
}

func (x *AuthSettings) GetLocalAuthEnabled() bool {
	if x != nil {
		return x.LocalAuthEnabled
	}
	return false
}

func (x *AuthSettings) GetSecondFactor() string {
	if x != nil {
		return x.SecondFactor
	}
	return ""
}

func (x *AuthSettings) GetPreferredMfa() string {
	if x != nil {
		return x.PreferredMfa
	}
	return ""
}

func (x *AuthSettings) GetAuthProviders() []*AuthProvider {
	if x != nil {
		return x.AuthProviders
	}
	return nil
}

func (x *AuthSettings) GetHasMessageOfTheDay() bool {
	if x != nil {
		return x.HasMessageOfTheDay
	}
	return false
}

func (x *AuthSettings) GetAuthType() string {
	if x != nil {
		return x.AuthType
	}
	return ""
}

func (x *AuthSettings) GetAllowPasswordless() bool {
	if x != nil {
		return x.AllowPasswordless
	}
	return false
}

func (x *AuthSettings) GetLocalConnectorName() string {
	if x != nil {
		return x.LocalConnectorName
	}
	return ""
}

// AuthProvider describes a way of authentication that is supported by the server. Auth provider is
// referred to as "auth connector" on the backend.
type AuthProvider struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Type is the auth provider type (github|oidc|etc)
	Type string `protobuf:"bytes,1,opt,name=type,proto3" json:"type,omitempty"`
	// Name is the internal name of the connector.
	Name string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	// Display is the display name for the connector.
	DisplayName string `protobuf:"bytes,3,opt,name=display_name,json=displayName,proto3" json:"display_name,omitempty"`
}

func (x *AuthProvider) Reset() {
	*x = AuthProvider{}
	if protoimpl.UnsafeEnabled {
		mi := &file_teleport_lib_teleterm_v1_auth_settings_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AuthProvider) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthProvider) ProtoMessage() {}

func (x *AuthProvider) ProtoReflect() protoreflect.Message {
	mi := &file_teleport_lib_teleterm_v1_auth_settings_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthProvider.ProtoReflect.Descriptor instead.
func (*AuthProvider) Descriptor() ([]byte, []int) {
	return file_teleport_lib_teleterm_v1_auth_settings_proto_rawDescGZIP(), []int{1}
}

func (x *AuthProvider) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *AuthProvider) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *AuthProvider) GetDisplayName() string {
	if x != nil {
		return x.DisplayName
	}
	return ""
}

var File_teleport_lib_teleterm_v1_auth_settings_proto protoreflect.FileDescriptor

var file_teleport_lib_teleterm_v1_auth_settings_proto_rawDesc = []byte{
	0x0a, 0x2c, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x6c, 0x69, 0x62, 0x2f, 0x74,
	0x65, 0x6c, 0x65, 0x74, 0x65, 0x72, 0x6d, 0x2f, 0x76, 0x31, 0x2f, 0x61, 0x75, 0x74, 0x68, 0x5f,
	0x73, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x18,
	0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c, 0x69, 0x62, 0x2e, 0x74, 0x65, 0x6c,
	0x65, 0x74, 0x65, 0x72, 0x6d, 0x2e, 0x76, 0x31, 0x22, 0x87, 0x03, 0x0a, 0x0c, 0x41, 0x75, 0x74,
	0x68, 0x53, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x73, 0x12, 0x2c, 0x0a, 0x12, 0x6c, 0x6f, 0x63,
	0x61, 0x6c, 0x5f, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x10, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x41, 0x75, 0x74, 0x68,
	0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x12, 0x23, 0x0a, 0x0d, 0x73, 0x65, 0x63, 0x6f, 0x6e,
	0x64, 0x5f, 0x66, 0x61, 0x63, 0x74, 0x6f, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c,
	0x73, 0x65, 0x63, 0x6f, 0x6e, 0x64, 0x46, 0x61, 0x63, 0x74, 0x6f, 0x72, 0x12, 0x23, 0x0a, 0x0d,
	0x70, 0x72, 0x65, 0x66, 0x65, 0x72, 0x72, 0x65, 0x64, 0x5f, 0x6d, 0x66, 0x61, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0c, 0x70, 0x72, 0x65, 0x66, 0x65, 0x72, 0x72, 0x65, 0x64, 0x4d, 0x66,
	0x61, 0x12, 0x4d, 0x0a, 0x0e, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64,
	0x65, 0x72, 0x73, 0x18, 0x04, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x26, 0x2e, 0x74, 0x65, 0x6c, 0x65,
	0x70, 0x6f, 0x72, 0x74, 0x2e, 0x6c, 0x69, 0x62, 0x2e, 0x74, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x72,
	0x6d, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65,
	0x72, 0x52, 0x0d, 0x61, 0x75, 0x74, 0x68, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x73,
	0x12, 0x32, 0x0a, 0x16, 0x68, 0x61, 0x73, 0x5f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x5f,
	0x6f, 0x66, 0x5f, 0x74, 0x68, 0x65, 0x5f, 0x64, 0x61, 0x79, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08,
	0x52, 0x12, 0x68, 0x61, 0x73, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x4f, 0x66, 0x54, 0x68,
	0x65, 0x44, 0x61, 0x79, 0x12, 0x1b, 0x0a, 0x09, 0x61, 0x75, 0x74, 0x68, 0x5f, 0x74, 0x79, 0x70,
	0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x61, 0x75, 0x74, 0x68, 0x54, 0x79, 0x70,
	0x65, 0x12, 0x2d, 0x0a, 0x12, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77,
	0x6f, 0x72, 0x64, 0x6c, 0x65, 0x73, 0x73, 0x18, 0x07, 0x20, 0x01, 0x28, 0x08, 0x52, 0x11, 0x61,
	0x6c, 0x6c, 0x6f, 0x77, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x6c, 0x65, 0x73, 0x73,
	0x12, 0x30, 0x0a, 0x14, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63,
	0x74, 0x6f, 0x72, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x12,
	0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x4e, 0x61,
	0x6d, 0x65, 0x22, 0x59, 0x0a, 0x0c, 0x41, 0x75, 0x74, 0x68, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64,
	0x65, 0x72, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x21, 0x0a, 0x0c, 0x64, 0x69,
	0x73, 0x70, 0x6c, 0x61, 0x79, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x0b, 0x64, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x42, 0x54, 0x5a,
	0x52, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x72, 0x61, 0x76,
	0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f,
	0x72, 0x74, 0x2f, 0x67, 0x65, 0x6e, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x67, 0x6f, 0x2f,
	0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x6c, 0x69, 0x62, 0x2f, 0x74, 0x65, 0x6c,
	0x65, 0x74, 0x65, 0x72, 0x6d, 0x2f, 0x76, 0x31, 0x3b, 0x74, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x72,
	0x6d, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_teleport_lib_teleterm_v1_auth_settings_proto_rawDescOnce sync.Once
	file_teleport_lib_teleterm_v1_auth_settings_proto_rawDescData = file_teleport_lib_teleterm_v1_auth_settings_proto_rawDesc
)

func file_teleport_lib_teleterm_v1_auth_settings_proto_rawDescGZIP() []byte {
	file_teleport_lib_teleterm_v1_auth_settings_proto_rawDescOnce.Do(func() {
		file_teleport_lib_teleterm_v1_auth_settings_proto_rawDescData = protoimpl.X.CompressGZIP(file_teleport_lib_teleterm_v1_auth_settings_proto_rawDescData)
	})
	return file_teleport_lib_teleterm_v1_auth_settings_proto_rawDescData
}

var file_teleport_lib_teleterm_v1_auth_settings_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_teleport_lib_teleterm_v1_auth_settings_proto_goTypes = []interface{}{
	(*AuthSettings)(nil), // 0: teleport.lib.teleterm.v1.AuthSettings
	(*AuthProvider)(nil), // 1: teleport.lib.teleterm.v1.AuthProvider
}
var file_teleport_lib_teleterm_v1_auth_settings_proto_depIdxs = []int32{
	1, // 0: teleport.lib.teleterm.v1.AuthSettings.auth_providers:type_name -> teleport.lib.teleterm.v1.AuthProvider
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_teleport_lib_teleterm_v1_auth_settings_proto_init() }
func file_teleport_lib_teleterm_v1_auth_settings_proto_init() {
	if File_teleport_lib_teleterm_v1_auth_settings_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_teleport_lib_teleterm_v1_auth_settings_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuthSettings); i {
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
		file_teleport_lib_teleterm_v1_auth_settings_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AuthProvider); i {
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
			RawDescriptor: file_teleport_lib_teleterm_v1_auth_settings_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_teleport_lib_teleterm_v1_auth_settings_proto_goTypes,
		DependencyIndexes: file_teleport_lib_teleterm_v1_auth_settings_proto_depIdxs,
		MessageInfos:      file_teleport_lib_teleterm_v1_auth_settings_proto_msgTypes,
	}.Build()
	File_teleport_lib_teleterm_v1_auth_settings_proto = out.File
	file_teleport_lib_teleterm_v1_auth_settings_proto_rawDesc = nil
	file_teleport_lib_teleterm_v1_auth_settings_proto_goTypes = nil
	file_teleport_lib_teleterm_v1_auth_settings_proto_depIdxs = nil
}
