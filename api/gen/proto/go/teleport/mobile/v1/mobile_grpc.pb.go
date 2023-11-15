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

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             (unknown)
// source: teleport/mobile/v1/mobile.proto

package mobilev1

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	MobileService_CreateAuthToken_FullMethodName             = "/teleport.mobile.v1.MobileService/CreateAuthToken"
	MobileService_RedeemAuthToken_FullMethodName             = "/teleport.mobile.v1.MobileService/RedeemAuthToken"
	MobileService_RegisterDeviceNotifications_FullMethodName = "/teleport.mobile.v1.MobileService/RegisterDeviceNotifications"
)

// MobileServiceClient is the client API for MobileService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type MobileServiceClient interface {
	// CreateAuthToken
	CreateAuthToken(ctx context.Context, in *CreateAuthTokenRequest, opts ...grpc.CallOption) (*CreateAuthTokenResponse, error)
	// RedeemAuthToken
	RedeemAuthToken(ctx context.Context, in *RedeemAuthTokenRequest, opts ...grpc.CallOption) (*RedeemAuthTokenResponse, error)
	// RegisterDeviceNotifications
	RegisterDeviceNotifications(ctx context.Context, in *RegisterDeviceNotificationsRequest, opts ...grpc.CallOption) (*RegisterDeviceNotificationsResponse, error)
}

type mobileServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewMobileServiceClient(cc grpc.ClientConnInterface) MobileServiceClient {
	return &mobileServiceClient{cc}
}

func (c *mobileServiceClient) CreateAuthToken(ctx context.Context, in *CreateAuthTokenRequest, opts ...grpc.CallOption) (*CreateAuthTokenResponse, error) {
	out := new(CreateAuthTokenResponse)
	err := c.cc.Invoke(ctx, MobileService_CreateAuthToken_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mobileServiceClient) RedeemAuthToken(ctx context.Context, in *RedeemAuthTokenRequest, opts ...grpc.CallOption) (*RedeemAuthTokenResponse, error) {
	out := new(RedeemAuthTokenResponse)
	err := c.cc.Invoke(ctx, MobileService_RedeemAuthToken_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mobileServiceClient) RegisterDeviceNotifications(ctx context.Context, in *RegisterDeviceNotificationsRequest, opts ...grpc.CallOption) (*RegisterDeviceNotificationsResponse, error) {
	out := new(RegisterDeviceNotificationsResponse)
	err := c.cc.Invoke(ctx, MobileService_RegisterDeviceNotifications_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MobileServiceServer is the server API for MobileService service.
// All implementations must embed UnimplementedMobileServiceServer
// for forward compatibility
type MobileServiceServer interface {
	// CreateAuthToken
	CreateAuthToken(context.Context, *CreateAuthTokenRequest) (*CreateAuthTokenResponse, error)
	// RedeemAuthToken
	RedeemAuthToken(context.Context, *RedeemAuthTokenRequest) (*RedeemAuthTokenResponse, error)
	// RegisterDeviceNotifications
	RegisterDeviceNotifications(context.Context, *RegisterDeviceNotificationsRequest) (*RegisterDeviceNotificationsResponse, error)
	mustEmbedUnimplementedMobileServiceServer()
}

// UnimplementedMobileServiceServer must be embedded to have forward compatible implementations.
type UnimplementedMobileServiceServer struct {
}

func (UnimplementedMobileServiceServer) CreateAuthToken(context.Context, *CreateAuthTokenRequest) (*CreateAuthTokenResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateAuthToken not implemented")
}
func (UnimplementedMobileServiceServer) RedeemAuthToken(context.Context, *RedeemAuthTokenRequest) (*RedeemAuthTokenResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RedeemAuthToken not implemented")
}
func (UnimplementedMobileServiceServer) RegisterDeviceNotifications(context.Context, *RegisterDeviceNotificationsRequest) (*RegisterDeviceNotificationsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RegisterDeviceNotifications not implemented")
}
func (UnimplementedMobileServiceServer) mustEmbedUnimplementedMobileServiceServer() {}

// UnsafeMobileServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to MobileServiceServer will
// result in compilation errors.
type UnsafeMobileServiceServer interface {
	mustEmbedUnimplementedMobileServiceServer()
}

func RegisterMobileServiceServer(s grpc.ServiceRegistrar, srv MobileServiceServer) {
	s.RegisterService(&MobileService_ServiceDesc, srv)
}

func _MobileService_CreateAuthToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateAuthTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MobileServiceServer).CreateAuthToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MobileService_CreateAuthToken_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MobileServiceServer).CreateAuthToken(ctx, req.(*CreateAuthTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MobileService_RedeemAuthToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RedeemAuthTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MobileServiceServer).RedeemAuthToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MobileService_RedeemAuthToken_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MobileServiceServer).RedeemAuthToken(ctx, req.(*RedeemAuthTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MobileService_RegisterDeviceNotifications_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RegisterDeviceNotificationsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MobileServiceServer).RegisterDeviceNotifications(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MobileService_RegisterDeviceNotifications_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MobileServiceServer).RegisterDeviceNotifications(ctx, req.(*RegisterDeviceNotificationsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// MobileService_ServiceDesc is the grpc.ServiceDesc for MobileService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var MobileService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "teleport.mobile.v1.MobileService",
	HandlerType: (*MobileServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateAuthToken",
			Handler:    _MobileService_CreateAuthToken_Handler,
		},
		{
			MethodName: "RedeemAuthToken",
			Handler:    _MobileService_RedeemAuthToken_Handler,
		},
		{
			MethodName: "RegisterDeviceNotifications",
			Handler:    _MobileService_RegisterDeviceNotifications_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "teleport/mobile/v1/mobile.proto",
}
