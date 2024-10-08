// Copyright 2024 Gravitational, Inc.
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
// - protoc-gen-go-grpc v1.5.1
// - protoc             (unknown)
// source: teleport/autoupdate/v1/autoupdate_service.proto

package autoupdate

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	AutoUpdateService_GetAutoUpdateConfig_FullMethodName       = "/teleport.autoupdate.v1.AutoUpdateService/GetAutoUpdateConfig"
	AutoUpdateService_CreateAutoUpdateConfig_FullMethodName    = "/teleport.autoupdate.v1.AutoUpdateService/CreateAutoUpdateConfig"
	AutoUpdateService_UpdateAutoUpdateConfig_FullMethodName    = "/teleport.autoupdate.v1.AutoUpdateService/UpdateAutoUpdateConfig"
	AutoUpdateService_UpsertAutoUpdateConfig_FullMethodName    = "/teleport.autoupdate.v1.AutoUpdateService/UpsertAutoUpdateConfig"
	AutoUpdateService_DeleteAutoUpdateConfig_FullMethodName    = "/teleport.autoupdate.v1.AutoUpdateService/DeleteAutoUpdateConfig"
	AutoUpdateService_GetAutoUpdateVersion_FullMethodName      = "/teleport.autoupdate.v1.AutoUpdateService/GetAutoUpdateVersion"
	AutoUpdateService_CreateAutoUpdateVersion_FullMethodName   = "/teleport.autoupdate.v1.AutoUpdateService/CreateAutoUpdateVersion"
	AutoUpdateService_UpdateAutoUpdateVersion_FullMethodName   = "/teleport.autoupdate.v1.AutoUpdateService/UpdateAutoUpdateVersion"
	AutoUpdateService_UpsertAutoUpdateVersion_FullMethodName   = "/teleport.autoupdate.v1.AutoUpdateService/UpsertAutoUpdateVersion"
	AutoUpdateService_DeleteAutoUpdateVersion_FullMethodName   = "/teleport.autoupdate.v1.AutoUpdateService/DeleteAutoUpdateVersion"
	AutoUpdateService_GetAutoUpdateAgentPlan_FullMethodName    = "/teleport.autoupdate.v1.AutoUpdateService/GetAutoUpdateAgentPlan"
	AutoUpdateService_CreateAutoUpdateAgentPlan_FullMethodName = "/teleport.autoupdate.v1.AutoUpdateService/CreateAutoUpdateAgentPlan"
	AutoUpdateService_UpdateAutoUpdateAgentPlan_FullMethodName = "/teleport.autoupdate.v1.AutoUpdateService/UpdateAutoUpdateAgentPlan"
	AutoUpdateService_UpsertAutoUpdateAgentPlan_FullMethodName = "/teleport.autoupdate.v1.AutoUpdateService/UpsertAutoUpdateAgentPlan"
	AutoUpdateService_DeleteAutoUpdateAgentPlan_FullMethodName = "/teleport.autoupdate.v1.AutoUpdateService/DeleteAutoUpdateAgentPlan"
)

// AutoUpdateServiceClient is the client API for AutoUpdateService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
//
// AutoUpdateService provides an API to manage autoupdates.
type AutoUpdateServiceClient interface {
	// GetAutoUpdateConfig gets the current autoupdate config singleton.
	GetAutoUpdateConfig(ctx context.Context, in *GetAutoUpdateConfigRequest, opts ...grpc.CallOption) (*AutoUpdateConfig, error)
	// CreateAutoUpdateConfig creates a new AutoUpdateConfig.
	CreateAutoUpdateConfig(ctx context.Context, in *CreateAutoUpdateConfigRequest, opts ...grpc.CallOption) (*AutoUpdateConfig, error)
	// CreateAutoUpdateConfig updates AutoUpdateConfig singleton.
	UpdateAutoUpdateConfig(ctx context.Context, in *UpdateAutoUpdateConfigRequest, opts ...grpc.CallOption) (*AutoUpdateConfig, error)
	// UpsertAutoUpdateConfig creates a new AutoUpdateConfig or replaces an existing AutoUpdateConfig.
	UpsertAutoUpdateConfig(ctx context.Context, in *UpsertAutoUpdateConfigRequest, opts ...grpc.CallOption) (*AutoUpdateConfig, error)
	// DeleteAutoUpdateConfig hard deletes the specified AutoUpdateConfig.
	DeleteAutoUpdateConfig(ctx context.Context, in *DeleteAutoUpdateConfigRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	// GetAutoUpdateVersion gets the current autoupdate version singleton.
	GetAutoUpdateVersion(ctx context.Context, in *GetAutoUpdateVersionRequest, opts ...grpc.CallOption) (*AutoUpdateVersion, error)
	// CreateAutoUpdateVersion creates a new AutoUpdateVersion.
	CreateAutoUpdateVersion(ctx context.Context, in *CreateAutoUpdateVersionRequest, opts ...grpc.CallOption) (*AutoUpdateVersion, error)
	// UpdateAutoUpdateVersion updates AutoUpdateVersion singleton.
	UpdateAutoUpdateVersion(ctx context.Context, in *UpdateAutoUpdateVersionRequest, opts ...grpc.CallOption) (*AutoUpdateVersion, error)
	// UpsertAutoUpdateVersion creates a new AutoUpdateVersion or replaces an existing AutoUpdateVersion.
	UpsertAutoUpdateVersion(ctx context.Context, in *UpsertAutoUpdateVersionRequest, opts ...grpc.CallOption) (*AutoUpdateVersion, error)
	// DeleteAutoUpdateVersion hard deletes the specified AutoUpdateVersionRequest.
	DeleteAutoUpdateVersion(ctx context.Context, in *DeleteAutoUpdateVersionRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	// GetAutoUpdateAgentPlan gets the current autoupdate version singleton.
	GetAutoUpdateAgentPlan(ctx context.Context, in *GetAutoUpdateAgentPlanRequest, opts ...grpc.CallOption) (*AutoUpdateAgentPlan, error)
	// CreateAutoUpdateAgentPlan creates a new AutoUpdateAgentPlan.
	CreateAutoUpdateAgentPlan(ctx context.Context, in *CreateAutoUpdateAgentPlanRequest, opts ...grpc.CallOption) (*AutoUpdateAgentPlan, error)
	// UpdateAutoUpdateAgentPlan updates AutoUpdateAgentPlan singleton.
	UpdateAutoUpdateAgentPlan(ctx context.Context, in *UpdateAutoUpdateAgentPlanRequest, opts ...grpc.CallOption) (*AutoUpdateAgentPlan, error)
	// UpsertAutoUpdateAgentPlan creates a new AutoUpdateAgentPlan or replaces an existing AutoUpdateAgentPlan.
	UpsertAutoUpdateAgentPlan(ctx context.Context, in *UpsertAutoUpdateAgentPlanRequest, opts ...grpc.CallOption) (*AutoUpdateAgentPlan, error)
	// DeleteAutoUpdateAgentPlan hard deletes the specified AutoUpdateAgentPlanRequest.
	DeleteAutoUpdateAgentPlan(ctx context.Context, in *DeleteAutoUpdateAgentPlanRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type autoUpdateServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewAutoUpdateServiceClient(cc grpc.ClientConnInterface) AutoUpdateServiceClient {
	return &autoUpdateServiceClient{cc}
}

func (c *autoUpdateServiceClient) GetAutoUpdateConfig(ctx context.Context, in *GetAutoUpdateConfigRequest, opts ...grpc.CallOption) (*AutoUpdateConfig, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AutoUpdateConfig)
	err := c.cc.Invoke(ctx, AutoUpdateService_GetAutoUpdateConfig_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autoUpdateServiceClient) CreateAutoUpdateConfig(ctx context.Context, in *CreateAutoUpdateConfigRequest, opts ...grpc.CallOption) (*AutoUpdateConfig, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AutoUpdateConfig)
	err := c.cc.Invoke(ctx, AutoUpdateService_CreateAutoUpdateConfig_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autoUpdateServiceClient) UpdateAutoUpdateConfig(ctx context.Context, in *UpdateAutoUpdateConfigRequest, opts ...grpc.CallOption) (*AutoUpdateConfig, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AutoUpdateConfig)
	err := c.cc.Invoke(ctx, AutoUpdateService_UpdateAutoUpdateConfig_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autoUpdateServiceClient) UpsertAutoUpdateConfig(ctx context.Context, in *UpsertAutoUpdateConfigRequest, opts ...grpc.CallOption) (*AutoUpdateConfig, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AutoUpdateConfig)
	err := c.cc.Invoke(ctx, AutoUpdateService_UpsertAutoUpdateConfig_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autoUpdateServiceClient) DeleteAutoUpdateConfig(ctx context.Context, in *DeleteAutoUpdateConfigRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, AutoUpdateService_DeleteAutoUpdateConfig_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autoUpdateServiceClient) GetAutoUpdateVersion(ctx context.Context, in *GetAutoUpdateVersionRequest, opts ...grpc.CallOption) (*AutoUpdateVersion, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AutoUpdateVersion)
	err := c.cc.Invoke(ctx, AutoUpdateService_GetAutoUpdateVersion_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autoUpdateServiceClient) CreateAutoUpdateVersion(ctx context.Context, in *CreateAutoUpdateVersionRequest, opts ...grpc.CallOption) (*AutoUpdateVersion, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AutoUpdateVersion)
	err := c.cc.Invoke(ctx, AutoUpdateService_CreateAutoUpdateVersion_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autoUpdateServiceClient) UpdateAutoUpdateVersion(ctx context.Context, in *UpdateAutoUpdateVersionRequest, opts ...grpc.CallOption) (*AutoUpdateVersion, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AutoUpdateVersion)
	err := c.cc.Invoke(ctx, AutoUpdateService_UpdateAutoUpdateVersion_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autoUpdateServiceClient) UpsertAutoUpdateVersion(ctx context.Context, in *UpsertAutoUpdateVersionRequest, opts ...grpc.CallOption) (*AutoUpdateVersion, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AutoUpdateVersion)
	err := c.cc.Invoke(ctx, AutoUpdateService_UpsertAutoUpdateVersion_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autoUpdateServiceClient) DeleteAutoUpdateVersion(ctx context.Context, in *DeleteAutoUpdateVersionRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, AutoUpdateService_DeleteAutoUpdateVersion_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autoUpdateServiceClient) GetAutoUpdateAgentPlan(ctx context.Context, in *GetAutoUpdateAgentPlanRequest, opts ...grpc.CallOption) (*AutoUpdateAgentPlan, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AutoUpdateAgentPlan)
	err := c.cc.Invoke(ctx, AutoUpdateService_GetAutoUpdateAgentPlan_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autoUpdateServiceClient) CreateAutoUpdateAgentPlan(ctx context.Context, in *CreateAutoUpdateAgentPlanRequest, opts ...grpc.CallOption) (*AutoUpdateAgentPlan, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AutoUpdateAgentPlan)
	err := c.cc.Invoke(ctx, AutoUpdateService_CreateAutoUpdateAgentPlan_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autoUpdateServiceClient) UpdateAutoUpdateAgentPlan(ctx context.Context, in *UpdateAutoUpdateAgentPlanRequest, opts ...grpc.CallOption) (*AutoUpdateAgentPlan, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AutoUpdateAgentPlan)
	err := c.cc.Invoke(ctx, AutoUpdateService_UpdateAutoUpdateAgentPlan_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autoUpdateServiceClient) UpsertAutoUpdateAgentPlan(ctx context.Context, in *UpsertAutoUpdateAgentPlanRequest, opts ...grpc.CallOption) (*AutoUpdateAgentPlan, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(AutoUpdateAgentPlan)
	err := c.cc.Invoke(ctx, AutoUpdateService_UpsertAutoUpdateAgentPlan_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *autoUpdateServiceClient) DeleteAutoUpdateAgentPlan(ctx context.Context, in *DeleteAutoUpdateAgentPlanRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, AutoUpdateService_DeleteAutoUpdateAgentPlan_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AutoUpdateServiceServer is the server API for AutoUpdateService service.
// All implementations must embed UnimplementedAutoUpdateServiceServer
// for forward compatibility.
//
// AutoUpdateService provides an API to manage autoupdates.
type AutoUpdateServiceServer interface {
	// GetAutoUpdateConfig gets the current autoupdate config singleton.
	GetAutoUpdateConfig(context.Context, *GetAutoUpdateConfigRequest) (*AutoUpdateConfig, error)
	// CreateAutoUpdateConfig creates a new AutoUpdateConfig.
	CreateAutoUpdateConfig(context.Context, *CreateAutoUpdateConfigRequest) (*AutoUpdateConfig, error)
	// CreateAutoUpdateConfig updates AutoUpdateConfig singleton.
	UpdateAutoUpdateConfig(context.Context, *UpdateAutoUpdateConfigRequest) (*AutoUpdateConfig, error)
	// UpsertAutoUpdateConfig creates a new AutoUpdateConfig or replaces an existing AutoUpdateConfig.
	UpsertAutoUpdateConfig(context.Context, *UpsertAutoUpdateConfigRequest) (*AutoUpdateConfig, error)
	// DeleteAutoUpdateConfig hard deletes the specified AutoUpdateConfig.
	DeleteAutoUpdateConfig(context.Context, *DeleteAutoUpdateConfigRequest) (*emptypb.Empty, error)
	// GetAutoUpdateVersion gets the current autoupdate version singleton.
	GetAutoUpdateVersion(context.Context, *GetAutoUpdateVersionRequest) (*AutoUpdateVersion, error)
	// CreateAutoUpdateVersion creates a new AutoUpdateVersion.
	CreateAutoUpdateVersion(context.Context, *CreateAutoUpdateVersionRequest) (*AutoUpdateVersion, error)
	// UpdateAutoUpdateVersion updates AutoUpdateVersion singleton.
	UpdateAutoUpdateVersion(context.Context, *UpdateAutoUpdateVersionRequest) (*AutoUpdateVersion, error)
	// UpsertAutoUpdateVersion creates a new AutoUpdateVersion or replaces an existing AutoUpdateVersion.
	UpsertAutoUpdateVersion(context.Context, *UpsertAutoUpdateVersionRequest) (*AutoUpdateVersion, error)
	// DeleteAutoUpdateVersion hard deletes the specified AutoUpdateVersionRequest.
	DeleteAutoUpdateVersion(context.Context, *DeleteAutoUpdateVersionRequest) (*emptypb.Empty, error)
	// GetAutoUpdateAgentPlan gets the current autoupdate version singleton.
	GetAutoUpdateAgentPlan(context.Context, *GetAutoUpdateAgentPlanRequest) (*AutoUpdateAgentPlan, error)
	// CreateAutoUpdateAgentPlan creates a new AutoUpdateAgentPlan.
	CreateAutoUpdateAgentPlan(context.Context, *CreateAutoUpdateAgentPlanRequest) (*AutoUpdateAgentPlan, error)
	// UpdateAutoUpdateAgentPlan updates AutoUpdateAgentPlan singleton.
	UpdateAutoUpdateAgentPlan(context.Context, *UpdateAutoUpdateAgentPlanRequest) (*AutoUpdateAgentPlan, error)
	// UpsertAutoUpdateAgentPlan creates a new AutoUpdateAgentPlan or replaces an existing AutoUpdateAgentPlan.
	UpsertAutoUpdateAgentPlan(context.Context, *UpsertAutoUpdateAgentPlanRequest) (*AutoUpdateAgentPlan, error)
	// DeleteAutoUpdateAgentPlan hard deletes the specified AutoUpdateAgentPlanRequest.
	DeleteAutoUpdateAgentPlan(context.Context, *DeleteAutoUpdateAgentPlanRequest) (*emptypb.Empty, error)
	mustEmbedUnimplementedAutoUpdateServiceServer()
}

// UnimplementedAutoUpdateServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedAutoUpdateServiceServer struct{}

func (UnimplementedAutoUpdateServiceServer) GetAutoUpdateConfig(context.Context, *GetAutoUpdateConfigRequest) (*AutoUpdateConfig, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAutoUpdateConfig not implemented")
}
func (UnimplementedAutoUpdateServiceServer) CreateAutoUpdateConfig(context.Context, *CreateAutoUpdateConfigRequest) (*AutoUpdateConfig, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateAutoUpdateConfig not implemented")
}
func (UnimplementedAutoUpdateServiceServer) UpdateAutoUpdateConfig(context.Context, *UpdateAutoUpdateConfigRequest) (*AutoUpdateConfig, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateAutoUpdateConfig not implemented")
}
func (UnimplementedAutoUpdateServiceServer) UpsertAutoUpdateConfig(context.Context, *UpsertAutoUpdateConfigRequest) (*AutoUpdateConfig, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertAutoUpdateConfig not implemented")
}
func (UnimplementedAutoUpdateServiceServer) DeleteAutoUpdateConfig(context.Context, *DeleteAutoUpdateConfigRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteAutoUpdateConfig not implemented")
}
func (UnimplementedAutoUpdateServiceServer) GetAutoUpdateVersion(context.Context, *GetAutoUpdateVersionRequest) (*AutoUpdateVersion, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAutoUpdateVersion not implemented")
}
func (UnimplementedAutoUpdateServiceServer) CreateAutoUpdateVersion(context.Context, *CreateAutoUpdateVersionRequest) (*AutoUpdateVersion, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateAutoUpdateVersion not implemented")
}
func (UnimplementedAutoUpdateServiceServer) UpdateAutoUpdateVersion(context.Context, *UpdateAutoUpdateVersionRequest) (*AutoUpdateVersion, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateAutoUpdateVersion not implemented")
}
func (UnimplementedAutoUpdateServiceServer) UpsertAutoUpdateVersion(context.Context, *UpsertAutoUpdateVersionRequest) (*AutoUpdateVersion, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertAutoUpdateVersion not implemented")
}
func (UnimplementedAutoUpdateServiceServer) DeleteAutoUpdateVersion(context.Context, *DeleteAutoUpdateVersionRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteAutoUpdateVersion not implemented")
}
func (UnimplementedAutoUpdateServiceServer) GetAutoUpdateAgentPlan(context.Context, *GetAutoUpdateAgentPlanRequest) (*AutoUpdateAgentPlan, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetAutoUpdateAgentPlan not implemented")
}
func (UnimplementedAutoUpdateServiceServer) CreateAutoUpdateAgentPlan(context.Context, *CreateAutoUpdateAgentPlanRequest) (*AutoUpdateAgentPlan, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateAutoUpdateAgentPlan not implemented")
}
func (UnimplementedAutoUpdateServiceServer) UpdateAutoUpdateAgentPlan(context.Context, *UpdateAutoUpdateAgentPlanRequest) (*AutoUpdateAgentPlan, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateAutoUpdateAgentPlan not implemented")
}
func (UnimplementedAutoUpdateServiceServer) UpsertAutoUpdateAgentPlan(context.Context, *UpsertAutoUpdateAgentPlanRequest) (*AutoUpdateAgentPlan, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertAutoUpdateAgentPlan not implemented")
}
func (UnimplementedAutoUpdateServiceServer) DeleteAutoUpdateAgentPlan(context.Context, *DeleteAutoUpdateAgentPlanRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteAutoUpdateAgentPlan not implemented")
}
func (UnimplementedAutoUpdateServiceServer) mustEmbedUnimplementedAutoUpdateServiceServer() {}
func (UnimplementedAutoUpdateServiceServer) testEmbeddedByValue()                           {}

// UnsafeAutoUpdateServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AutoUpdateServiceServer will
// result in compilation errors.
type UnsafeAutoUpdateServiceServer interface {
	mustEmbedUnimplementedAutoUpdateServiceServer()
}

func RegisterAutoUpdateServiceServer(s grpc.ServiceRegistrar, srv AutoUpdateServiceServer) {
	// If the following call pancis, it indicates UnimplementedAutoUpdateServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&AutoUpdateService_ServiceDesc, srv)
}

func _AutoUpdateService_GetAutoUpdateConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAutoUpdateConfigRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutoUpdateServiceServer).GetAutoUpdateConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AutoUpdateService_GetAutoUpdateConfig_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutoUpdateServiceServer).GetAutoUpdateConfig(ctx, req.(*GetAutoUpdateConfigRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AutoUpdateService_CreateAutoUpdateConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateAutoUpdateConfigRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutoUpdateServiceServer).CreateAutoUpdateConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AutoUpdateService_CreateAutoUpdateConfig_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutoUpdateServiceServer).CreateAutoUpdateConfig(ctx, req.(*CreateAutoUpdateConfigRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AutoUpdateService_UpdateAutoUpdateConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateAutoUpdateConfigRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutoUpdateServiceServer).UpdateAutoUpdateConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AutoUpdateService_UpdateAutoUpdateConfig_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutoUpdateServiceServer).UpdateAutoUpdateConfig(ctx, req.(*UpdateAutoUpdateConfigRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AutoUpdateService_UpsertAutoUpdateConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpsertAutoUpdateConfigRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutoUpdateServiceServer).UpsertAutoUpdateConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AutoUpdateService_UpsertAutoUpdateConfig_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutoUpdateServiceServer).UpsertAutoUpdateConfig(ctx, req.(*UpsertAutoUpdateConfigRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AutoUpdateService_DeleteAutoUpdateConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteAutoUpdateConfigRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutoUpdateServiceServer).DeleteAutoUpdateConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AutoUpdateService_DeleteAutoUpdateConfig_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutoUpdateServiceServer).DeleteAutoUpdateConfig(ctx, req.(*DeleteAutoUpdateConfigRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AutoUpdateService_GetAutoUpdateVersion_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAutoUpdateVersionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutoUpdateServiceServer).GetAutoUpdateVersion(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AutoUpdateService_GetAutoUpdateVersion_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutoUpdateServiceServer).GetAutoUpdateVersion(ctx, req.(*GetAutoUpdateVersionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AutoUpdateService_CreateAutoUpdateVersion_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateAutoUpdateVersionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutoUpdateServiceServer).CreateAutoUpdateVersion(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AutoUpdateService_CreateAutoUpdateVersion_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutoUpdateServiceServer).CreateAutoUpdateVersion(ctx, req.(*CreateAutoUpdateVersionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AutoUpdateService_UpdateAutoUpdateVersion_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateAutoUpdateVersionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutoUpdateServiceServer).UpdateAutoUpdateVersion(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AutoUpdateService_UpdateAutoUpdateVersion_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutoUpdateServiceServer).UpdateAutoUpdateVersion(ctx, req.(*UpdateAutoUpdateVersionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AutoUpdateService_UpsertAutoUpdateVersion_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpsertAutoUpdateVersionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutoUpdateServiceServer).UpsertAutoUpdateVersion(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AutoUpdateService_UpsertAutoUpdateVersion_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutoUpdateServiceServer).UpsertAutoUpdateVersion(ctx, req.(*UpsertAutoUpdateVersionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AutoUpdateService_DeleteAutoUpdateVersion_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteAutoUpdateVersionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutoUpdateServiceServer).DeleteAutoUpdateVersion(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AutoUpdateService_DeleteAutoUpdateVersion_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutoUpdateServiceServer).DeleteAutoUpdateVersion(ctx, req.(*DeleteAutoUpdateVersionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AutoUpdateService_GetAutoUpdateAgentPlan_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetAutoUpdateAgentPlanRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutoUpdateServiceServer).GetAutoUpdateAgentPlan(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AutoUpdateService_GetAutoUpdateAgentPlan_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutoUpdateServiceServer).GetAutoUpdateAgentPlan(ctx, req.(*GetAutoUpdateAgentPlanRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AutoUpdateService_CreateAutoUpdateAgentPlan_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateAutoUpdateAgentPlanRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutoUpdateServiceServer).CreateAutoUpdateAgentPlan(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AutoUpdateService_CreateAutoUpdateAgentPlan_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutoUpdateServiceServer).CreateAutoUpdateAgentPlan(ctx, req.(*CreateAutoUpdateAgentPlanRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AutoUpdateService_UpdateAutoUpdateAgentPlan_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateAutoUpdateAgentPlanRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutoUpdateServiceServer).UpdateAutoUpdateAgentPlan(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AutoUpdateService_UpdateAutoUpdateAgentPlan_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutoUpdateServiceServer).UpdateAutoUpdateAgentPlan(ctx, req.(*UpdateAutoUpdateAgentPlanRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AutoUpdateService_UpsertAutoUpdateAgentPlan_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpsertAutoUpdateAgentPlanRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutoUpdateServiceServer).UpsertAutoUpdateAgentPlan(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AutoUpdateService_UpsertAutoUpdateAgentPlan_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutoUpdateServiceServer).UpsertAutoUpdateAgentPlan(ctx, req.(*UpsertAutoUpdateAgentPlanRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AutoUpdateService_DeleteAutoUpdateAgentPlan_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteAutoUpdateAgentPlanRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AutoUpdateServiceServer).DeleteAutoUpdateAgentPlan(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: AutoUpdateService_DeleteAutoUpdateAgentPlan_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AutoUpdateServiceServer).DeleteAutoUpdateAgentPlan(ctx, req.(*DeleteAutoUpdateAgentPlanRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// AutoUpdateService_ServiceDesc is the grpc.ServiceDesc for AutoUpdateService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var AutoUpdateService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "teleport.autoupdate.v1.AutoUpdateService",
	HandlerType: (*AutoUpdateServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetAutoUpdateConfig",
			Handler:    _AutoUpdateService_GetAutoUpdateConfig_Handler,
		},
		{
			MethodName: "CreateAutoUpdateConfig",
			Handler:    _AutoUpdateService_CreateAutoUpdateConfig_Handler,
		},
		{
			MethodName: "UpdateAutoUpdateConfig",
			Handler:    _AutoUpdateService_UpdateAutoUpdateConfig_Handler,
		},
		{
			MethodName: "UpsertAutoUpdateConfig",
			Handler:    _AutoUpdateService_UpsertAutoUpdateConfig_Handler,
		},
		{
			MethodName: "DeleteAutoUpdateConfig",
			Handler:    _AutoUpdateService_DeleteAutoUpdateConfig_Handler,
		},
		{
			MethodName: "GetAutoUpdateVersion",
			Handler:    _AutoUpdateService_GetAutoUpdateVersion_Handler,
		},
		{
			MethodName: "CreateAutoUpdateVersion",
			Handler:    _AutoUpdateService_CreateAutoUpdateVersion_Handler,
		},
		{
			MethodName: "UpdateAutoUpdateVersion",
			Handler:    _AutoUpdateService_UpdateAutoUpdateVersion_Handler,
		},
		{
			MethodName: "UpsertAutoUpdateVersion",
			Handler:    _AutoUpdateService_UpsertAutoUpdateVersion_Handler,
		},
		{
			MethodName: "DeleteAutoUpdateVersion",
			Handler:    _AutoUpdateService_DeleteAutoUpdateVersion_Handler,
		},
		{
			MethodName: "GetAutoUpdateAgentPlan",
			Handler:    _AutoUpdateService_GetAutoUpdateAgentPlan_Handler,
		},
		{
			MethodName: "CreateAutoUpdateAgentPlan",
			Handler:    _AutoUpdateService_CreateAutoUpdateAgentPlan_Handler,
		},
		{
			MethodName: "UpdateAutoUpdateAgentPlan",
			Handler:    _AutoUpdateService_UpdateAutoUpdateAgentPlan_Handler,
		},
		{
			MethodName: "UpsertAutoUpdateAgentPlan",
			Handler:    _AutoUpdateService_UpsertAutoUpdateAgentPlan_Handler,
		},
		{
			MethodName: "DeleteAutoUpdateAgentPlan",
			Handler:    _AutoUpdateService_DeleteAutoUpdateAgentPlan_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "teleport/autoupdate/v1/autoupdate_service.proto",
}
