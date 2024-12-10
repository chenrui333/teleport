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

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             (unknown)
// source: teleport/gitserver/v1/git_server_service.proto

package gitserverv1

import (
	context "context"
	types "github.com/gravitational/teleport/api/types"
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
	GitServerService_CreateGitServer_FullMethodName         = "/teleport.gitserver.v1.GitServerService/CreateGitServer"
	GitServerService_GetGitServer_FullMethodName            = "/teleport.gitserver.v1.GitServerService/GetGitServer"
	GitServerService_ListGitServers_FullMethodName          = "/teleport.gitserver.v1.GitServerService/ListGitServers"
	GitServerService_UpdateGitServer_FullMethodName         = "/teleport.gitserver.v1.GitServerService/UpdateGitServer"
	GitServerService_UpsertGitServer_FullMethodName         = "/teleport.gitserver.v1.GitServerService/UpsertGitServer"
	GitServerService_DeleteGitServer_FullMethodName         = "/teleport.gitserver.v1.GitServerService/DeleteGitServer"
	GitServerService_CreateGitHubAuthRequest_FullMethodName = "/teleport.gitserver.v1.GitServerService/CreateGitHubAuthRequest"
)

// GitServerServiceClient is the client API for GitServerService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
//
// GitServerService provides methods to manage Git server.
type GitServerServiceClient interface {
	// CreateGitServer is used to create a Git server object.
	CreateGitServer(ctx context.Context, in *CreateGitServerRequest, opts ...grpc.CallOption) (*types.ServerV2, error)
	// GetGitServer is used to retrieve a Git server object.
	GetGitServer(ctx context.Context, in *GetGitServerRequest, opts ...grpc.CallOption) (*types.ServerV2, error)
	// ListGitServers is used to query Git servers.
	ListGitServers(ctx context.Context, in *ListGitServersRequest, opts ...grpc.CallOption) (*ListGitServersResponse, error)
	// UpdateGitServer is used to update a Git server object.
	UpdateGitServer(ctx context.Context, in *UpdateGitServerRequest, opts ...grpc.CallOption) (*types.ServerV2, error)
	// UpsertGitServer is used to create or replace a Git server object.
	UpsertGitServer(ctx context.Context, in *UpsertGitServerRequest, opts ...grpc.CallOption) (*types.ServerV2, error)
	// DeleteGitServer is used to delete a Git server object.
	DeleteGitServer(ctx context.Context, in *DeleteGitServerRequest, opts ...grpc.CallOption) (*emptypb.Empty, error)
	// CreateGitHubAuthRequest starts GitHub OAuth flow for authenticated user.
	CreateGitHubAuthRequest(ctx context.Context, in *CreateGitHubAuthRequestRequest, opts ...grpc.CallOption) (*types.GithubAuthRequest, error)
}

type gitServerServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewGitServerServiceClient(cc grpc.ClientConnInterface) GitServerServiceClient {
	return &gitServerServiceClient{cc}
}

func (c *gitServerServiceClient) CreateGitServer(ctx context.Context, in *CreateGitServerRequest, opts ...grpc.CallOption) (*types.ServerV2, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(types.ServerV2)
	err := c.cc.Invoke(ctx, GitServerService_CreateGitServer_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *gitServerServiceClient) GetGitServer(ctx context.Context, in *GetGitServerRequest, opts ...grpc.CallOption) (*types.ServerV2, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(types.ServerV2)
	err := c.cc.Invoke(ctx, GitServerService_GetGitServer_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *gitServerServiceClient) ListGitServers(ctx context.Context, in *ListGitServersRequest, opts ...grpc.CallOption) (*ListGitServersResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ListGitServersResponse)
	err := c.cc.Invoke(ctx, GitServerService_ListGitServers_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *gitServerServiceClient) UpdateGitServer(ctx context.Context, in *UpdateGitServerRequest, opts ...grpc.CallOption) (*types.ServerV2, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(types.ServerV2)
	err := c.cc.Invoke(ctx, GitServerService_UpdateGitServer_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *gitServerServiceClient) UpsertGitServer(ctx context.Context, in *UpsertGitServerRequest, opts ...grpc.CallOption) (*types.ServerV2, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(types.ServerV2)
	err := c.cc.Invoke(ctx, GitServerService_UpsertGitServer_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *gitServerServiceClient) DeleteGitServer(ctx context.Context, in *DeleteGitServerRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, GitServerService_DeleteGitServer_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *gitServerServiceClient) CreateGitHubAuthRequest(ctx context.Context, in *CreateGitHubAuthRequestRequest, opts ...grpc.CallOption) (*types.GithubAuthRequest, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(types.GithubAuthRequest)
	err := c.cc.Invoke(ctx, GitServerService_CreateGitHubAuthRequest_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GitServerServiceServer is the server API for GitServerService service.
// All implementations must embed UnimplementedGitServerServiceServer
// for forward compatibility.
//
// GitServerService provides methods to manage Git server.
type GitServerServiceServer interface {
	// CreateGitServer is used to create a Git server object.
	CreateGitServer(context.Context, *CreateGitServerRequest) (*types.ServerV2, error)
	// GetGitServer is used to retrieve a Git server object.
	GetGitServer(context.Context, *GetGitServerRequest) (*types.ServerV2, error)
	// ListGitServers is used to query Git servers.
	ListGitServers(context.Context, *ListGitServersRequest) (*ListGitServersResponse, error)
	// UpdateGitServer is used to update a Git server object.
	UpdateGitServer(context.Context, *UpdateGitServerRequest) (*types.ServerV2, error)
	// UpsertGitServer is used to create or replace a Git server object.
	UpsertGitServer(context.Context, *UpsertGitServerRequest) (*types.ServerV2, error)
	// DeleteGitServer is used to delete a Git server object.
	DeleteGitServer(context.Context, *DeleteGitServerRequest) (*emptypb.Empty, error)
	// CreateGitHubAuthRequest starts GitHub OAuth flow for authenticated user.
	CreateGitHubAuthRequest(context.Context, *CreateGitHubAuthRequestRequest) (*types.GithubAuthRequest, error)
	mustEmbedUnimplementedGitServerServiceServer()
}

// UnimplementedGitServerServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedGitServerServiceServer struct{}

func (UnimplementedGitServerServiceServer) CreateGitServer(context.Context, *CreateGitServerRequest) (*types.ServerV2, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateGitServer not implemented")
}
func (UnimplementedGitServerServiceServer) GetGitServer(context.Context, *GetGitServerRequest) (*types.ServerV2, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetGitServer not implemented")
}
func (UnimplementedGitServerServiceServer) ListGitServers(context.Context, *ListGitServersRequest) (*ListGitServersResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListGitServers not implemented")
}
func (UnimplementedGitServerServiceServer) UpdateGitServer(context.Context, *UpdateGitServerRequest) (*types.ServerV2, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateGitServer not implemented")
}
func (UnimplementedGitServerServiceServer) UpsertGitServer(context.Context, *UpsertGitServerRequest) (*types.ServerV2, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpsertGitServer not implemented")
}
func (UnimplementedGitServerServiceServer) DeleteGitServer(context.Context, *DeleteGitServerRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteGitServer not implemented")
}
func (UnimplementedGitServerServiceServer) CreateGitHubAuthRequest(context.Context, *CreateGitHubAuthRequestRequest) (*types.GithubAuthRequest, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateGitHubAuthRequest not implemented")
}
func (UnimplementedGitServerServiceServer) mustEmbedUnimplementedGitServerServiceServer() {}
func (UnimplementedGitServerServiceServer) testEmbeddedByValue()                          {}

// UnsafeGitServerServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to GitServerServiceServer will
// result in compilation errors.
type UnsafeGitServerServiceServer interface {
	mustEmbedUnimplementedGitServerServiceServer()
}

func RegisterGitServerServiceServer(s grpc.ServiceRegistrar, srv GitServerServiceServer) {
	// If the following call pancis, it indicates UnimplementedGitServerServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&GitServerService_ServiceDesc, srv)
}

func _GitServerService_CreateGitServer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateGitServerRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GitServerServiceServer).CreateGitServer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: GitServerService_CreateGitServer_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GitServerServiceServer).CreateGitServer(ctx, req.(*CreateGitServerRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GitServerService_GetGitServer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetGitServerRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GitServerServiceServer).GetGitServer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: GitServerService_GetGitServer_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GitServerServiceServer).GetGitServer(ctx, req.(*GetGitServerRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GitServerService_ListGitServers_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListGitServersRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GitServerServiceServer).ListGitServers(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: GitServerService_ListGitServers_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GitServerServiceServer).ListGitServers(ctx, req.(*ListGitServersRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GitServerService_UpdateGitServer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateGitServerRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GitServerServiceServer).UpdateGitServer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: GitServerService_UpdateGitServer_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GitServerServiceServer).UpdateGitServer(ctx, req.(*UpdateGitServerRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GitServerService_UpsertGitServer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpsertGitServerRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GitServerServiceServer).UpsertGitServer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: GitServerService_UpsertGitServer_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GitServerServiceServer).UpsertGitServer(ctx, req.(*UpsertGitServerRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GitServerService_DeleteGitServer_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteGitServerRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GitServerServiceServer).DeleteGitServer(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: GitServerService_DeleteGitServer_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GitServerServiceServer).DeleteGitServer(ctx, req.(*DeleteGitServerRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GitServerService_CreateGitHubAuthRequest_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateGitHubAuthRequestRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GitServerServiceServer).CreateGitHubAuthRequest(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: GitServerService_CreateGitHubAuthRequest_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GitServerServiceServer).CreateGitHubAuthRequest(ctx, req.(*CreateGitHubAuthRequestRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// GitServerService_ServiceDesc is the grpc.ServiceDesc for GitServerService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var GitServerService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "teleport.gitserver.v1.GitServerService",
	HandlerType: (*GitServerServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateGitServer",
			Handler:    _GitServerService_CreateGitServer_Handler,
		},
		{
			MethodName: "GetGitServer",
			Handler:    _GitServerService_GetGitServer_Handler,
		},
		{
			MethodName: "ListGitServers",
			Handler:    _GitServerService_ListGitServers_Handler,
		},
		{
			MethodName: "UpdateGitServer",
			Handler:    _GitServerService_UpdateGitServer_Handler,
		},
		{
			MethodName: "UpsertGitServer",
			Handler:    _GitServerService_UpsertGitServer_Handler,
		},
		{
			MethodName: "DeleteGitServer",
			Handler:    _GitServerService_DeleteGitServer_Handler,
		},
		{
			MethodName: "CreateGitHubAuthRequest",
			Handler:    _GitServerService_CreateGitHubAuthRequest_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "teleport/gitserver/v1/git_server_service.proto",
}
