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

// @generated by protoc-gen-es v1.10.0 with parameter "target=ts"
// @generated from file teleport/transport/v1/transport_service.proto (package teleport.transport.v1, syntax proto3)
/* eslint-disable */
// @ts-nocheck

import type { BinaryReadOptions, FieldList, JsonReadOptions, JsonValue, PartialMessage, PlainMessage } from "@bufbuild/protobuf";
import { Message, proto3 } from "@bufbuild/protobuf";

/**
 * Request for ProxySSH
 *
 * In order for proxying to begin the client must send a request with the
 * TargetHost populated. Creating the stream doesn't actually open the SSH connection.
 * Any attempts to exchange frames prior to the client sending a TargetHost message will
 * result in the stream being terminated.
 *
 * @generated from message teleport.transport.v1.ProxySSHRequest
 */
export class ProxySSHRequest extends Message<ProxySSHRequest> {
  /**
   * Contains the information required to dial the target.
   * Must be populated on the initial request so that SSH connection can be established.
   *
   * @generated from field: teleport.transport.v1.TargetHost dial_target = 1;
   */
  dialTarget?: TargetHost;

  /**
   * Payload from SSH/SSH Agent Protocols
   *
   * @generated from oneof teleport.transport.v1.ProxySSHRequest.frame
   */
  frame: {
    /**
     * Raw SSH payload
     *
     * @generated from field: teleport.transport.v1.Frame ssh = 2;
     */
    value: Frame;
    case: "ssh";
  } | {
    /**
     * Raw SSH Agent payload, populated for agent forwarding
     *
     * @generated from field: teleport.transport.v1.Frame agent = 3;
     */
    value: Frame;
    case: "agent";
  } | { case: undefined; value?: undefined } = { case: undefined };

  constructor(data?: PartialMessage<ProxySSHRequest>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.transport.v1.ProxySSHRequest";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "dial_target", kind: "message", T: TargetHost },
    { no: 2, name: "ssh", kind: "message", T: Frame, oneof: "frame" },
    { no: 3, name: "agent", kind: "message", T: Frame, oneof: "frame" },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ProxySSHRequest {
    return new ProxySSHRequest().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ProxySSHRequest {
    return new ProxySSHRequest().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ProxySSHRequest {
    return new ProxySSHRequest().fromJsonString(jsonString, options);
  }

  static equals(a: ProxySSHRequest | PlainMessage<ProxySSHRequest> | undefined, b: ProxySSHRequest | PlainMessage<ProxySSHRequest> | undefined): boolean {
    return proto3.util.equals(ProxySSHRequest, a, b);
  }
}

/**
 * Response for ProxySSH
 *
 * The first response from the server will contain ClusterDetails
 * so that clients may get information about a particular cluster
 * without needing to call GetClusterDetails first. All subsequent
 * response will only contain Frames.
 *
 * @generated from message teleport.transport.v1.ProxySSHResponse
 */
export class ProxySSHResponse extends Message<ProxySSHResponse> {
  /**
   * Cluster information returned *ONLY* with the first frame
   *
   * @generated from field: teleport.transport.v1.ClusterDetails details = 1;
   */
  details?: ClusterDetails;

  /**
   * Payload from SSH/SSH Agent Protocols
   *
   * @generated from oneof teleport.transport.v1.ProxySSHResponse.frame
   */
  frame: {
    /**
     * SSH payload
     *
     * @generated from field: teleport.transport.v1.Frame ssh = 2;
     */
    value: Frame;
    case: "ssh";
  } | {
    /**
     * SSH Agent payload, populated for agent forwarding
     *
     * @generated from field: teleport.transport.v1.Frame agent = 3;
     */
    value: Frame;
    case: "agent";
  } | { case: undefined; value?: undefined } = { case: undefined };

  constructor(data?: PartialMessage<ProxySSHResponse>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.transport.v1.ProxySSHResponse";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "details", kind: "message", T: ClusterDetails },
    { no: 2, name: "ssh", kind: "message", T: Frame, oneof: "frame" },
    { no: 3, name: "agent", kind: "message", T: Frame, oneof: "frame" },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ProxySSHResponse {
    return new ProxySSHResponse().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ProxySSHResponse {
    return new ProxySSHResponse().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ProxySSHResponse {
    return new ProxySSHResponse().fromJsonString(jsonString, options);
  }

  static equals(a: ProxySSHResponse | PlainMessage<ProxySSHResponse> | undefined, b: ProxySSHResponse | PlainMessage<ProxySSHResponse> | undefined): boolean {
    return proto3.util.equals(ProxySSHResponse, a, b);
  }
}

/**
 * Request for ProxyCluster
 *
 * In order for proxying to begin the client must send a request with the
 * cluster name populated. Creating the stream doesn't actually open the connection.
 * Any attempts to exchange frames prior to the client sending a cluster name will
 * result in the stream being terminated. All subsequent messages only need to
 * provide a Frame.
 *
 * @generated from message teleport.transport.v1.ProxyClusterRequest
 */
export class ProxyClusterRequest extends Message<ProxyClusterRequest> {
  /**
   * Name of the cluster to connect to. Must
   * be sent first so the connection can be established.
   *
   * @generated from field: string cluster = 1;
   */
  cluster = "";

  /**
   * Raw payload
   *
   * @generated from field: teleport.transport.v1.Frame frame = 2;
   */
  frame?: Frame;

  constructor(data?: PartialMessage<ProxyClusterRequest>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.transport.v1.ProxyClusterRequest";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "cluster", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 2, name: "frame", kind: "message", T: Frame },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ProxyClusterRequest {
    return new ProxyClusterRequest().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ProxyClusterRequest {
    return new ProxyClusterRequest().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ProxyClusterRequest {
    return new ProxyClusterRequest().fromJsonString(jsonString, options);
  }

  static equals(a: ProxyClusterRequest | PlainMessage<ProxyClusterRequest> | undefined, b: ProxyClusterRequest | PlainMessage<ProxyClusterRequest> | undefined): boolean {
    return proto3.util.equals(ProxyClusterRequest, a, b);
  }
}

/**
 * Response for ProxyCluster
 *
 * @generated from message teleport.transport.v1.ProxyClusterResponse
 */
export class ProxyClusterResponse extends Message<ProxyClusterResponse> {
  /**
   * Raw payload
   *
   * @generated from field: teleport.transport.v1.Frame frame = 1;
   */
  frame?: Frame;

  constructor(data?: PartialMessage<ProxyClusterResponse>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.transport.v1.ProxyClusterResponse";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "frame", kind: "message", T: Frame },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ProxyClusterResponse {
    return new ProxyClusterResponse().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ProxyClusterResponse {
    return new ProxyClusterResponse().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ProxyClusterResponse {
    return new ProxyClusterResponse().fromJsonString(jsonString, options);
  }

  static equals(a: ProxyClusterResponse | PlainMessage<ProxyClusterResponse> | undefined, b: ProxyClusterResponse | PlainMessage<ProxyClusterResponse> | undefined): boolean {
    return proto3.util.equals(ProxyClusterResponse, a, b);
  }
}

/**
 * Encapsulates protocol specific payloads
 *
 * @generated from message teleport.transport.v1.Frame
 */
export class Frame extends Message<Frame> {
  /**
   * The raw packet of data
   *
   * @generated from field: bytes payload = 1;
   */
  payload = new Uint8Array(0);

  constructor(data?: PartialMessage<Frame>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.transport.v1.Frame";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "payload", kind: "scalar", T: 12 /* ScalarType.BYTES */ },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): Frame {
    return new Frame().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): Frame {
    return new Frame().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): Frame {
    return new Frame().fromJsonString(jsonString, options);
  }

  static equals(a: Frame | PlainMessage<Frame> | undefined, b: Frame | PlainMessage<Frame> | undefined): boolean {
    return proto3.util.equals(Frame, a, b);
  }
}

/**
 * TargetHost indicates which server the connection is for
 *
 * @generated from message teleport.transport.v1.TargetHost
 */
export class TargetHost extends Message<TargetHost> {
  /**
   * The hostname/ip/uuid:port of the remote host.
   *
   * @generated from field: string host_port = 1;
   */
  hostPort = "";

  /**
   * The cluster the server is a member of
   *
   * @generated from field: string cluster = 2;
   */
  cluster = "";

  constructor(data?: PartialMessage<TargetHost>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.transport.v1.TargetHost";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "host_port", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 2, name: "cluster", kind: "scalar", T: 9 /* ScalarType.STRING */ },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): TargetHost {
    return new TargetHost().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): TargetHost {
    return new TargetHost().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): TargetHost {
    return new TargetHost().fromJsonString(jsonString, options);
  }

  static equals(a: TargetHost | PlainMessage<TargetHost> | undefined, b: TargetHost | PlainMessage<TargetHost> | undefined): boolean {
    return proto3.util.equals(TargetHost, a, b);
  }
}

/**
 * Request for GetClusterDetails.
 *
 * @generated from message teleport.transport.v1.GetClusterDetailsRequest
 */
export class GetClusterDetailsRequest extends Message<GetClusterDetailsRequest> {
  constructor(data?: PartialMessage<GetClusterDetailsRequest>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.transport.v1.GetClusterDetailsRequest";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): GetClusterDetailsRequest {
    return new GetClusterDetailsRequest().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): GetClusterDetailsRequest {
    return new GetClusterDetailsRequest().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): GetClusterDetailsRequest {
    return new GetClusterDetailsRequest().fromJsonString(jsonString, options);
  }

  static equals(a: GetClusterDetailsRequest | PlainMessage<GetClusterDetailsRequest> | undefined, b: GetClusterDetailsRequest | PlainMessage<GetClusterDetailsRequest> | undefined): boolean {
    return proto3.util.equals(GetClusterDetailsRequest, a, b);
  }
}

/**
 * Response for GetClusterDetails.
 *
 * @generated from message teleport.transport.v1.GetClusterDetailsResponse
 */
export class GetClusterDetailsResponse extends Message<GetClusterDetailsResponse> {
  /**
   * Cluster configuration details
   *
   * @generated from field: teleport.transport.v1.ClusterDetails details = 1;
   */
  details?: ClusterDetails;

  constructor(data?: PartialMessage<GetClusterDetailsResponse>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.transport.v1.GetClusterDetailsResponse";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "details", kind: "message", T: ClusterDetails },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): GetClusterDetailsResponse {
    return new GetClusterDetailsResponse().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): GetClusterDetailsResponse {
    return new GetClusterDetailsResponse().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): GetClusterDetailsResponse {
    return new GetClusterDetailsResponse().fromJsonString(jsonString, options);
  }

  static equals(a: GetClusterDetailsResponse | PlainMessage<GetClusterDetailsResponse> | undefined, b: GetClusterDetailsResponse | PlainMessage<GetClusterDetailsResponse> | undefined): boolean {
    return proto3.util.equals(GetClusterDetailsResponse, a, b);
  }
}

/**
 * ClusterDetails contains cluster configuration information
 *
 * @generated from message teleport.transport.v1.ClusterDetails
 */
export class ClusterDetails extends Message<ClusterDetails> {
  /**
   * If the cluster is running in FIPS mode
   *
   * @generated from field: bool fips_enabled = 1;
   */
  fipsEnabled = false;

  constructor(data?: PartialMessage<ClusterDetails>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.transport.v1.ClusterDetails";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "fips_enabled", kind: "scalar", T: 8 /* ScalarType.BOOL */ },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ClusterDetails {
    return new ClusterDetails().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ClusterDetails {
    return new ClusterDetails().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ClusterDetails {
    return new ClusterDetails().fromJsonString(jsonString, options);
  }

  static equals(a: ClusterDetails | PlainMessage<ClusterDetails> | undefined, b: ClusterDetails | PlainMessage<ClusterDetails> | undefined): boolean {
    return proto3.util.equals(ClusterDetails, a, b);
  }
}

