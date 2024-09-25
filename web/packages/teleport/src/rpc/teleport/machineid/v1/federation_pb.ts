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

// @generated by protoc-gen-es v1.10.0 with parameter "target=ts"
// @generated from file teleport/machineid/v1/federation.proto (package teleport.machineid.v1, syntax proto3)
/* eslint-disable */
// @ts-nocheck

import type { BinaryReadOptions, FieldList, JsonReadOptions, JsonValue, PartialMessage, PlainMessage } from "@bufbuild/protobuf";
import { Message, proto3, Timestamp } from "@bufbuild/protobuf";
import { Metadata } from "../../header/v1/metadata_pb.js";

/**
 * SPIFFEFederation is a resource that represents the configuration of a trust
 * domain federation.
 *
 * @generated from message teleport.machineid.v1.SPIFFEFederation
 */
export class SPIFFEFederation extends Message<SPIFFEFederation> {
  /**
   * The kind of resource represented.
   *
   * @generated from field: string kind = 1;
   */
  kind = "";

  /**
   * Differentiates variations of the same kind. All resources should
   * contain one, even if it is never populated.
   *
   * @generated from field: string sub_kind = 2;
   */
  subKind = "";

  /**
   * The version of the resource being represented.
   *
   * @generated from field: string version = 3;
   */
  version = "";

  /**
   * Common metadata that all resources share.
   * Importantly, the name MUST match the name of the trust domain you federate
   * with.
   *
   * @generated from field: teleport.header.v1.Metadata metadata = 4;
   */
  metadata?: Metadata;

  /**
   * The configured properties of the trust domain federation
   *
   * @generated from field: teleport.machineid.v1.SPIFFEFederationSpec spec = 5;
   */
  spec?: SPIFFEFederationSpec;

  /**
   * Fields that are set by the server as results of operations. These should
   * not be modified by users.
   *
   * @generated from field: teleport.machineid.v1.SPIFFEFederationStatus status = 6;
   */
  status?: SPIFFEFederationStatus;

  constructor(data?: PartialMessage<SPIFFEFederation>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.machineid.v1.SPIFFEFederation";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "kind", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 2, name: "sub_kind", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 3, name: "version", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 4, name: "metadata", kind: "message", T: Metadata },
    { no: 5, name: "spec", kind: "message", T: SPIFFEFederationSpec },
    { no: 6, name: "status", kind: "message", T: SPIFFEFederationStatus },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): SPIFFEFederation {
    return new SPIFFEFederation().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): SPIFFEFederation {
    return new SPIFFEFederation().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): SPIFFEFederation {
    return new SPIFFEFederation().fromJsonString(jsonString, options);
  }

  static equals(a: SPIFFEFederation | PlainMessage<SPIFFEFederation> | undefined, b: SPIFFEFederation | PlainMessage<SPIFFEFederation> | undefined): boolean {
    return proto3.util.equals(SPIFFEFederation, a, b);
  }
}

/**
 * SPIFFEFederationBundleSourceStatic is a static bundle source. It should be an
 * option of last resort, as it requires manual updates.
 *
 * @generated from message teleport.machineid.v1.SPIFFEFederationBundleSourceStatic
 */
export class SPIFFEFederationBundleSourceStatic extends Message<SPIFFEFederationBundleSourceStatic> {
  /**
   * The SPIFFE JWKS bundle.
   *
   * @generated from field: string bundle = 1;
   */
  bundle = "";

  constructor(data?: PartialMessage<SPIFFEFederationBundleSourceStatic>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.machineid.v1.SPIFFEFederationBundleSourceStatic";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "bundle", kind: "scalar", T: 9 /* ScalarType.STRING */ },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): SPIFFEFederationBundleSourceStatic {
    return new SPIFFEFederationBundleSourceStatic().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): SPIFFEFederationBundleSourceStatic {
    return new SPIFFEFederationBundleSourceStatic().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): SPIFFEFederationBundleSourceStatic {
    return new SPIFFEFederationBundleSourceStatic().fromJsonString(jsonString, options);
  }

  static equals(a: SPIFFEFederationBundleSourceStatic | PlainMessage<SPIFFEFederationBundleSourceStatic> | undefined, b: SPIFFEFederationBundleSourceStatic | PlainMessage<SPIFFEFederationBundleSourceStatic> | undefined): boolean {
    return proto3.util.equals(SPIFFEFederationBundleSourceStatic, a, b);
  }
}

/**
 * SPIFFEFederationBundleSourceHTTPSWeb is a bundle source that fetches the bundle
 * from a HTTPS endpoint that is protected by a Web PKI certificate.
 *
 * @generated from message teleport.machineid.v1.SPIFFEFederationBundleSourceHTTPSWeb
 */
export class SPIFFEFederationBundleSourceHTTPSWeb extends Message<SPIFFEFederationBundleSourceHTTPSWeb> {
  /**
   * The URL of the SPIFFE Bundle Endpoint.
   *
   * @generated from field: string bundle_endpoint_url = 1;
   */
  bundleEndpointUrl = "";

  constructor(data?: PartialMessage<SPIFFEFederationBundleSourceHTTPSWeb>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.machineid.v1.SPIFFEFederationBundleSourceHTTPSWeb";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "bundle_endpoint_url", kind: "scalar", T: 9 /* ScalarType.STRING */ },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): SPIFFEFederationBundleSourceHTTPSWeb {
    return new SPIFFEFederationBundleSourceHTTPSWeb().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): SPIFFEFederationBundleSourceHTTPSWeb {
    return new SPIFFEFederationBundleSourceHTTPSWeb().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): SPIFFEFederationBundleSourceHTTPSWeb {
    return new SPIFFEFederationBundleSourceHTTPSWeb().fromJsonString(jsonString, options);
  }

  static equals(a: SPIFFEFederationBundleSourceHTTPSWeb | PlainMessage<SPIFFEFederationBundleSourceHTTPSWeb> | undefined, b: SPIFFEFederationBundleSourceHTTPSWeb | PlainMessage<SPIFFEFederationBundleSourceHTTPSWeb> | undefined): boolean {
    return proto3.util.equals(SPIFFEFederationBundleSourceHTTPSWeb, a, b);
  }
}

/**
 * SPIFFEFederationBundleSource configures how the federation bundle is sourced.
 * Only one field can be set.
 *
 * @generated from message teleport.machineid.v1.SPIFFEFederationBundleSource
 */
export class SPIFFEFederationBundleSource extends Message<SPIFFEFederationBundleSource> {
  /**
   * @generated from field: teleport.machineid.v1.SPIFFEFederationBundleSourceStatic static = 1;
   */
  static?: SPIFFEFederationBundleSourceStatic;

  /**
   * @generated from field: teleport.machineid.v1.SPIFFEFederationBundleSourceHTTPSWeb https_web = 2;
   */
  httpsWeb?: SPIFFEFederationBundleSourceHTTPSWeb;

  constructor(data?: PartialMessage<SPIFFEFederationBundleSource>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.machineid.v1.SPIFFEFederationBundleSource";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "static", kind: "message", T: SPIFFEFederationBundleSourceStatic },
    { no: 2, name: "https_web", kind: "message", T: SPIFFEFederationBundleSourceHTTPSWeb },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): SPIFFEFederationBundleSource {
    return new SPIFFEFederationBundleSource().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): SPIFFEFederationBundleSource {
    return new SPIFFEFederationBundleSource().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): SPIFFEFederationBundleSource {
    return new SPIFFEFederationBundleSource().fromJsonString(jsonString, options);
  }

  static equals(a: SPIFFEFederationBundleSource | PlainMessage<SPIFFEFederationBundleSource> | undefined, b: SPIFFEFederationBundleSource | PlainMessage<SPIFFEFederationBundleSource> | undefined): boolean {
    return proto3.util.equals(SPIFFEFederationBundleSource, a, b);
  }
}

/**
 * SPIFFEFederationSpec is the configuration of a trust domain federation.
 *
 * @generated from message teleport.machineid.v1.SPIFFEFederationSpec
 */
export class SPIFFEFederationSpec extends Message<SPIFFEFederationSpec> {
  /**
   * The source of the federation bundle.
   *
   * @generated from field: teleport.machineid.v1.SPIFFEFederationBundleSource bundle_source = 1;
   */
  bundleSource?: SPIFFEFederationBundleSource;

  constructor(data?: PartialMessage<SPIFFEFederationSpec>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.machineid.v1.SPIFFEFederationSpec";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "bundle_source", kind: "message", T: SPIFFEFederationBundleSource },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): SPIFFEFederationSpec {
    return new SPIFFEFederationSpec().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): SPIFFEFederationSpec {
    return new SPIFFEFederationSpec().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): SPIFFEFederationSpec {
    return new SPIFFEFederationSpec().fromJsonString(jsonString, options);
  }

  static equals(a: SPIFFEFederationSpec | PlainMessage<SPIFFEFederationSpec> | undefined, b: SPIFFEFederationSpec | PlainMessage<SPIFFEFederationSpec> | undefined): boolean {
    return proto3.util.equals(SPIFFEFederationSpec, a, b);
  }
}

/**
 * FederationStatus is the status of a trust domain federation.
 *
 * @generated from message teleport.machineid.v1.SPIFFEFederationStatus
 */
export class SPIFFEFederationStatus extends Message<SPIFFEFederationStatus> {
  /**
   * The most recently fetched bundle from the federated trust domain.
   *
   * @generated from field: string current_bundle = 1;
   */
  currentBundle = "";

  /**
   * The time that the most recently fetched bundle was obtained.
   *
   * @generated from field: google.protobuf.Timestamp current_bundle_synced_at = 2;
   */
  currentBundleSyncedAt?: Timestamp;

  /**
   * The time that this SPIFFE federation should be synced again. This is
   * usually determined by the refresh hint provided within the current bundle
   * but this can be overridden by the server where the provided refresh hint
   * is not appropriate.
   *
   * A value of zero indicates that an automatic sync is not scheduled (e.g.
   * because the bundle source is static).
   *
   * @generated from field: google.protobuf.Timestamp next_sync_at = 4;
   */
  nextSyncAt?: Timestamp;

  /**
   * The SPIFFEFederationBundleSource that was used for the currently synced
   * bundle. This allows the bundle to be resynced if the source changes.
   *
   * @generated from field: teleport.machineid.v1.SPIFFEFederationBundleSource current_bundle_synced_from = 5;
   */
  currentBundleSyncedFrom?: SPIFFEFederationBundleSource;

  constructor(data?: PartialMessage<SPIFFEFederationStatus>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.machineid.v1.SPIFFEFederationStatus";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "current_bundle", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 2, name: "current_bundle_synced_at", kind: "message", T: Timestamp },
    { no: 4, name: "next_sync_at", kind: "message", T: Timestamp },
    { no: 5, name: "current_bundle_synced_from", kind: "message", T: SPIFFEFederationBundleSource },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): SPIFFEFederationStatus {
    return new SPIFFEFederationStatus().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): SPIFFEFederationStatus {
    return new SPIFFEFederationStatus().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): SPIFFEFederationStatus {
    return new SPIFFEFederationStatus().fromJsonString(jsonString, options);
  }

  static equals(a: SPIFFEFederationStatus | PlainMessage<SPIFFEFederationStatus> | undefined, b: SPIFFEFederationStatus | PlainMessage<SPIFFEFederationStatus> | undefined): boolean {
    return proto3.util.equals(SPIFFEFederationStatus, a, b);
  }
}

