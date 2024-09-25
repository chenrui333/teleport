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
// @generated from file teleport/header/v1/resourceheader.proto (package teleport.header.v1, syntax proto3)
/* eslint-disable */
// @ts-nocheck

import type { BinaryReadOptions, FieldList, JsonReadOptions, JsonValue, PartialMessage, PlainMessage } from "@bufbuild/protobuf";
import { Message, proto3 } from "@bufbuild/protobuf";
import { Metadata } from "./metadata_pb.js";

/**
 * ResourceHeader is a shared resource header.
 *
 * @generated from message teleport.header.v1.ResourceHeader
 */
export class ResourceHeader extends Message<ResourceHeader> {
  /**
   * kind is a resource kind.
   *
   * @generated from field: string kind = 1;
   */
  kind = "";

  /**
   * sub_kind is an optional resource sub kind, used in some resources.
   *
   * @generated from field: string sub_kind = 2;
   */
  subKind = "";

  /**
   * Version is the API version used to create the resource. It must be
   * specified. Based on this version, Teleport will apply different defaults on
   * resource creation or deletion. It must be an integer prefixed by "v".
   * For example: `v1`
   *
   * @generated from field: string version = 3;
   */
  version = "";

  /**
   * metadata is resource metadata.
   *
   * @generated from field: teleport.header.v1.Metadata metadata = 4;
   */
  metadata?: Metadata;

  constructor(data?: PartialMessage<ResourceHeader>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.header.v1.ResourceHeader";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "kind", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 2, name: "sub_kind", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 3, name: "version", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 4, name: "metadata", kind: "message", T: Metadata },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ResourceHeader {
    return new ResourceHeader().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ResourceHeader {
    return new ResourceHeader().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ResourceHeader {
    return new ResourceHeader().fromJsonString(jsonString, options);
  }

  static equals(a: ResourceHeader | PlainMessage<ResourceHeader> | undefined, b: ResourceHeader | PlainMessage<ResourceHeader> | undefined): boolean {
    return proto3.util.equals(ResourceHeader, a, b);
  }
}

