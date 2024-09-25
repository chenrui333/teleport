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

// @generated by protoc-gen-es v1.10.0 with parameter "target=ts"
// @generated from file teleport/autoupdate/v1/autoupdate.proto (package teleport.autoupdate.v1, syntax proto3)
/* eslint-disable */
// @ts-nocheck

import type { BinaryReadOptions, FieldList, JsonReadOptions, JsonValue, PartialMessage, PlainMessage } from "@bufbuild/protobuf";
import { Message, proto3 } from "@bufbuild/protobuf";
import { Metadata } from "../../header/v1/metadata_pb.js";

/**
 * AutoUpdateConfig is a config singleton used to configure cluster
 * autoupdate settings.
 *
 * @generated from message teleport.autoupdate.v1.AutoUpdateConfig
 */
export class AutoUpdateConfig extends Message<AutoUpdateConfig> {
  /**
   * @generated from field: string kind = 1;
   */
  kind = "";

  /**
   * @generated from field: string sub_kind = 2;
   */
  subKind = "";

  /**
   * @generated from field: string version = 3;
   */
  version = "";

  /**
   * @generated from field: teleport.header.v1.Metadata metadata = 4;
   */
  metadata?: Metadata;

  /**
   * @generated from field: teleport.autoupdate.v1.AutoUpdateConfigSpec spec = 5;
   */
  spec?: AutoUpdateConfigSpec;

  constructor(data?: PartialMessage<AutoUpdateConfig>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.autoupdate.v1.AutoUpdateConfig";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "kind", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 2, name: "sub_kind", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 3, name: "version", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 4, name: "metadata", kind: "message", T: Metadata },
    { no: 5, name: "spec", kind: "message", T: AutoUpdateConfigSpec },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): AutoUpdateConfig {
    return new AutoUpdateConfig().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): AutoUpdateConfig {
    return new AutoUpdateConfig().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): AutoUpdateConfig {
    return new AutoUpdateConfig().fromJsonString(jsonString, options);
  }

  static equals(a: AutoUpdateConfig | PlainMessage<AutoUpdateConfig> | undefined, b: AutoUpdateConfig | PlainMessage<AutoUpdateConfig> | undefined): boolean {
    return proto3.util.equals(AutoUpdateConfig, a, b);
  }
}

/**
 * AutoUpdateConfigSpec encodes the parameters of the autoupdate config object.
 *
 * @generated from message teleport.autoupdate.v1.AutoUpdateConfigSpec
 */
export class AutoUpdateConfigSpec extends Message<AutoUpdateConfigSpec> {
  /**
   * ToolsAutoupdate encodes the feature flag to enable/disable tools autoupdates.
   *
   * @generated from field: bool tools_autoupdate = 1;
   */
  toolsAutoupdate = false;

  constructor(data?: PartialMessage<AutoUpdateConfigSpec>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.autoupdate.v1.AutoUpdateConfigSpec";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "tools_autoupdate", kind: "scalar", T: 8 /* ScalarType.BOOL */ },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): AutoUpdateConfigSpec {
    return new AutoUpdateConfigSpec().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): AutoUpdateConfigSpec {
    return new AutoUpdateConfigSpec().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): AutoUpdateConfigSpec {
    return new AutoUpdateConfigSpec().fromJsonString(jsonString, options);
  }

  static equals(a: AutoUpdateConfigSpec | PlainMessage<AutoUpdateConfigSpec> | undefined, b: AutoUpdateConfigSpec | PlainMessage<AutoUpdateConfigSpec> | undefined): boolean {
    return proto3.util.equals(AutoUpdateConfigSpec, a, b);
  }
}

/**
 * AutoUpdateVersion is a resource singleton with version required for
 * tools autoupdate.
 *
 * @generated from message teleport.autoupdate.v1.AutoUpdateVersion
 */
export class AutoUpdateVersion extends Message<AutoUpdateVersion> {
  /**
   * @generated from field: string kind = 1;
   */
  kind = "";

  /**
   * @generated from field: string sub_kind = 2;
   */
  subKind = "";

  /**
   * @generated from field: string version = 3;
   */
  version = "";

  /**
   * @generated from field: teleport.header.v1.Metadata metadata = 4;
   */
  metadata?: Metadata;

  /**
   * @generated from field: teleport.autoupdate.v1.AutoUpdateVersionSpec spec = 5;
   */
  spec?: AutoUpdateVersionSpec;

  constructor(data?: PartialMessage<AutoUpdateVersion>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.autoupdate.v1.AutoUpdateVersion";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "kind", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 2, name: "sub_kind", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 3, name: "version", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 4, name: "metadata", kind: "message", T: Metadata },
    { no: 5, name: "spec", kind: "message", T: AutoUpdateVersionSpec },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): AutoUpdateVersion {
    return new AutoUpdateVersion().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): AutoUpdateVersion {
    return new AutoUpdateVersion().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): AutoUpdateVersion {
    return new AutoUpdateVersion().fromJsonString(jsonString, options);
  }

  static equals(a: AutoUpdateVersion | PlainMessage<AutoUpdateVersion> | undefined, b: AutoUpdateVersion | PlainMessage<AutoUpdateVersion> | undefined): boolean {
    return proto3.util.equals(AutoUpdateVersion, a, b);
  }
}

/**
 * AutoUpdateVersionSpec encodes the parameters of the autoupdate versions.
 *
 * @generated from message teleport.autoupdate.v1.AutoUpdateVersionSpec
 */
export class AutoUpdateVersionSpec extends Message<AutoUpdateVersionSpec> {
  /**
   * ToolsVersion is the semantic version required for tools autoupdates.
   *
   * @generated from field: string tools_version = 1;
   */
  toolsVersion = "";

  constructor(data?: PartialMessage<AutoUpdateVersionSpec>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.autoupdate.v1.AutoUpdateVersionSpec";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "tools_version", kind: "scalar", T: 9 /* ScalarType.STRING */ },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): AutoUpdateVersionSpec {
    return new AutoUpdateVersionSpec().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): AutoUpdateVersionSpec {
    return new AutoUpdateVersionSpec().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): AutoUpdateVersionSpec {
    return new AutoUpdateVersionSpec().fromJsonString(jsonString, options);
  }

  static equals(a: AutoUpdateVersionSpec | PlainMessage<AutoUpdateVersionSpec> | undefined, b: AutoUpdateVersionSpec | PlainMessage<AutoUpdateVersionSpec> | undefined): boolean {
    return proto3.util.equals(AutoUpdateVersionSpec, a, b);
  }
}

