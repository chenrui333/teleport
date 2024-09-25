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
// @generated from file teleport/userpreferences/v1/cluster_preferences.proto (package teleport.userpreferences.v1, syntax proto3)
/* eslint-disable */
// @ts-nocheck

import type { BinaryReadOptions, FieldList, JsonReadOptions, JsonValue, PartialMessage, PlainMessage } from "@bufbuild/protobuf";
import { Message, proto3 } from "@bufbuild/protobuf";

/**
 * PinnedResourcesUserPreferences is a collection of resource IDs that will be
 * displayed in the user's pinned resources tab in the Web UI.
 *
 * @generated from message teleport.userpreferences.v1.PinnedResourcesUserPreferences
 */
export class PinnedResourcesUserPreferences extends Message<PinnedResourcesUserPreferences> {
  /**
   * resource_ids is a list of unified resource name sort keys.
   *
   * @generated from field: repeated string resource_ids = 1;
   */
  resourceIds: string[] = [];

  constructor(data?: PartialMessage<PinnedResourcesUserPreferences>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.userpreferences.v1.PinnedResourcesUserPreferences";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "resource_ids", kind: "scalar", T: 9 /* ScalarType.STRING */, repeated: true },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): PinnedResourcesUserPreferences {
    return new PinnedResourcesUserPreferences().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): PinnedResourcesUserPreferences {
    return new PinnedResourcesUserPreferences().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): PinnedResourcesUserPreferences {
    return new PinnedResourcesUserPreferences().fromJsonString(jsonString, options);
  }

  static equals(a: PinnedResourcesUserPreferences | PlainMessage<PinnedResourcesUserPreferences> | undefined, b: PinnedResourcesUserPreferences | PlainMessage<PinnedResourcesUserPreferences> | undefined): boolean {
    return proto3.util.equals(PinnedResourcesUserPreferences, a, b);
  }
}

/**
 * ClusterUserPreferences are user preferences saved per cluster.
 *
 * @generated from message teleport.userpreferences.v1.ClusterUserPreferences
 */
export class ClusterUserPreferences extends Message<ClusterUserPreferences> {
  /**
   * pinned_resources is a list of pinned resources.
   *
   * @generated from field: teleport.userpreferences.v1.PinnedResourcesUserPreferences pinned_resources = 1;
   */
  pinnedResources?: PinnedResourcesUserPreferences;

  constructor(data?: PartialMessage<ClusterUserPreferences>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.userpreferences.v1.ClusterUserPreferences";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "pinned_resources", kind: "message", T: PinnedResourcesUserPreferences },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ClusterUserPreferences {
    return new ClusterUserPreferences().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ClusterUserPreferences {
    return new ClusterUserPreferences().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ClusterUserPreferences {
    return new ClusterUserPreferences().fromJsonString(jsonString, options);
  }

  static equals(a: ClusterUserPreferences | PlainMessage<ClusterUserPreferences> | undefined, b: ClusterUserPreferences | PlainMessage<ClusterUserPreferences> | undefined): boolean {
    return proto3.util.equals(ClusterUserPreferences, a, b);
  }
}

