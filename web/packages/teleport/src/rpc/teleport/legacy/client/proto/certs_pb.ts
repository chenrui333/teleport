// Copyright 2022 Gravitational, Inc
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
// @generated from file teleport/legacy/client/proto/certs.proto (package proto, syntax proto3)
/* eslint-disable */
// @ts-nocheck

import type { BinaryReadOptions, FieldList, JsonReadOptions, JsonValue, PartialMessage, PlainMessage } from "@bufbuild/protobuf";
import { Message, proto3 } from "@bufbuild/protobuf";

/**
 * Set of certificates corresponding to a single public key.
 *
 * @generated from message proto.Certs
 */
export class Certs extends Message<Certs> {
  /**
   * SSH certificate marshaled in the authorized key format.
   *
   * @generated from field: bytes SSH = 1;
   */
  SSH = new Uint8Array(0);

  /**
   * TLS X.509 certificate (PEM-encoded).
   *
   * @generated from field: bytes TLS = 2;
   */
  TLS = new Uint8Array(0);

  /**
   * TLSCACerts is a list of TLS certificate authorities.
   *
   * @generated from field: repeated bytes TLSCACerts = 3;
   */
  TLSCACerts: Uint8Array[] = [];

  /**
   * SSHCACerts is a list of SSH certificate authorities.
   *
   * @generated from field: repeated bytes SSHCACerts = 4;
   */
  SSHCACerts: Uint8Array[] = [];

  constructor(data?: PartialMessage<Certs>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "proto.Certs";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "SSH", kind: "scalar", T: 12 /* ScalarType.BYTES */ },
    { no: 2, name: "TLS", kind: "scalar", T: 12 /* ScalarType.BYTES */ },
    { no: 3, name: "TLSCACerts", kind: "scalar", T: 12 /* ScalarType.BYTES */, repeated: true },
    { no: 4, name: "SSHCACerts", kind: "scalar", T: 12 /* ScalarType.BYTES */, repeated: true },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): Certs {
    return new Certs().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): Certs {
    return new Certs().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): Certs {
    return new Certs().fromJsonString(jsonString, options);
  }

  static equals(a: Certs | PlainMessage<Certs> | undefined, b: Certs | PlainMessage<Certs> | undefined): boolean {
    return proto3.util.equals(Certs, a, b);
  }
}

