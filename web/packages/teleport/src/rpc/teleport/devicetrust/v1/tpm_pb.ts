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
// @generated from file teleport/devicetrust/v1/tpm.proto (package teleport.devicetrust.v1, syntax proto3)
/* eslint-disable */
// @ts-nocheck

import type { BinaryReadOptions, FieldList, JsonReadOptions, JsonValue, PartialMessage, PlainMessage } from "@bufbuild/protobuf";
import { Message, proto3, protoInt64 } from "@bufbuild/protobuf";

/**
 * Encapsulates the value of a PCR at a point at time.
 * See https://pkg.go.dev/github.com/google/go-attestation/attest#PCR
 *
 * @generated from message teleport.devicetrust.v1.TPMPCR
 */
export class TPMPCR extends Message<TPMPCR> {
  /**
   * the PCR index in the PCR bank
   *
   * @generated from field: int32 index = 1;
   */
  index = 0;

  /**
   * the digest currently held in the PCR
   *
   * @generated from field: bytes digest = 2;
   */
  digest = new Uint8Array(0);

  /**
   * the hash algorithm used to produce the digest in this PCR bank. This value
   * is the underlying value of the Go crypto.Hash type.
   *
   * @generated from field: uint64 digest_alg = 3;
   */
  digestAlg = protoInt64.zero;

  constructor(data?: PartialMessage<TPMPCR>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.devicetrust.v1.TPMPCR";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "index", kind: "scalar", T: 5 /* ScalarType.INT32 */ },
    { no: 2, name: "digest", kind: "scalar", T: 12 /* ScalarType.BYTES */ },
    { no: 3, name: "digest_alg", kind: "scalar", T: 4 /* ScalarType.UINT64 */ },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): TPMPCR {
    return new TPMPCR().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): TPMPCR {
    return new TPMPCR().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): TPMPCR {
    return new TPMPCR().fromJsonString(jsonString, options);
  }

  static equals(a: TPMPCR | PlainMessage<TPMPCR> | undefined, b: TPMPCR | PlainMessage<TPMPCR> | undefined): boolean {
    return proto3.util.equals(TPMPCR, a, b);
  }
}

/**
 * Encapsulates the result of a quote operation against the TPM over a PCR
 * using an attestation key.
 * See https://pkg.go.dev/github.com/google/go-attestation/attest#Quote
 *
 * @generated from message teleport.devicetrust.v1.TPMQuote
 */
export class TPMQuote extends Message<TPMQuote> {
  /**
   * @generated from field: bytes quote = 1;
   */
  quote = new Uint8Array(0);

  /**
   * @generated from field: bytes signature = 2;
   */
  signature = new Uint8Array(0);

  constructor(data?: PartialMessage<TPMQuote>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.devicetrust.v1.TPMQuote";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "quote", kind: "scalar", T: 12 /* ScalarType.BYTES */ },
    { no: 2, name: "signature", kind: "scalar", T: 12 /* ScalarType.BYTES */ },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): TPMQuote {
    return new TPMQuote().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): TPMQuote {
    return new TPMQuote().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): TPMQuote {
    return new TPMQuote().fromJsonString(jsonString, options);
  }

  static equals(a: TPMQuote | PlainMessage<TPMQuote> | undefined, b: TPMQuote | PlainMessage<TPMQuote> | undefined): boolean {
    return proto3.util.equals(TPMQuote, a, b);
  }
}

/**
 * The quotes, PCRs and event log from a TPM that attest to the booted state
 * of the machine.
 * See https://pkg.go.dev/github.com/google/go-attestation/attest#PlatformParameters
 * Excludes TPMVersion and Public since these are already known values.
 *
 * @generated from message teleport.devicetrust.v1.TPMPlatformParameters
 */
export class TPMPlatformParameters extends Message<TPMPlatformParameters> {
  /**
   * @generated from field: repeated teleport.devicetrust.v1.TPMQuote quotes = 1;
   */
  quotes: TPMQuote[] = [];

  /**
   * @generated from field: repeated teleport.devicetrust.v1.TPMPCR pcrs = 2;
   */
  pcrs: TPMPCR[] = [];

  /**
   * @generated from field: bytes event_log = 3;
   */
  eventLog = new Uint8Array(0);

  constructor(data?: PartialMessage<TPMPlatformParameters>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.devicetrust.v1.TPMPlatformParameters";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "quotes", kind: "message", T: TPMQuote, repeated: true },
    { no: 2, name: "pcrs", kind: "message", T: TPMPCR, repeated: true },
    { no: 3, name: "event_log", kind: "scalar", T: 12 /* ScalarType.BYTES */ },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): TPMPlatformParameters {
    return new TPMPlatformParameters().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): TPMPlatformParameters {
    return new TPMPlatformParameters().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): TPMPlatformParameters {
    return new TPMPlatformParameters().fromJsonString(jsonString, options);
  }

  static equals(a: TPMPlatformParameters | PlainMessage<TPMPlatformParameters> | undefined, b: TPMPlatformParameters | PlainMessage<TPMPlatformParameters> | undefined): boolean {
    return proto3.util.equals(TPMPlatformParameters, a, b);
  }
}

/**
 * Holds the record of a TPM platform attestation, including the platform
 * parameters sent by the device and the nonce the server generated. This allows
 * a historical platform attestation to be revalidated and allows us to compare
 * the incoming state of a device (e.g during authentication) against the
 * historical state in order to detect potentially malicious actions.
 *
 * @generated from message teleport.devicetrust.v1.TPMPlatformAttestation
 */
export class TPMPlatformAttestation extends Message<TPMPlatformAttestation> {
  /**
   * @generated from field: bytes nonce = 1;
   */
  nonce = new Uint8Array(0);

  /**
   * @generated from field: teleport.devicetrust.v1.TPMPlatformParameters platform_parameters = 2;
   */
  platformParameters?: TPMPlatformParameters;

  constructor(data?: PartialMessage<TPMPlatformAttestation>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.devicetrust.v1.TPMPlatformAttestation";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "nonce", kind: "scalar", T: 12 /* ScalarType.BYTES */ },
    { no: 2, name: "platform_parameters", kind: "message", T: TPMPlatformParameters },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): TPMPlatformAttestation {
    return new TPMPlatformAttestation().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): TPMPlatformAttestation {
    return new TPMPlatformAttestation().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): TPMPlatformAttestation {
    return new TPMPlatformAttestation().fromJsonString(jsonString, options);
  }

  static equals(a: TPMPlatformAttestation | PlainMessage<TPMPlatformAttestation> | undefined, b: TPMPlatformAttestation | PlainMessage<TPMPlatformAttestation> | undefined): boolean {
    return proto3.util.equals(TPMPlatformAttestation, a, b);
  }
}

