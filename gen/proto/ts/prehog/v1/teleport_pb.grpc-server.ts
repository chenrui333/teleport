/* eslint-disable */
// @generated by protobuf-ts 2.9.3 with parameter long_type_number,eslint_disable,add_pb_suffix,client_grpc1,server_grpc1,ts_nocheck
// @generated from protobuf file "prehog/v1/teleport.proto" (package "prehog.v1", syntax proto3)
// tslint:disable
// @ts-nocheck
//
//
// Teleport
// Copyright (C) 2023  Gravitational, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
import { SubmitUsageReportsResponse } from "./teleport_pb";
import { SubmitUsageReportsRequest } from "./teleport_pb";
import type * as grpc from "@grpc/grpc-js";
/**
 * @generated from protobuf service prehog.v1.TeleportReportingService
 */
export interface ITeleportReportingService extends grpc.UntypedServiceImplementation {
    /**
     * encodes and forwards usage reports to the PostHog event database; each
     * event is annotated with some properties that depend on the identity of the
     * caller:
     * - tp.account_id (UUID in string form, can be empty if missing from the
     *   license)
     * - tp.license_name (should always be a UUID)
     * - tp.license_authority (name of the authority that signed the license file
     *   used for authentication)
     * - tp.is_cloud (boolean)
     *
     * @generated from protobuf rpc: SubmitUsageReports(prehog.v1.SubmitUsageReportsRequest) returns (prehog.v1.SubmitUsageReportsResponse);
     */
    submitUsageReports: grpc.handleUnaryCall<SubmitUsageReportsRequest, SubmitUsageReportsResponse>;
}
/**
 * @grpc/grpc-js definition for the protobuf service prehog.v1.TeleportReportingService.
 *
 * Usage: Implement the interface ITeleportReportingService and add to a grpc server.
 *
 * ```typescript
 * const server = new grpc.Server();
 * const service: ITeleportReportingService = ...
 * server.addService(teleportReportingServiceDefinition, service);
 * ```
 */
export const teleportReportingServiceDefinition: grpc.ServiceDefinition<ITeleportReportingService> = {
    submitUsageReports: {
        path: "/prehog.v1.TeleportReportingService/SubmitUsageReports",
        originalName: "SubmitUsageReports",
        requestStream: false,
        responseStream: false,
        responseDeserialize: bytes => SubmitUsageReportsResponse.fromBinary(bytes),
        requestDeserialize: bytes => SubmitUsageReportsRequest.fromBinary(bytes),
        responseSerialize: value => Buffer.from(SubmitUsageReportsResponse.toBinary(value)),
        requestSerialize: value => Buffer.from(SubmitUsageReportsRequest.toBinary(value))
    }
};
