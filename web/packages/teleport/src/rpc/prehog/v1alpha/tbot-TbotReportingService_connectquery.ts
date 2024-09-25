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

// @generated by protoc-gen-connect-query v1.4.2 with parameter "target=ts"
// @generated from file prehog/v1alpha/tbot.proto (package prehog.v1alpha, syntax proto3)
/* eslint-disable */
// @ts-nocheck

import { MethodKind } from "@bufbuild/protobuf";
import { SubmitTbotEventRequest, SubmitTbotEventResponse } from "./tbot_pb.js";

/**
 * @generated from rpc prehog.v1alpha.TbotReportingService.SubmitTbotEvent
 */
export const submitTbotEvent = {
  localName: "submitTbotEvent",
  name: "SubmitTbotEvent",
  kind: MethodKind.Unary,
  I: SubmitTbotEventRequest,
  O: SubmitTbotEventResponse,
  service: {
    typeName: "prehog.v1alpha.TbotReportingService"
  }
} as const;
