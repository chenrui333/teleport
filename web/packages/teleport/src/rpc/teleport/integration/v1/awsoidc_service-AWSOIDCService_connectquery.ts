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

// @generated by protoc-gen-connect-query v1.4.2 with parameter "target=ts"
// @generated from file teleport/integration/v1/awsoidc_service.proto (package teleport.integration.v1, syntax proto3)
/* eslint-disable */
// @ts-nocheck

import { MethodKind } from "@bufbuild/protobuf";
import { CreateEICERequest, CreateEICEResponse, DeployDatabaseServiceRequest, DeployDatabaseServiceResponse, DeployServiceRequest, DeployServiceResponse, EnrollEKSClustersRequest, EnrollEKSClustersResponse, ListDatabasesRequest, ListDatabasesResponse, ListEC2Request, ListEC2Response, ListEICERequest, ListEICEResponse, ListEKSClustersRequest, ListEKSClustersResponse, ListSecurityGroupsRequest, ListSecurityGroupsResponse, ListSubnetsRequest, ListSubnetsResponse, ListVPCsRequest, ListVPCsResponse, PingRequest, PingResponse } from "./awsoidc_service_pb.js";

/**
 * ListEICE returns a list of EC2 Instance Connect Endpoints.
 * An optional NextToken that can be used to fetch the next page.
 * It uses the following API:
 * https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstanceConnectEndpoints.html
 *
 * @generated from rpc teleport.integration.v1.AWSOIDCService.ListEICE
 */
export const listEICE = {
  localName: "listEICE",
  name: "ListEICE",
  kind: MethodKind.Unary,
  I: ListEICERequest,
  O: ListEICEResponse,
  service: {
    typeName: "teleport.integration.v1.AWSOIDCService"
  }
} as const;

/**
 * CreateEICE creates multiple EC2 Instance Connect Endpoint using the provided Subnets and Security Group IDs.
 * It uses the following API:
 * https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateInstanceConnectEndpoint.html
 *
 * @generated from rpc teleport.integration.v1.AWSOIDCService.CreateEICE
 */
export const createEICE = {
  localName: "createEICE",
  name: "CreateEICE",
  kind: MethodKind.Unary,
  I: CreateEICERequest,
  O: CreateEICEResponse,
  service: {
    typeName: "teleport.integration.v1.AWSOIDCService"
  }
} as const;

/**
 * ListDatabases calls the following AWS API:
 * https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBClusters.html
 * https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html
 * It returns a list of Databases and an optional NextToken that can be used to fetch the next page
 *
 * @generated from rpc teleport.integration.v1.AWSOIDCService.ListDatabases
 */
export const listDatabases = {
  localName: "listDatabases",
  name: "ListDatabases",
  kind: MethodKind.Unary,
  I: ListDatabasesRequest,
  O: ListDatabasesResponse,
  service: {
    typeName: "teleport.integration.v1.AWSOIDCService"
  }
} as const;

/**
 * ListSecurityGroups returns a list of AWS VPC SecurityGroups.
 * It uses the following API:
 * https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSecurityGroups.html
 *
 * @generated from rpc teleport.integration.v1.AWSOIDCService.ListSecurityGroups
 */
export const listSecurityGroups = {
  localName: "listSecurityGroups",
  name: "ListSecurityGroups",
  kind: MethodKind.Unary,
  I: ListSecurityGroupsRequest,
  O: ListSecurityGroupsResponse,
  service: {
    typeName: "teleport.integration.v1.AWSOIDCService"
  }
} as const;

/**
 * ListSubnets returns a list of AWS VPC subnets.
 * It uses the following API:
 * https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSubnets.html
 *
 * @generated from rpc teleport.integration.v1.AWSOIDCService.ListSubnets
 */
export const listSubnets = {
  localName: "listSubnets",
  name: "ListSubnets",
  kind: MethodKind.Unary,
  I: ListSubnetsRequest,
  O: ListSubnetsResponse,
  service: {
    typeName: "teleport.integration.v1.AWSOIDCService"
  }
} as const;

/**
 * ListVPCs returns a list of AWS VPCs.
 * It uses the following API:
 * https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVpcs.html
 *
 * @generated from rpc teleport.integration.v1.AWSOIDCService.ListVPCs
 */
export const listVPCs = {
  localName: "listVPCs",
  name: "ListVPCs",
  kind: MethodKind.Unary,
  I: ListVPCsRequest,
  O: ListVPCsResponse,
  service: {
    typeName: "teleport.integration.v1.AWSOIDCService"
  }
} as const;

/**
 * DeployDatabaseService deploys a Database Services to Amazon ECS.
 *
 * @generated from rpc teleport.integration.v1.AWSOIDCService.DeployDatabaseService
 */
export const deployDatabaseService = {
  localName: "deployDatabaseService",
  name: "DeployDatabaseService",
  kind: MethodKind.Unary,
  I: DeployDatabaseServiceRequest,
  O: DeployDatabaseServiceResponse,
  service: {
    typeName: "teleport.integration.v1.AWSOIDCService"
  }
} as const;

/**
 * DeployService deploys an ECS Service to Amazon ECS.
 *
 * @generated from rpc teleport.integration.v1.AWSOIDCService.DeployService
 */
export const deployService = {
  localName: "deployService",
  name: "DeployService",
  kind: MethodKind.Unary,
  I: DeployServiceRequest,
  O: DeployServiceResponse,
  service: {
    typeName: "teleport.integration.v1.AWSOIDCService"
  }
} as const;

/**
 * EnrollEKSClusters enrolls EKS clusters by installing kube agent Helm chart.
 *
 * @generated from rpc teleport.integration.v1.AWSOIDCService.EnrollEKSClusters
 */
export const enrollEKSClusters = {
  localName: "enrollEKSClusters",
  name: "EnrollEKSClusters",
  kind: MethodKind.Unary,
  I: EnrollEKSClustersRequest,
  O: EnrollEKSClustersResponse,
  service: {
    typeName: "teleport.integration.v1.AWSOIDCService"
  }
} as const;

/**
 * ListEC2 lists the EC2 instances of the AWS account per region.
 * It uses the following API:
 * https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html
 *
 * @generated from rpc teleport.integration.v1.AWSOIDCService.ListEC2
 */
export const listEC2 = {
  localName: "listEC2",
  name: "ListEC2",
  kind: MethodKind.Unary,
  I: ListEC2Request,
  O: ListEC2Response,
  service: {
    typeName: "teleport.integration.v1.AWSOIDCService"
  }
} as const;

/**
 * ListEKSClusters retrieves a paginated list of EKS clusters in the specified AWS region for a specific account.
 * It uses the following APIs:
 * https://docs.aws.amazon.com/eks/latest/APIReference/API_ListClusters.html
 * https://docs.aws.amazon.com/eks/latest/APIReference/API_DescribeCluster.html
 *
 * @generated from rpc teleport.integration.v1.AWSOIDCService.ListEKSClusters
 */
export const listEKSClusters = {
  localName: "listEKSClusters",
  name: "ListEKSClusters",
  kind: MethodKind.Unary,
  I: ListEKSClustersRequest,
  O: ListEKSClustersResponse,
  service: {
    typeName: "teleport.integration.v1.AWSOIDCService"
  }
} as const;

/**
 * Ping does an health check for the integration.
 * Returns the caller identity.
 * It uses the following APIs:
 * https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
 *
 * @generated from rpc teleport.integration.v1.AWSOIDCService.Ping
 */
export const ping = {
  localName: "ping",
  name: "Ping",
  kind: MethodKind.Unary,
  I: PingRequest,
  O: PingResponse,
  service: {
    typeName: "teleport.integration.v1.AWSOIDCService"
  }
} as const;
