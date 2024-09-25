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
// @generated from file teleport/legacy/client/proto/event.proto (package proto, syntax proto3)
/* eslint-disable */
// @ts-nocheck

import type { BinaryReadOptions, FieldList, JsonReadOptions, JsonValue, PartialMessage, PlainMessage } from "@bufbuild/protobuf";
import { Message, proto3 } from "@bufbuild/protobuf";
import { AccessRequestV3, AppServerV3, AppV3, AuthPreferenceV2, CertAuthorityV2, ClusterAuditConfigV2, ClusterNameV2, ClusterNetworkingConfigV2, DatabaseServerV3, DatabaseServiceV1, DatabaseV3, HeadlessAuthentication, InstallerV1, IntegrationV1, KubernetesClusterV3, KubernetesServerV3, LockV2, Namespace, NetworkRestrictionsV4, OktaAssignmentV1, OktaImportRuleV1, ProvisionTokenV2, RemoteClusterV3, ResourceHeader, ReverseTunnelV2, RoleV6, SAMLIdPServiceProviderV1, ServerV2, SessionRecordingConfigV2, StaticTokensV2, TunnelConnectionV2, UIConfigV1, UserGroupV1, UserV2, WatchStatusV1, WebSessionV2, WebTokenV3, WindowsDesktopServiceV3, WindowsDesktopV3 } from "../../types/types_pb.js";
import { AccessList, Member, Review } from "../../../accesslist/v1/accesslist_pb.js";
import { UserLoginState } from "../../../userloginstate/v1/userloginstate_pb.js";
import { DiscoveryConfig } from "../../../discoveryconfig/v1/discoveryconfig_pb.js";
import { AuditQuery, Report, ReportState } from "../../../secreports/v1/secreports_pb.js";
import { AccessMonitoringRule } from "../../../accessmonitoringrules/v1/access_monitoring_rules_pb.js";
import { KubernetesWaitingContainer } from "../../../kubewaitingcontainer/v1/kubewaitingcontainer_pb.js";
import { GlobalNotification, Notification } from "../../../notifications/v1/notifications_pb.js";
import { CrownJewel } from "../../../crownjewel/v1/crownjewel_pb.js";
import { DatabaseObject } from "../../../dbobject/v1/dbobject_pb.js";
import { BotInstance } from "../../../machineid/v1/bot_instance_pb.js";
import { AccessGraphSettings } from "../../../clusterconfig/v1/access_graph_settings_pb.js";
import { SPIFFEFederation } from "../../../machineid/v1/federation_pb.js";
import { AutoUpdateConfig, AutoUpdateVersion } from "../../../autoupdate/v1/autoupdate_pb.js";
import { StaticHostUser } from "../../../userprovisioning/v2/statichostuser_pb.js";
import { UserTask } from "../../../usertasks/v1/user_tasks_pb.js";

/**
 * Operation identifies type of operation
 *
 * @generated from enum proto.Operation
 */
export enum Operation {
  /**
   * INIT is sent as a first sentinel event
   * on the watch channel
   *
   * @generated from enum value: INIT = 0;
   */
  INIT = 0,

  /**
   * PUT identifies created or updated object
   *
   * @generated from enum value: PUT = 1;
   */
  PUT = 1,

  /**
   * DELETE identifies deleted object
   *
   * @generated from enum value: DELETE = 2;
   */
  DELETE = 2,
}
// Retrieve enum metadata with: proto3.getEnumType(Operation)
proto3.util.setEnumType(Operation, "proto.Operation", [
  { no: 0, name: "INIT" },
  { no: 1, name: "PUT" },
  { no: 2, name: "DELETE" },
]);

/**
 * Event returns cluster event
 *
 * @generated from message proto.Event
 */
export class Event extends Message<Event> {
  /**
   * Operation identifies operation
   *
   * @generated from field: proto.Operation Type = 1;
   */
  Type = Operation.INIT;

  /**
   * Resource contains the updated resource
   *
   * @generated from oneof proto.Event.Resource
   */
  Resource: {
    /**
     * ResourceHeader is specified in delete events,
     * the full object is not available, so resource
     * header is used to provide information about object type
     *
     * @generated from field: types.ResourceHeader ResourceHeader = 2;
     */
    value: ResourceHeader;
    case: "ResourceHeader";
  } | {
    /**
     * CertAuthority is filled in certificate-authority related events
     *
     * @generated from field: types.CertAuthorityV2 CertAuthority = 3;
     */
    value: CertAuthorityV2;
    case: "CertAuthority";
  } | {
    /**
     * StaticTokens is filled in static-tokens related events
     *
     * @generated from field: types.StaticTokensV2 StaticTokens = 4;
     */
    value: StaticTokensV2;
    case: "StaticTokens";
  } | {
    /**
     * ProvisionToken is filled in provision-token related events
     *
     * @generated from field: types.ProvisionTokenV2 ProvisionToken = 5;
     */
    value: ProvisionTokenV2;
    case: "ProvisionToken";
  } | {
    /**
     * ClusterNameV2 is a cluster name resource
     *
     * @generated from field: types.ClusterNameV2 ClusterName = 6;
     */
    value: ClusterNameV2;
    case: "ClusterName";
  } | {
    /**
     * User is a user resource
     *
     * @generated from field: types.UserV2 User = 8;
     */
    value: UserV2;
    case: "User";
  } | {
    /**
     * Role is a role resource
     *
     * @generated from field: types.RoleV6 Role = 9;
     */
    value: RoleV6;
    case: "Role";
  } | {
    /**
     * Namespace is a namespace resource
     *
     * @generated from field: types.Namespace Namespace = 10;
     */
    value: Namespace;
    case: "Namespace";
  } | {
    /**
     * Server is a node or proxy resource
     *
     * @generated from field: types.ServerV2 Server = 11;
     */
    value: ServerV2;
    case: "Server";
  } | {
    /**
     * ReverseTunnel is a resource with reverse tunnel
     *
     * @generated from field: types.ReverseTunnelV2 ReverseTunnel = 12;
     */
    value: ReverseTunnelV2;
    case: "ReverseTunnel";
  } | {
    /**
     * TunnelConnection is a resource for tunnel connnections
     *
     * @generated from field: types.TunnelConnectionV2 TunnelConnection = 13;
     */
    value: TunnelConnectionV2;
    case: "TunnelConnection";
  } | {
    /**
     * AccessRequest is a resource for access requests
     *
     * @generated from field: types.AccessRequestV3 AccessRequest = 14;
     */
    value: AccessRequestV3;
    case: "AccessRequest";
  } | {
    /**
     * AppSession is an application web session.
     *
     * @generated from field: types.WebSessionV2 AppSession = 15;
     */
    value: WebSessionV2;
    case: "AppSession";
  } | {
    /**
     * RemoteCluster is a resource for remote clusters
     *
     * @generated from field: types.RemoteClusterV3 RemoteCluster = 16;
     */
    value: RemoteClusterV3;
    case: "RemoteCluster";
  } | {
    /**
     * DatabaseServer is a resource for database servers.
     *
     * @generated from field: types.DatabaseServerV3 DatabaseServer = 17;
     */
    value: DatabaseServerV3;
    case: "DatabaseServer";
  } | {
    /**
     * WebSession is a regular web session.
     *
     * @generated from field: types.WebSessionV2 WebSession = 18;
     */
    value: WebSessionV2;
    case: "WebSession";
  } | {
    /**
     * WebToken is a web token.
     *
     * @generated from field: types.WebTokenV3 WebToken = 19;
     */
    value: WebTokenV3;
    case: "WebToken";
  } | {
    /**
     * ClusterNetworkingConfig is a resource for cluster networking configuration.
     *
     * @generated from field: types.ClusterNetworkingConfigV2 ClusterNetworkingConfig = 20;
     */
    value: ClusterNetworkingConfigV2;
    case: "ClusterNetworkingConfig";
  } | {
    /**
     * SessionRecordingConfig is a resource for session recording configuration.
     *
     * @generated from field: types.SessionRecordingConfigV2 SessionRecordingConfig = 21;
     */
    value: SessionRecordingConfigV2;
    case: "SessionRecordingConfig";
  } | {
    /**
     * AuthPreference is cluster auth preference.
     *
     * @generated from field: types.AuthPreferenceV2 AuthPreference = 22;
     */
    value: AuthPreferenceV2;
    case: "AuthPreference";
  } | {
    /**
     * ClusterAuditConfig is a resource for cluster audit configuration.
     *
     * @generated from field: types.ClusterAuditConfigV2 ClusterAuditConfig = 23;
     */
    value: ClusterAuditConfigV2;
    case: "ClusterAuditConfig";
  } | {
    /**
     * Lock is a lock resource.
     *
     * @generated from field: types.LockV2 Lock = 24;
     */
    value: LockV2;
    case: "Lock";
  } | {
    /**
     * NetworkRestrictions is a resource for network restrictions
     *
     * @generated from field: types.NetworkRestrictionsV4 NetworkRestrictions = 25;
     */
    value: NetworkRestrictionsV4;
    case: "NetworkRestrictions";
  } | {
    /**
     * WindowsDesktopService is a resource for Windows desktop services.
     *
     * @generated from field: types.WindowsDesktopServiceV3 WindowsDesktopService = 26;
     */
    value: WindowsDesktopServiceV3;
    case: "WindowsDesktopService";
  } | {
    /**
     * WindowsDesktop is a resource for Windows desktop host.
     *
     * @generated from field: types.WindowsDesktopV3 WindowsDesktop = 27;
     */
    value: WindowsDesktopV3;
    case: "WindowsDesktop";
  } | {
    /**
     * Database is a database resource.
     *
     * @generated from field: types.DatabaseV3 Database = 28;
     */
    value: DatabaseV3;
    case: "Database";
  } | {
    /**
     * AppServer is an application server resource.
     *
     * @generated from field: types.AppServerV3 AppServer = 29;
     */
    value: AppServerV3;
    case: "AppServer";
  } | {
    /**
     * App is an application resource.
     *
     * @generated from field: types.AppV3 App = 30;
     */
    value: AppV3;
    case: "App";
  } | {
    /**
     * SnowflakeSession is a Snowflake web session.
     *
     * @generated from field: types.WebSessionV2 SnowflakeSession = 31;
     */
    value: WebSessionV2;
    case: "SnowflakeSession";
  } | {
    /**
     * KubernetesServer is an Kubernetes server resource.
     *
     * @generated from field: types.KubernetesServerV3 KubernetesServer = 32;
     */
    value: KubernetesServerV3;
    case: "KubernetesServer";
  } | {
    /**
     * KubernetesCluster is an Kubernetes cluster resource.
     *
     * @generated from field: types.KubernetesClusterV3 KubernetesCluster = 33;
     */
    value: KubernetesClusterV3;
    case: "KubernetesCluster";
  } | {
    /**
     * Installer is an installer resource
     *
     * @generated from field: types.InstallerV1 Installer = 34;
     */
    value: InstallerV1;
    case: "Installer";
  } | {
    /**
     * DatabaseService is a DatabaseService resource
     *
     * @generated from field: types.DatabaseServiceV1 DatabaseService = 35;
     */
    value: DatabaseServiceV1;
    case: "DatabaseService";
  } | {
    /**
     * SAMLIdPServiceProvider is a SAMLIdPServiceProvider resource
     *
     * @generated from field: types.SAMLIdPServiceProviderV1 SAMLIdPServiceProvider = 36;
     */
    value: SAMLIdPServiceProviderV1;
    case: "SAMLIdPServiceProvider";
  } | {
    /**
     * SAMLIdPSession is a SAML IdP session.
     *
     * @generated from field: types.WebSessionV2 SAMLIdPSession = 37;
     */
    value: WebSessionV2;
    case: "SAMLIdPSession";
  } | {
    /**
     * UserGroup is a UserGroup resource
     *
     * @generated from field: types.UserGroupV1 UserGroup = 38;
     */
    value: UserGroupV1;
    case: "UserGroup";
  } | {
    /**
     * UIConfig provides a way for users to adjust settings of the UI served by the proxy service.
     *
     * @generated from field: types.UIConfigV1 UIConfig = 39;
     */
    value: UIConfigV1;
    case: "UIConfig";
  } | {
    /**
     * OktaImportRule is an OktaImportRule resource.
     *
     * @generated from field: types.OktaImportRuleV1 OktaImportRule = 40;
     */
    value: OktaImportRuleV1;
    case: "OktaImportRule";
  } | {
    /**
     * OktaAssignment is an OktaAssignment resource.
     *
     * @generated from field: types.OktaAssignmentV1 OktaAssignment = 41;
     */
    value: OktaAssignmentV1;
    case: "OktaAssignment";
  } | {
    /**
     * Integration is an Integration resource.
     *
     * @generated from field: types.IntegrationV1 Integration = 42;
     */
    value: IntegrationV1;
    case: "Integration";
  } | {
    /**
     * WatchStatus is an WatchStatus resource.
     *
     * @generated from field: types.WatchStatusV1 WatchStatus = 43;
     */
    value: WatchStatusV1;
    case: "WatchStatus";
  } | {
    /**
     * HeadlessAuthentication is a HeadlessAuthentication resource.
     *
     * @generated from field: types.HeadlessAuthentication HeadlessAuthentication = 44;
     */
    value: HeadlessAuthentication;
    case: "HeadlessAuthentication";
  } | {
    /**
     * AccessList is an AccessList resource.
     *
     * @generated from field: teleport.accesslist.v1.AccessList AccessList = 45;
     */
    value: AccessList;
    case: "AccessList";
  } | {
    /**
     * UserLoginState is a UserLoginState resource.
     *
     * @generated from field: teleport.userloginstate.v1.UserLoginState UserLoginState = 46;
     */
    value: UserLoginState;
    case: "UserLoginState";
  } | {
    /**
     * AccessListMember is an access list member resource.
     *
     * @generated from field: teleport.accesslist.v1.Member AccessListMember = 47;
     */
    value: Member;
    case: "AccessListMember";
  } | {
    /**
     * DiscoveryConfig contains a list of matchers to be loaded dynamically by Discovery Services.
     *
     * @generated from field: teleport.discoveryconfig.v1.DiscoveryConfig DiscoveryConfig = 48;
     */
    value: DiscoveryConfig;
    case: "DiscoveryConfig";
  } | {
    /**
     * AuditQuery is an audit query resource.
     *
     * @generated from field: teleport.secreports.v1.AuditQuery AuditQuery = 50;
     */
    value: AuditQuery;
    case: "AuditQuery";
  } | {
    /**
     * SecurityReport is a security report resource.
     *
     * @generated from field: teleport.secreports.v1.Report Report = 51;
     */
    value: Report;
    case: "Report";
  } | {
    /**
     * SecurityReportState is a security report state resource.
     *
     * @generated from field: teleport.secreports.v1.ReportState ReportState = 52;
     */
    value: ReportState;
    case: "ReportState";
  } | {
    /**
     * AccessListReview is an access list review resource.
     *
     * @generated from field: teleport.accesslist.v1.Review AccessListReview = 53;
     */
    value: Review;
    case: "AccessListReview";
  } | {
    /**
     * AccessMonitoringRule is an access monitoring rule resource.
     *
     * @generated from field: teleport.accessmonitoringrules.v1.AccessMonitoringRule AccessMonitoringRule = 54;
     */
    value: AccessMonitoringRule;
    case: "AccessMonitoringRule";
  } | {
    /**
     * KubernetesWaitingContainer is a Kubernetes ephemeral container
     * waiting to be created.
     *
     * @generated from field: teleport.kubewaitingcontainer.v1.KubernetesWaitingContainer KubernetesWaitingContainer = 55;
     */
    value: KubernetesWaitingContainer;
    case: "KubernetesWaitingContainer";
  } | {
    /**
     * UserNotification is a user notification resource.
     *
     * @generated from field: teleport.notifications.v1.Notification UserNotification = 56;
     */
    value: Notification;
    case: "UserNotification";
  } | {
    /**
     * GlobalNotification is a global notification resource.
     *
     * @generated from field: teleport.notifications.v1.GlobalNotification GlobalNotification = 57;
     */
    value: GlobalNotification;
    case: "GlobalNotification";
  } | {
    /**
     * CrownJewel is a Crown Jewel resource.
     *
     * @generated from field: teleport.crownjewel.v1.CrownJewel CrownJewel = 58;
     */
    value: CrownJewel;
    case: "CrownJewel";
  } | {
    /**
     * DatabaseObject is a database object resource.
     *
     * @generated from field: teleport.dbobject.v1.DatabaseObject DatabaseObject = 59;
     */
    value: DatabaseObject;
    case: "DatabaseObject";
  } | {
    /**
     * BotInstance is a Machine ID bot instance.
     *
     * @generated from field: teleport.machineid.v1.BotInstance BotInstance = 60;
     */
    value: BotInstance;
    case: "BotInstance";
  } | {
    /**
     * AccessGraphSettings is a resource for access graph settings.
     *
     * @generated from field: teleport.clusterconfig.v1.AccessGraphSettings AccessGraphSettings = 61;
     */
    value: AccessGraphSettings;
    case: "AccessGraphSettings";
  } | {
    /**
     * SPIFFEFederation is a resource for SPIFFE federation.
     *
     * @generated from field: teleport.machineid.v1.SPIFFEFederation SPIFFEFederation = 62;
     */
    value: SPIFFEFederation;
    case: "SPIFFEFederation";
  } | {
    /**
     * AutoUpdateConfig is a resource for autoupdate config.
     *
     * @generated from field: teleport.autoupdate.v1.AutoUpdateConfig AutoUpdateConfig = 64;
     */
    value: AutoUpdateConfig;
    case: "AutoUpdateConfig";
  } | {
    /**
     * AutoUpdateVersion is a resource for autoupdate version.
     *
     * @generated from field: teleport.autoupdate.v1.AutoUpdateVersion AutoUpdateVersion = 65;
     */
    value: AutoUpdateVersion;
    case: "AutoUpdateVersion";
  } | {
    /**
     * StaticHostUserV2 is a resource for static host users.
     *
     * @generated from field: teleport.userprovisioning.v2.StaticHostUser StaticHostUserV2 = 66;
     */
    value: StaticHostUser;
    case: "StaticHostUserV2";
  } | {
    /**
     * UsernTask is a resource for user task.
     *
     * @generated from field: teleport.usertasks.v1.UserTask UserTask = 67;
     */
    value: UserTask;
    case: "UserTask";
  } | { case: undefined; value?: undefined } = { case: undefined };

  constructor(data?: PartialMessage<Event>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "proto.Event";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "Type", kind: "enum", T: proto3.getEnumType(Operation) },
    { no: 2, name: "ResourceHeader", kind: "message", T: ResourceHeader, oneof: "Resource" },
    { no: 3, name: "CertAuthority", kind: "message", T: CertAuthorityV2, oneof: "Resource" },
    { no: 4, name: "StaticTokens", kind: "message", T: StaticTokensV2, oneof: "Resource" },
    { no: 5, name: "ProvisionToken", kind: "message", T: ProvisionTokenV2, oneof: "Resource" },
    { no: 6, name: "ClusterName", kind: "message", T: ClusterNameV2, oneof: "Resource" },
    { no: 8, name: "User", kind: "message", T: UserV2, oneof: "Resource" },
    { no: 9, name: "Role", kind: "message", T: RoleV6, oneof: "Resource" },
    { no: 10, name: "Namespace", kind: "message", T: Namespace, oneof: "Resource" },
    { no: 11, name: "Server", kind: "message", T: ServerV2, oneof: "Resource" },
    { no: 12, name: "ReverseTunnel", kind: "message", T: ReverseTunnelV2, oneof: "Resource" },
    { no: 13, name: "TunnelConnection", kind: "message", T: TunnelConnectionV2, oneof: "Resource" },
    { no: 14, name: "AccessRequest", kind: "message", T: AccessRequestV3, oneof: "Resource" },
    { no: 15, name: "AppSession", kind: "message", T: WebSessionV2, oneof: "Resource" },
    { no: 16, name: "RemoteCluster", kind: "message", T: RemoteClusterV3, oneof: "Resource" },
    { no: 17, name: "DatabaseServer", kind: "message", T: DatabaseServerV3, oneof: "Resource" },
    { no: 18, name: "WebSession", kind: "message", T: WebSessionV2, oneof: "Resource" },
    { no: 19, name: "WebToken", kind: "message", T: WebTokenV3, oneof: "Resource" },
    { no: 20, name: "ClusterNetworkingConfig", kind: "message", T: ClusterNetworkingConfigV2, oneof: "Resource" },
    { no: 21, name: "SessionRecordingConfig", kind: "message", T: SessionRecordingConfigV2, oneof: "Resource" },
    { no: 22, name: "AuthPreference", kind: "message", T: AuthPreferenceV2, oneof: "Resource" },
    { no: 23, name: "ClusterAuditConfig", kind: "message", T: ClusterAuditConfigV2, oneof: "Resource" },
    { no: 24, name: "Lock", kind: "message", T: LockV2, oneof: "Resource" },
    { no: 25, name: "NetworkRestrictions", kind: "message", T: NetworkRestrictionsV4, oneof: "Resource" },
    { no: 26, name: "WindowsDesktopService", kind: "message", T: WindowsDesktopServiceV3, oneof: "Resource" },
    { no: 27, name: "WindowsDesktop", kind: "message", T: WindowsDesktopV3, oneof: "Resource" },
    { no: 28, name: "Database", kind: "message", T: DatabaseV3, oneof: "Resource" },
    { no: 29, name: "AppServer", kind: "message", T: AppServerV3, oneof: "Resource" },
    { no: 30, name: "App", kind: "message", T: AppV3, oneof: "Resource" },
    { no: 31, name: "SnowflakeSession", kind: "message", T: WebSessionV2, oneof: "Resource" },
    { no: 32, name: "KubernetesServer", kind: "message", T: KubernetesServerV3, oneof: "Resource" },
    { no: 33, name: "KubernetesCluster", kind: "message", T: KubernetesClusterV3, oneof: "Resource" },
    { no: 34, name: "Installer", kind: "message", T: InstallerV1, oneof: "Resource" },
    { no: 35, name: "DatabaseService", kind: "message", T: DatabaseServiceV1, oneof: "Resource" },
    { no: 36, name: "SAMLIdPServiceProvider", kind: "message", T: SAMLIdPServiceProviderV1, oneof: "Resource" },
    { no: 37, name: "SAMLIdPSession", kind: "message", T: WebSessionV2, oneof: "Resource" },
    { no: 38, name: "UserGroup", kind: "message", T: UserGroupV1, oneof: "Resource" },
    { no: 39, name: "UIConfig", kind: "message", T: UIConfigV1, oneof: "Resource" },
    { no: 40, name: "OktaImportRule", kind: "message", T: OktaImportRuleV1, oneof: "Resource" },
    { no: 41, name: "OktaAssignment", kind: "message", T: OktaAssignmentV1, oneof: "Resource" },
    { no: 42, name: "Integration", kind: "message", T: IntegrationV1, oneof: "Resource" },
    { no: 43, name: "WatchStatus", kind: "message", T: WatchStatusV1, oneof: "Resource" },
    { no: 44, name: "HeadlessAuthentication", kind: "message", T: HeadlessAuthentication, oneof: "Resource" },
    { no: 45, name: "AccessList", kind: "message", T: AccessList, oneof: "Resource" },
    { no: 46, name: "UserLoginState", kind: "message", T: UserLoginState, oneof: "Resource" },
    { no: 47, name: "AccessListMember", kind: "message", T: Member, oneof: "Resource" },
    { no: 48, name: "DiscoveryConfig", kind: "message", T: DiscoveryConfig, oneof: "Resource" },
    { no: 50, name: "AuditQuery", kind: "message", T: AuditQuery, oneof: "Resource" },
    { no: 51, name: "Report", kind: "message", T: Report, oneof: "Resource" },
    { no: 52, name: "ReportState", kind: "message", T: ReportState, oneof: "Resource" },
    { no: 53, name: "AccessListReview", kind: "message", T: Review, oneof: "Resource" },
    { no: 54, name: "AccessMonitoringRule", kind: "message", T: AccessMonitoringRule, oneof: "Resource" },
    { no: 55, name: "KubernetesWaitingContainer", kind: "message", T: KubernetesWaitingContainer, oneof: "Resource" },
    { no: 56, name: "UserNotification", kind: "message", T: Notification, oneof: "Resource" },
    { no: 57, name: "GlobalNotification", kind: "message", T: GlobalNotification, oneof: "Resource" },
    { no: 58, name: "CrownJewel", kind: "message", T: CrownJewel, oneof: "Resource" },
    { no: 59, name: "DatabaseObject", kind: "message", T: DatabaseObject, oneof: "Resource" },
    { no: 60, name: "BotInstance", kind: "message", T: BotInstance, oneof: "Resource" },
    { no: 61, name: "AccessGraphSettings", kind: "message", T: AccessGraphSettings, oneof: "Resource" },
    { no: 62, name: "SPIFFEFederation", kind: "message", T: SPIFFEFederation, oneof: "Resource" },
    { no: 64, name: "AutoUpdateConfig", kind: "message", T: AutoUpdateConfig, oneof: "Resource" },
    { no: 65, name: "AutoUpdateVersion", kind: "message", T: AutoUpdateVersion, oneof: "Resource" },
    { no: 66, name: "StaticHostUserV2", kind: "message", T: StaticHostUser, oneof: "Resource" },
    { no: 67, name: "UserTask", kind: "message", T: UserTask, oneof: "Resource" },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): Event {
    return new Event().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): Event {
    return new Event().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): Event {
    return new Event().fromJsonString(jsonString, options);
  }

  static equals(a: Event | PlainMessage<Event> | undefined, b: Event | PlainMessage<Event> | undefined): boolean {
    return proto3.util.equals(Event, a, b);
  }
}

