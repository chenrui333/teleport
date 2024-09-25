//
// Teleport
// Copyright (C) 2024  Gravitational, Inc.
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

// @generated by protoc-gen-es v1.10.0 with parameter "target=ts"
// @generated from file teleport/notifications/v1/notifications.proto (package teleport.notifications.v1, syntax proto3)
/* eslint-disable */
// @ts-nocheck

import type { BinaryReadOptions, FieldList, JsonReadOptions, JsonValue, PartialMessage, PlainMessage } from "@bufbuild/protobuf";
import { Message, proto3, Timestamp } from "@bufbuild/protobuf";
import { Metadata } from "../../header/v1/metadata_pb.js";
import { RoleConditions } from "../../legacy/types/types_pb.js";

/**
 * NotificationState the state of a notification for a user. This can represent either "clicked" or "dismissed".
 *
 * @generated from enum teleport.notifications.v1.NotificationState
 */
export enum NotificationState {
  /**
   * @generated from enum value: NOTIFICATION_STATE_UNSPECIFIED = 0;
   */
  UNSPECIFIED = 0,

  /**
   * NOTIFICATION_STATE_CLICKED marks this notification as having been clicked on by the user.
   *
   * @generated from enum value: NOTIFICATION_STATE_CLICKED = 1;
   */
  CLICKED = 1,

  /**
   * NOTIFICATION_STATE_DISMISSED marks this notification as having been dismissed by the user.
   *
   * @generated from enum value: NOTIFICATION_STATE_DISMISSED = 2;
   */
  DISMISSED = 2,
}
// Retrieve enum metadata with: proto3.getEnumType(NotificationState)
proto3.util.setEnumType(NotificationState, "teleport.notifications.v1.NotificationState", [
  { no: 0, name: "NOTIFICATION_STATE_UNSPECIFIED" },
  { no: 1, name: "NOTIFICATION_STATE_CLICKED" },
  { no: 2, name: "NOTIFICATION_STATE_DISMISSED" },
]);

/**
 * Notification represents a notification item.
 *
 * @generated from message teleport.notifications.v1.Notification
 */
export class Notification extends Message<Notification> {
  /**
   * kind is the resource kind ("notification").
   *
   * @generated from field: string kind = 1;
   */
  kind = "";

  /**
   * sub_kind represents the unique kind of notification this is, eg. `access-request-approved`
   *
   * @generated from field: string sub_kind = 2;
   */
  subKind = "";

  /**
   * version is the resource version.
   *
   * @generated from field: string version = 3;
   */
  version = "";

  /**
   * metadata is the notification's metadata. This contains the notification's labels, and expiry. All custom notification metadata should be stored in labels.
   *
   * @generated from field: teleport.header.v1.Metadata metadata = 4;
   */
  metadata?: Metadata;

  /**
   * spec is the notification specification.
   *
   * @generated from field: teleport.notifications.v1.NotificationSpec spec = 5;
   */
  spec?: NotificationSpec;

  constructor(data?: PartialMessage<Notification>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.notifications.v1.Notification";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "kind", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 2, name: "sub_kind", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 3, name: "version", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 4, name: "metadata", kind: "message", T: Metadata },
    { no: 5, name: "spec", kind: "message", T: NotificationSpec },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): Notification {
    return new Notification().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): Notification {
    return new Notification().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): Notification {
    return new Notification().fromJsonString(jsonString, options);
  }

  static equals(a: Notification | PlainMessage<Notification> | undefined, b: Notification | PlainMessage<Notification> | undefined): boolean {
    return proto3.util.equals(Notification, a, b);
  }
}

/**
 * NotificationSpec is the notification specification.
 *
 * @generated from message teleport.notifications.v1.NotificationSpec
 */
export class NotificationSpec extends Message<NotificationSpec> {
  /**
   * created is when the notification was created, in UNIX time.
   *
   * @generated from field: google.protobuf.Timestamp created = 2;
   */
  created?: Timestamp;

  /**
   * unscoped is whether the notification shouldn't be restricted to a specific audience. This is to prevent the potential future possibility that a user-specific notification contains information that the user should no longer be allowed to see. Default is true.
   *
   * @generated from field: bool unscoped = 3;
   */
  unscoped = false;

  /**
   * username is the username of the target user if this is a user-specific notification. Requests for global notifications with a username will be rejected.
   *
   * @generated from field: string username = 4;
   */
  username = "";

  constructor(data?: PartialMessage<NotificationSpec>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.notifications.v1.NotificationSpec";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 2, name: "created", kind: "message", T: Timestamp },
    { no: 3, name: "unscoped", kind: "scalar", T: 8 /* ScalarType.BOOL */ },
    { no: 4, name: "username", kind: "scalar", T: 9 /* ScalarType.STRING */ },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): NotificationSpec {
    return new NotificationSpec().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): NotificationSpec {
    return new NotificationSpec().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): NotificationSpec {
    return new NotificationSpec().fromJsonString(jsonString, options);
  }

  static equals(a: NotificationSpec | PlainMessage<NotificationSpec> | undefined, b: NotificationSpec | PlainMessage<NotificationSpec> | undefined): boolean {
    return proto3.util.equals(NotificationSpec, a, b);
  }
}

/**
 * GlobalNotification represents a global notification.
 *
 * @generated from message teleport.notifications.v1.GlobalNotification
 */
export class GlobalNotification extends Message<GlobalNotification> {
  /**
   * kind is the resource kind ("global_notification").
   *
   * @generated from field: string kind = 1;
   */
  kind = "";

  /**
   * sub_kind is the optional resource subkind. This is unused.
   *
   * @generated from field: string sub_kind = 2;
   */
  subKind = "";

  /**
   * version is the resource version.
   *
   * @generated from field: string version = 3;
   */
  version = "";

  /**
   * metadata is the user last seen notification object's metadata.
   *
   * @generated from field: teleport.header.v1.Metadata metadata = 4;
   */
  metadata?: Metadata;

  /**
   * spec is the global notification's specification.
   *
   * @generated from field: teleport.notifications.v1.GlobalNotificationSpec spec = 5;
   */
  spec?: GlobalNotificationSpec;

  constructor(data?: PartialMessage<GlobalNotification>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.notifications.v1.GlobalNotification";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "kind", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 2, name: "sub_kind", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 3, name: "version", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 4, name: "metadata", kind: "message", T: Metadata },
    { no: 5, name: "spec", kind: "message", T: GlobalNotificationSpec },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): GlobalNotification {
    return new GlobalNotification().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): GlobalNotification {
    return new GlobalNotification().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): GlobalNotification {
    return new GlobalNotification().fromJsonString(jsonString, options);
  }

  static equals(a: GlobalNotification | PlainMessage<GlobalNotification> | undefined, b: GlobalNotification | PlainMessage<GlobalNotification> | undefined): boolean {
    return proto3.util.equals(GlobalNotification, a, b);
  }
}

/**
 * GlobalNotificationSpec is the global notification's specification.
 *
 * @generated from message teleport.notifications.v1.GlobalNotificationSpec
 */
export class GlobalNotificationSpec extends Message<GlobalNotificationSpec> {
  /**
   * Matcher for determining the target of this notification.
   *
   * @generated from oneof teleport.notifications.v1.GlobalNotificationSpec.matcher
   */
  matcher: {
    /**
     * by_permissions represents the RoleConditions needed for a user to receive this notification.
     * If multiple permissions are defined and `MatchAllConditions` is true, the user will need to have
     * all of them to receive this notification.
     *
     * @generated from field: teleport.notifications.v1.ByPermissions by_permissions = 1;
     */
    value: ByPermissions;
    case: "byPermissions";
  } | {
    /**
     * by_roles represents the roles targeted by this notification.
     * If multiple roles are defined and `MatchAllConditions` is true, the user will need to have all
     * of them to receive this notification.
     *
     * @generated from field: teleport.notifications.v1.ByRoles by_roles = 2;
     */
    value: ByRoles;
    case: "byRoles";
  } | {
    /**
     * all represents whether to target all users, regardless of roles or permissions.
     *
     * @generated from field: bool all = 3;
     */
    value: boolean;
    case: "all";
  } | { case: undefined; value?: undefined } = { case: undefined };

  /**
   * match_all_conditions is whether or not all the conditions specified by the matcher must be met,
   * if false, only one of the conditions needs to be met.
   *
   * @generated from field: bool match_all_conditions = 4;
   */
  matchAllConditions = false;

  /**
   * notification is the notification itself.
   *
   * @generated from field: teleport.notifications.v1.Notification notification = 5;
   */
  notification?: Notification;

  constructor(data?: PartialMessage<GlobalNotificationSpec>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.notifications.v1.GlobalNotificationSpec";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "by_permissions", kind: "message", T: ByPermissions, oneof: "matcher" },
    { no: 2, name: "by_roles", kind: "message", T: ByRoles, oneof: "matcher" },
    { no: 3, name: "all", kind: "scalar", T: 8 /* ScalarType.BOOL */, oneof: "matcher" },
    { no: 4, name: "match_all_conditions", kind: "scalar", T: 8 /* ScalarType.BOOL */ },
    { no: 5, name: "notification", kind: "message", T: Notification },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): GlobalNotificationSpec {
    return new GlobalNotificationSpec().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): GlobalNotificationSpec {
    return new GlobalNotificationSpec().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): GlobalNotificationSpec {
    return new GlobalNotificationSpec().fromJsonString(jsonString, options);
  }

  static equals(a: GlobalNotificationSpec | PlainMessage<GlobalNotificationSpec> | undefined, b: GlobalNotificationSpec | PlainMessage<GlobalNotificationSpec> | undefined): boolean {
    return proto3.util.equals(GlobalNotificationSpec, a, b);
  }
}

/**
 * ByPermissions represents the RoleConditions needed for a user to receive this notification.
 *
 * @generated from message teleport.notifications.v1.ByPermissions
 */
export class ByPermissions extends Message<ByPermissions> {
  /**
   * @generated from field: repeated types.RoleConditions role_conditions = 1;
   */
  roleConditions: RoleConditions[] = [];

  constructor(data?: PartialMessage<ByPermissions>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.notifications.v1.ByPermissions";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "role_conditions", kind: "message", T: RoleConditions, repeated: true },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ByPermissions {
    return new ByPermissions().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ByPermissions {
    return new ByPermissions().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ByPermissions {
    return new ByPermissions().fromJsonString(jsonString, options);
  }

  static equals(a: ByPermissions | PlainMessage<ByPermissions> | undefined, b: ByPermissions | PlainMessage<ByPermissions> | undefined): boolean {
    return proto3.util.equals(ByPermissions, a, b);
  }
}

/**
 * ByRoles represents the roles targeted by this notification.
 *
 * @generated from message teleport.notifications.v1.ByRoles
 */
export class ByRoles extends Message<ByRoles> {
  /**
   * @generated from field: repeated string roles = 1;
   */
  roles: string[] = [];

  constructor(data?: PartialMessage<ByRoles>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.notifications.v1.ByRoles";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "roles", kind: "scalar", T: 9 /* ScalarType.STRING */, repeated: true },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): ByRoles {
    return new ByRoles().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): ByRoles {
    return new ByRoles().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): ByRoles {
    return new ByRoles().fromJsonString(jsonString, options);
  }

  static equals(a: ByRoles | PlainMessage<ByRoles> | undefined, b: ByRoles | PlainMessage<ByRoles> | undefined): boolean {
    return proto3.util.equals(ByRoles, a, b);
  }
}

/**
 * UserNotificationState represents a notification's state for a user. This is to keep track
 * of whether the user has clicked on or dismissed the notification.
 *
 * @generated from message teleport.notifications.v1.UserNotificationState
 */
export class UserNotificationState extends Message<UserNotificationState> {
  /**
   * kind is the resource kind ("user_notification_state").
   *
   * @generated from field: string kind = 1;
   */
  kind = "";

  /**
   * sub_kind is the optional resource subkind. This is unused.
   *
   * @generated from field: string sub_kind = 2;
   */
  subKind = "";

  /**
   * version is the resource version.
   *
   * @generated from field: string version = 3;
   */
  version = "";

  /**
   * metadata is the user notification state's metadata.
   *
   * @generated from field: teleport.header.v1.Metadata metadata = 4;
   */
  metadata?: Metadata;

  /**
   * spec is the user notification state's specification.
   *
   * @generated from field: teleport.notifications.v1.UserNotificationStateSpec spec = 5;
   */
  spec?: UserNotificationStateSpec;

  /**
   * status is the state of this user notification state, it contains the notification state itself which will be dynamically modified.
   *
   * @generated from field: teleport.notifications.v1.UserNotificationStateStatus status = 6;
   */
  status?: UserNotificationStateStatus;

  constructor(data?: PartialMessage<UserNotificationState>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.notifications.v1.UserNotificationState";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "kind", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 2, name: "sub_kind", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 3, name: "version", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 4, name: "metadata", kind: "message", T: Metadata },
    { no: 5, name: "spec", kind: "message", T: UserNotificationStateSpec },
    { no: 6, name: "status", kind: "message", T: UserNotificationStateStatus },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): UserNotificationState {
    return new UserNotificationState().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): UserNotificationState {
    return new UserNotificationState().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): UserNotificationState {
    return new UserNotificationState().fromJsonString(jsonString, options);
  }

  static equals(a: UserNotificationState | PlainMessage<UserNotificationState> | undefined, b: UserNotificationState | PlainMessage<UserNotificationState> | undefined): boolean {
    return proto3.util.equals(UserNotificationState, a, b);
  }
}

/**
 * UserNotificationStateSpec is the user notification state's specification.
 *
 * @generated from message teleport.notifications.v1.UserNotificationStateSpec
 */
export class UserNotificationStateSpec extends Message<UserNotificationStateSpec> {
  /**
   * notification_id is the ID of the notification this state is for.
   *
   * @generated from field: string notification_id = 1;
   */
  notificationId = "";

  /**
   * username is the username of the user this notification state is for.
   *
   * @generated from field: string username = 2;
   */
  username = "";

  constructor(data?: PartialMessage<UserNotificationStateSpec>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.notifications.v1.UserNotificationStateSpec";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "notification_id", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 2, name: "username", kind: "scalar", T: 9 /* ScalarType.STRING */ },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): UserNotificationStateSpec {
    return new UserNotificationStateSpec().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): UserNotificationStateSpec {
    return new UserNotificationStateSpec().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): UserNotificationStateSpec {
    return new UserNotificationStateSpec().fromJsonString(jsonString, options);
  }

  static equals(a: UserNotificationStateSpec | PlainMessage<UserNotificationStateSpec> | undefined, b: UserNotificationStateSpec | PlainMessage<UserNotificationStateSpec> | undefined): boolean {
    return proto3.util.equals(UserNotificationStateSpec, a, b);
  }
}

/**
 * UserNotificationStateStatus is the status of this user notification state, it contains the notification state itself which will be dynamically modified.
 *
 * @generated from message teleport.notifications.v1.UserNotificationStateStatus
 */
export class UserNotificationStateStatus extends Message<UserNotificationStateStatus> {
  /**
   * notification_state is the state of this notification for the user. This can represent either "clicked" or "dismissed".
   *
   * @generated from field: teleport.notifications.v1.NotificationState notification_state = 1;
   */
  notificationState = NotificationState.UNSPECIFIED;

  constructor(data?: PartialMessage<UserNotificationStateStatus>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.notifications.v1.UserNotificationStateStatus";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "notification_state", kind: "enum", T: proto3.getEnumType(NotificationState) },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): UserNotificationStateStatus {
    return new UserNotificationStateStatus().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): UserNotificationStateStatus {
    return new UserNotificationStateStatus().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): UserNotificationStateStatus {
    return new UserNotificationStateStatus().fromJsonString(jsonString, options);
  }

  static equals(a: UserNotificationStateStatus | PlainMessage<UserNotificationStateStatus> | undefined, b: UserNotificationStateStatus | PlainMessage<UserNotificationStateStatus> | undefined): boolean {
    return proto3.util.equals(UserNotificationStateStatus, a, b);
  }
}

/**
 * UserLastSeenNotification represents the timestamp of the last notification a user has seen.
 *
 * @generated from message teleport.notifications.v1.UserLastSeenNotification
 */
export class UserLastSeenNotification extends Message<UserLastSeenNotification> {
  /**
   * kind is the resource kind ("user_last_seen_notification").
   *
   * @generated from field: string kind = 1;
   */
  kind = "";

  /**
   * sub_kind is the optional resource subkind. This is unused.
   *
   * @generated from field: string sub_kind = 2;
   */
  subKind = "";

  /**
   * version is the resource version.
   *
   * @generated from field: string version = 3;
   */
  version = "";

  /**
   * metadata is the user last seen notification object's metadata.
   *
   * @generated from field: teleport.header.v1.Metadata metadata = 4;
   */
  metadata?: Metadata;

  /**
   * UserLastSeenNotificationSpec is the user last seen notification item's specification.
   *
   * @generated from field: teleport.notifications.v1.UserLastSeenNotificationSpec spec = 5;
   */
  spec?: UserLastSeenNotificationSpec;

  /**
   * status is the timestamp of this user's last seen notification, it contains the timestamp of the notification which will be dynamically modified.
   *
   * @generated from field: teleport.notifications.v1.UserLastSeenNotificationStatus status = 7;
   */
  status?: UserLastSeenNotificationStatus;

  constructor(data?: PartialMessage<UserLastSeenNotification>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.notifications.v1.UserLastSeenNotification";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "kind", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 2, name: "sub_kind", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 3, name: "version", kind: "scalar", T: 9 /* ScalarType.STRING */ },
    { no: 4, name: "metadata", kind: "message", T: Metadata },
    { no: 5, name: "spec", kind: "message", T: UserLastSeenNotificationSpec },
    { no: 7, name: "status", kind: "message", T: UserLastSeenNotificationStatus },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): UserLastSeenNotification {
    return new UserLastSeenNotification().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): UserLastSeenNotification {
    return new UserLastSeenNotification().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): UserLastSeenNotification {
    return new UserLastSeenNotification().fromJsonString(jsonString, options);
  }

  static equals(a: UserLastSeenNotification | PlainMessage<UserLastSeenNotification> | undefined, b: UserLastSeenNotification | PlainMessage<UserLastSeenNotification> | undefined): boolean {
    return proto3.util.equals(UserLastSeenNotification, a, b);
  }
}

/**
 * UserLastSeenNotificationSpec is a user last seen notification specification.
 *
 * @generated from message teleport.notifications.v1.UserLastSeenNotificationSpec
 */
export class UserLastSeenNotificationSpec extends Message<UserLastSeenNotificationSpec> {
  constructor(data?: PartialMessage<UserLastSeenNotificationSpec>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.notifications.v1.UserLastSeenNotificationSpec";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): UserLastSeenNotificationSpec {
    return new UserLastSeenNotificationSpec().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): UserLastSeenNotificationSpec {
    return new UserLastSeenNotificationSpec().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): UserLastSeenNotificationSpec {
    return new UserLastSeenNotificationSpec().fromJsonString(jsonString, options);
  }

  static equals(a: UserLastSeenNotificationSpec | PlainMessage<UserLastSeenNotificationSpec> | undefined, b: UserLastSeenNotificationSpec | PlainMessage<UserLastSeenNotificationSpec> | undefined): boolean {
    return proto3.util.equals(UserLastSeenNotificationSpec, a, b);
  }
}

/**
 * UserLastSeenNotificationStatus is the timestamp of this user's last seen notification, it contains the timestamp of the notification which will be dynamically modified.
 *
 * @generated from message teleport.notifications.v1.UserLastSeenNotificationStatus
 */
export class UserLastSeenNotificationStatus extends Message<UserLastSeenNotificationStatus> {
  /**
   * last_seen_time is the timestamp of the last notification that the user has seen.
   *
   * @generated from field: google.protobuf.Timestamp last_seen_time = 1;
   */
  lastSeenTime?: Timestamp;

  constructor(data?: PartialMessage<UserLastSeenNotificationStatus>) {
    super();
    proto3.util.initPartial(data, this);
  }

  static readonly runtime: typeof proto3 = proto3;
  static readonly typeName = "teleport.notifications.v1.UserLastSeenNotificationStatus";
  static readonly fields: FieldList = proto3.util.newFieldList(() => [
    { no: 1, name: "last_seen_time", kind: "message", T: Timestamp },
  ]);

  static fromBinary(bytes: Uint8Array, options?: Partial<BinaryReadOptions>): UserLastSeenNotificationStatus {
    return new UserLastSeenNotificationStatus().fromBinary(bytes, options);
  }

  static fromJson(jsonValue: JsonValue, options?: Partial<JsonReadOptions>): UserLastSeenNotificationStatus {
    return new UserLastSeenNotificationStatus().fromJson(jsonValue, options);
  }

  static fromJsonString(jsonString: string, options?: Partial<JsonReadOptions>): UserLastSeenNotificationStatus {
    return new UserLastSeenNotificationStatus().fromJsonString(jsonString, options);
  }

  static equals(a: UserLastSeenNotificationStatus | PlainMessage<UserLastSeenNotificationStatus> | undefined, b: UserLastSeenNotificationStatus | PlainMessage<UserLastSeenNotificationStatus> | undefined): boolean {
    return proto3.util.equals(UserLastSeenNotificationStatus, a, b);
  }
}

