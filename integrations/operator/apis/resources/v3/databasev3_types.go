/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package v3

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/integrations/operator/apis/resources"
)

func init() {
	SchemeBuilder.Register(&TeleportDatabaseV3{}, &TeleportDatabaseListV3{})
}

// TeleportDatabaseSpec defines the desired state of TeleportDatabase
type TeleportDatabaseSpec types.DatabaseSpecV3

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// TeleportDatabase is the Schema for the databases API
type TeleportDatabaseV3 struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   TeleportDatabaseSpec `json:"spec,omitempty"`
	Status resources.Status     `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// TeleportDatabaseList contains a list of TeleportDatabase
type TeleportDatabaseListV3 struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TeleportDatabaseV3 `json:"items"`
}

func (r TeleportDatabaseV3) ToTeleport() types.Database {
	return &types.DatabaseV3{
		Kind:    types.KindDatabase,
		Version: types.V3,
		Metadata: types.Metadata{
			Name:        r.Name,
			Labels:      r.Labels,
			Description: r.Annotations[resources.DescriptionKey],
		},
		Spec: types.DatabaseSpecV3(r.Spec),
	}
}

// Marshal serializes a spec into binary data.
func (spec *TeleportDatabaseSpec) Marshal() ([]byte, error) {
	return (*types.DatabaseSpecV3)(spec).Marshal()
}

// Unmarshal deserializes a spec from binary data.
func (spec *TeleportDatabaseSpec) Unmarshal(data []byte) error {
	return (*types.DatabaseSpecV3)(spec).Unmarshal(data)
}

// DeepCopyInto deep-copies one database spec into another.
// Required to satisfy runtime.Object interface.
func (spec *TeleportDatabaseSpec) DeepCopyInto(out *TeleportDatabaseSpec) {
	data, err := spec.Marshal()
	if err != nil {
		panic(err)
	}
	*out = TeleportDatabaseSpec{}
	if err = out.Unmarshal(data); err != nil {
		panic(err)
	}
}

// StatusConditions returns a pointer to Status.Conditions slice.
func (r *TeleportDatabaseV3) StatusConditions() *[]metav1.Condition {
	return &r.Status.Conditions
}
