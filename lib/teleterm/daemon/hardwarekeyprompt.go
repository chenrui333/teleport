/*
 * Teleport
 * Copyright (C) 2024 Gravitational, Inc.
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

package daemon

import (
	"context"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/utils/keys"
	api "github.com/gravitational/teleport/gen/proto/go/teleport/lib/teleterm/v1"
	"github.com/gravitational/teleport/lib/teleterm/api/uri"
)

// NewHardwareKeyPromptConstructor returns a new hardware key prompt constructor
// for this service and the given root cluster URI.
func (s *Service) NewHardwareKeyPromptConstructor(rootClusterURI uri.ResourceURI) keys.HardwareKeyPrompt {
	return &hardwareKeyPrompter{s: s, rootClusterURI: rootClusterURI}
}

type hardwareKeyPrompter struct {
	s              *Service
	rootClusterURI uri.ResourceURI
}

// Touch prompts the user to touch the hardware key.
func (h *hardwareKeyPrompter) Touch(ctx context.Context) error {
	if err := h.s.importantModalSemaphore.Acquire(ctx); err != nil {
		return trace.Wrap(err)
	}
	defer h.s.importantModalSemaphore.Release()
	_, err := h.s.tshdEventsClient.PromptHardwareKeyTouch(ctx, &api.PromptHardwareKeyTouchRequest{
		RootClusterUri: h.rootClusterURI.String(),
	})
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// AskPIN prompts the user for a PIN.
func (h *hardwareKeyPrompter) AskPIN(ctx context.Context, requirement keys.PINPromptRequirement) (string, error) {
	if err := h.s.importantModalSemaphore.Acquire(ctx); err != nil {
		return "", trace.Wrap(err)
	}
	defer h.s.importantModalSemaphore.Release()
	res, err := h.s.tshdEventsClient.PromptHardwareKeyPIN(ctx, &api.PromptHardwareKeyPINRequest{
		RootClusterUri: h.rootClusterURI.String(),
		PinOptional:    requirement == keys.PINOptional,
	})
	if err != nil {
		return "", trace.Wrap(err)
	}
	return res.Pin, nil
}

// ChangePIN asks for a new PIN.
// The Electron app prompt must handle default values for PIN and PUK,
// preventing the user from submitting empty/default values.
func (h *hardwareKeyPrompter) ChangePIN(ctx context.Context) (*keys.PINAndPUK, error) {
	if err := h.s.importantModalSemaphore.Acquire(ctx); err != nil {
		return nil, trace.Wrap(err)
	}
	defer h.s.importantModalSemaphore.Release()
	res, err := h.s.tshdEventsClient.PromptHardwareKeyPINChange(ctx, &api.PromptHardwareKeyPINChangeRequest{
		RootClusterUri: h.rootClusterURI.String(),
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &keys.PINAndPUK{
		PIN:        res.Pin,
		PUK:        res.Puk,
		PUKChanged: res.PukChanged,
	}, nil
}

// ConfirmSlotOverwrite asks the user if the slot's private key and certificate can be overridden.
func (h *hardwareKeyPrompter) ConfirmSlotOverwrite(ctx context.Context, message string) (bool, error) {
	if err := h.s.importantModalSemaphore.Acquire(ctx); err != nil {
		return false, trace.Wrap(err)
	}
	defer h.s.importantModalSemaphore.Release()
	res, err := h.s.tshdEventsClient.ConfirmHardwareKeySlotOverwrite(ctx, &api.ConfirmHardwareKeySlotOverwriteRequest{
		RootClusterUri: h.rootClusterURI.String(),
		Message:        message,
	})
	if err != nil {
		return false, trace.Wrap(err)
	}
	return res.Confirmed, nil
}
