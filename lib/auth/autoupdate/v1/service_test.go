// Teleport
// Copyright (C) 2024 Gravitational, Inc.
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

package autoupdate

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/gen/proto/go/teleport/autoupdate/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/backend/memory"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local"
	"github.com/gravitational/teleport/lib/utils"
)

var allAdminStates = map[authz.AdminActionAuthState]string{
	authz.AdminActionAuthUnauthorized:         "Unauthorized",
	authz.AdminActionAuthNotRequired:          "NotRequired",
	authz.AdminActionAuthMFAVerified:          "MFAVerified",
	authz.AdminActionAuthMFAVerifiedWithReuse: "MFAVerifiedWithReuse",
}

func stateToString(state authz.AdminActionAuthState) string {
	str, ok := allAdminStates[state]
	if !ok {
		return fmt.Sprintf("unknown(%v)", state)
	}
	return str
}

// otherAdminStates returns all admin states except for those passed in
func otherAdminStates(states []authz.AdminActionAuthState) []authz.AdminActionAuthState {
	var out []authz.AdminActionAuthState
	for state := range allAdminStates {
		found := slices.Index(states, state) != -1
		if !found {
			out = append(out, state)
		}
	}
	return out
}

// callMethod calls a method with given name in the DatabaseObjectService service
func callMethod(t *testing.T, service *Service, method string) error {
	for _, desc := range autoupdate.AutoupdateService_ServiceDesc.Methods {
		if desc.MethodName == method {
			_, err := desc.Handler(service, context.Background(), func(_ any) error { return nil }, nil)
			return err
		}
	}
	require.FailNow(t, "method %v not found", method)
	panic("this line should never be reached: FailNow() should interrupt the test")
}

func TestServiceAccess(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		allowedVerbs     []string
		allowedStates    []authz.AdminActionAuthState
		disallowedStates []authz.AdminActionAuthState
	}{
		{
			name: "CreateAutoupdateConfig",
			allowedStates: []authz.AdminActionAuthState{
				authz.AdminActionAuthNotRequired,
				authz.AdminActionAuthMFAVerified,
				authz.AdminActionAuthMFAVerifiedWithReuse,
			},
			allowedVerbs: []string{types.VerbCreate},
		},
		{
			name: "UpdateAutoupdateConfig",
			allowedStates: []authz.AdminActionAuthState{
				authz.AdminActionAuthNotRequired,
				authz.AdminActionAuthMFAVerified,
				authz.AdminActionAuthMFAVerifiedWithReuse,
			},
			allowedVerbs: []string{types.VerbUpdate},
		},
		{
			name: "UpsertAutoupdateConfig",
			allowedStates: []authz.AdminActionAuthState{
				authz.AdminActionAuthNotRequired,
				authz.AdminActionAuthMFAVerified,
				authz.AdminActionAuthMFAVerifiedWithReuse,
			},
			allowedVerbs: []string{types.VerbUpdate, types.VerbCreate},
		},
		{
			name:             "GetAutoupdateConfig",
			allowedStates:    []authz.AdminActionAuthState{},
			disallowedStates: []authz.AdminActionAuthState{},
			allowedVerbs:     []string{types.VerbRead},
		},
		{
			name:          "DeleteAutoupdateConfig",
			allowedStates: []authz.AdminActionAuthState{authz.AdminActionAuthNotRequired, authz.AdminActionAuthMFAVerified},
			allowedVerbs:  []string{types.VerbDelete},
		},
		// Autoupdate version check.
		{
			name: "CreateAutoupdateVersion",
			allowedStates: []authz.AdminActionAuthState{
				authz.AdminActionAuthNotRequired,
				authz.AdminActionAuthMFAVerified,
				authz.AdminActionAuthMFAVerifiedWithReuse,
			},
			allowedVerbs: []string{types.VerbCreate},
		},
		{
			name: "UpdateAutoupdateVersion",
			allowedStates: []authz.AdminActionAuthState{
				authz.AdminActionAuthNotRequired,
				authz.AdminActionAuthMFAVerified,
				authz.AdminActionAuthMFAVerifiedWithReuse,
			},
			allowedVerbs: []string{types.VerbUpdate},
		},
		{
			name: "UpsertAutoupdateVersion",
			allowedStates: []authz.AdminActionAuthState{
				authz.AdminActionAuthNotRequired,
				authz.AdminActionAuthMFAVerified,
				authz.AdminActionAuthMFAVerifiedWithReuse,
			},
			allowedVerbs: []string{types.VerbUpdate, types.VerbCreate},
		},
		{
			name:             "GetAutoupdateVersion",
			allowedStates:    []authz.AdminActionAuthState{},
			disallowedStates: []authz.AdminActionAuthState{},
			allowedVerbs:     []string{types.VerbRead},
		},
		{
			name:          "DeleteAutoupdateVersion",
			allowedStates: []authz.AdminActionAuthState{authz.AdminActionAuthNotRequired, authz.AdminActionAuthMFAVerified},
			allowedVerbs:  []string{types.VerbDelete},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// test the method with allowed admin states, each one separately.
			t.Run("allowed admin states", func(t *testing.T) {
				for _, state := range tt.allowedStates {
					t.Run(stateToString(state), func(t *testing.T) {
						for _, verbs := range utils.Combinations(tt.allowedVerbs) {
							t.Run(fmt.Sprintf("verbs=%v", verbs), func(t *testing.T) {
								service := newService(t, state, fakeChecker{allowedVerbs: verbs})
								err := callMethod(t, service, tt.name)
								// expect access denied except with full set of verbs.
								if len(verbs) == len(tt.allowedVerbs) {
									require.False(t, trace.IsAccessDenied(err))
								} else {
									require.True(t, trace.IsAccessDenied(err), "expected access denied for verbs %v, got err=%v", verbs, err)
								}
							})
						}
					})
				}
			})

			// test the method with disallowed admin states; expect failures.
			t.Run("disallowed admin states", func(t *testing.T) {
				disallowedStates := otherAdminStates(tt.allowedStates)
				if tt.disallowedStates != nil {
					disallowedStates = tt.disallowedStates
				}
				for _, state := range disallowedStates {
					t.Run(stateToString(state), func(t *testing.T) {
						// it is enough to test against tt.allowedVerbs,
						// this is the only different data point compared to the test cases above.
						service := newService(t, state, fakeChecker{allowedVerbs: tt.allowedVerbs})
						err := callMethod(t, service, tt.name)
						require.True(t, trace.IsAccessDenied(err))
					})
				}
			})
		})
	}

	// verify that all declared methods have matching test cases
	t.Run("verify coverage", func(t *testing.T) {
		for _, method := range autoupdate.AutoupdateService_ServiceDesc.Methods {
			t.Run(method.MethodName, func(t *testing.T) {
				match := false
				for _, testCase := range testCases {
					match = match || testCase.name == method.MethodName
				}
				require.True(t, match, "method %v without coverage, no matching tests", method.MethodName)
			})
		}
	})
}

type fakeChecker struct {
	allowedVerbs []string
	services.AccessChecker
}

func (f fakeChecker) CheckAccessToRule(_ services.RuleContext, _ string, resource string, verb string) error {
	if resource == types.KindAutoupdateConfig || resource == types.KindAutoupdateVersion {
		for _, allowedVerb := range f.allowedVerbs {
			if allowedVerb == verb {
				return nil
			}
		}
	}

	return trace.AccessDenied("access denied to rule=%v/verb=%v", resource, verb)
}

func newService(t *testing.T, authState authz.AdminActionAuthState, checker services.AccessChecker) *Service {
	t.Helper()

	bk, err := memory.New(memory.Config{})
	require.NoError(t, err)

	storage, err := local.NewAutoupdateService(bk)
	require.NoError(t, err)

	return newServiceWithStorage(t, authState, checker, storage)
}

func newServiceWithStorage(t *testing.T, authState authz.AdminActionAuthState, checker services.AccessChecker, storage services.AutoupdateService) *Service {
	t.Helper()

	authorizer := authz.AuthorizerFunc(func(ctx context.Context) (*authz.Context, error) {
		user, err := types.NewUser("alice")
		if err != nil {
			return nil, err
		}
		return &authz.Context{
			User:                 user,
			Checker:              checker,
			AdminActionAuthState: authState,
		}, nil
	})

	service, err := NewService(ServiceConfig{
		Authorizer: authorizer,
		Backend:    storage,
		Cache:      storage,
	})
	require.NoError(t, err)
	return service
}
