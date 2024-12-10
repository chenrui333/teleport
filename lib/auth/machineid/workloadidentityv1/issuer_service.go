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

package workloadidentityv1

import (
	"context"
	"crypto"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"

	"github.com/gravitational/teleport"
	workloadidentityv1pb "github.com/gravitational/teleport/api/gen/proto/go/teleport/workloadidentity/v1"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/authz"
)

// KeyStorer is an interface that provides methods to retrieve keys and
// certificates from the backend.
type KeyStorer interface {
	GetTLSCertAndSigner(ctx context.Context, ca types.CertAuthority) ([]byte, crypto.Signer, error)
	GetJWTSigner(ctx context.Context, ca types.CertAuthority) (crypto.Signer, error)
}

// IssuanceServiceConfig holds configuration options for the IssuanceService.
type IssuanceServiceConfig struct {
	Authorizer authz.Authorizer
	Cache      workloadIdentityReader
	Clock      clockwork.Clock
	Emitter    apievents.Emitter
	Logger     *slog.Logger
	KeyStore   KeyStorer

	ClusterName string
}

// IssuanceService is the gRPC service for managing workload identity resources.
// It implements the workloadidentityv1pb.WorkloadIdentityIssuanceServiceServer.
type IssuanceService struct {
	workloadidentityv1pb.UnimplementedWorkloadIdentityIssuanceServiceServer

	authorizer authz.Authorizer
	cache      workloadIdentityReader
	clock      clockwork.Clock
	emitter    apievents.Emitter
	logger     *slog.Logger
	keyStore   KeyStorer

	clusterName string
}

// NewIssuanceService returns a new instance of the IssuanceService.
func NewIssuanceService(cfg *IssuanceServiceConfig) (*IssuanceService, error) {
	switch {
	case cfg.Cache == nil:
		return nil, trace.BadParameter("cache service is required")
	case cfg.Authorizer == nil:
		return nil, trace.BadParameter("authorizer is required")
	case cfg.Emitter == nil:
		return nil, trace.BadParameter("emitter is required")
	case cfg.KeyStore == nil:
		return nil, trace.BadParameter("key store is required")
	case cfg.ClusterName == "":
		return nil, trace.BadParameter("cluster name is required")
	}

	if cfg.Logger == nil {
		cfg.Logger = slog.With(teleport.ComponentKey, "workload_identity_issuance.service")
	}
	if cfg.Clock == nil {
		cfg.Clock = clockwork.NewRealClock()
	}
	return &IssuanceService{
		authorizer:  cfg.Authorizer,
		cache:       cfg.Cache,
		clock:       cfg.Clock,
		emitter:     cfg.Emitter,
		logger:      cfg.Logger,
		keyStore:    cfg.KeyStore,
		clusterName: cfg.ClusterName,
	}, nil
}

// getFieldStringValue
// TODO(noah): This is a fairly gnarly first pass of a reflection based
// attribute extraction function. This will eventually be replaced potentially
// by the chosen expression/predicate language mechanism.
func getFieldStringValue(attrs *workloadidentityv1pb.Attrs, attr string) (string, error) {
	// join.gitlab.username
	attrParts := strings.Split(attr, ".")
	message := attrs.ProtoReflect()
	for i, part := range attrParts {
		fieldDesc := message.Descriptor().Fields().ByTextName(part)
		if fieldDesc == nil {
			return "", trace.NotFound("field %q not found", part)
		}
		// We expect the final key to point to a string field - otherwise - we
		// return an error.
		if i == len(attrParts)-1 {
			if fieldDesc.Kind() != protoreflect.StringKind {
				return "", trace.BadParameter("field %q is not a string", part)
			}
			return message.Get(fieldDesc).String(), nil
		}
		// If we're not processing the final key part, we expect this to point
		// to a message that we can further explore.
		if fieldDesc.Kind() != protoreflect.MessageKind {
			return "", trace.BadParameter("field %q is not a message", part)
		}
		message = message.Get(fieldDesc).Message()
	}
	return "", nil
}

// This place is not a place of honor...
// no highly esteemed deed is commemorated here...
// nothing valued is here.
//
// What is here was dangerous and repulsive to us.
// This message is a warning about danger.
func templateString(in string, attrs *workloadidentityv1pb.Attrs) (string, error) {
	re := regexp.MustCompile(`\{\{(.*?)\}\}`)
	matches := re.FindAllStringSubmatch(in, -1)

	for _, match := range matches {
		attrKey := strings.Trim(match[0], "{}")
		attrKey = strings.TrimFunc(attrKey, unicode.IsSpace)
		value, err := getFieldStringValue(attrs, attrKey)
		if err != nil {
			return "", trace.Wrap(err, "fetching attribute value for %q", attrKey)
		}
		in = strings.Replace(in, match[0], value, 1)
	}

	return in, nil
}

func evaluateRules(
	wi *workloadidentityv1pb.WorkloadIdentity,
	attrs *workloadidentityv1pb.Attrs,
) error {
	if len(wi.GetSpec().GetRules().GetAllow()) == 0 {
		return nil
	}
ruleLoop:
	for _, rule := range wi.GetSpec().GetRules().GetAllow() {
		for _, condition := range rule.GetConditions() {
			val, err := getFieldStringValue(attrs, condition.Attribute)
			if err != nil {
				return trace.Wrap(err)
			}
			if val != condition.Equals {
				continue ruleLoop
			}
		}
		return nil
	}
	return trace.AccessDenied("no matching rule found")
}

func (s *IssuanceService) IssueWorkloadIdentity(
	ctx context.Context,
	req *workloadidentityv1pb.IssueWorkloadIdentityRequest,
) (*workloadidentityv1pb.IssueWorkloadIdentityResponse, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	if req.GetName() == "" {
		return nil, trace.BadParameter("name: is required")
	}

	// TODO: Enforce WorkloadIdentity labelling access control?
	wi, err := s.cache.GetWorkloadIdentity(ctx, req.GetName())
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// TODO: Build up workload identity evaluation context.
	attrs := &workloadidentityv1pb.Attrs{
		Workload: req.WorkloadAttrs,
		User: &workloadidentityv1pb.UserAttrs{
			Username: authCtx.User.GetName(),
		},
		Join: &workloadidentityv1pb.JoinAttrs{},
	}

	// Evaluate any rules explicitly configured by the user
	if err := evaluateRules(wi, attrs); err != nil {
		return nil, trace.Wrap(err)
	}

	// Perform any templating

	_, err = spiffeid.FromURI(&url.URL{
		Scheme: "spiffe",
		Host:   s.clusterName,
		Path:   "woof",
	})
	if err != nil {
		return nil, trace.Wrap(err, "creating SPIFFE ID")
	}

	// TODO: Perform templating

	// TODO: Issue X509 or JWT

	// Return.

	return nil, trace.NotImplemented("not implemented")
}

func (s *IssuanceService) issueX509() error {
	return trace.NotImplemented("womp womp")
}

const jtiLength = 16

func (s *IssuanceService) issueJWT() error {
	return trace.NotImplemented("womp womp")
}
