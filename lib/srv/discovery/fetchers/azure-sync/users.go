package azure_sync

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	accessgraphv1alpha "github.com/gravitational/teleport/gen/proto/go/accessgraph/v1alpha"
	"github.com/gravitational/trace"
	"google.golang.org/protobuf/types/known/timestamppb"
	"slices"
)

func (a *azureFetcher) fetchPrincipals(ctx context.Context) ([]*accessgraphv1alpha.AzurePrincipal, error) {
	// Get the VM client
	cred, err := a.CloudClients.GetAzureCredential()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	scopes := []string{"https://graph.microsoft.com/.default"}
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: scopes})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	cli := NewGraphClient(token)

	// Fetch the users, groups, and managed identities
	users, err := cli.ListUsers(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	groups, err := cli.ListGroups(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	svcPrincipals, err := cli.ListServicePrincipals(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	principals := slices.Concat(users, groups, svcPrincipals)

	// Return the users as protobuf messages
	pbPrincipals := make([]*accessgraphv1alpha.AzurePrincipal, 0, len(principals))
	for _, principal := range principals {
		pbPrincipal := &accessgraphv1alpha.AzurePrincipal{
			Id:             principal.ID,
			SubscriptionId: a.GetSubscriptionID(),
			LastSyncTime:   timestamppb.Now(),
			DisplayName:    principal.Name,
			MemberOf:       principal.MemberOf,
		}
		pbPrincipals = append(pbPrincipals, pbPrincipal)
	}
	return pbPrincipals, nil
}
