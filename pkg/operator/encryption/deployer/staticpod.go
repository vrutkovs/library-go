package deployer

import (
	"context"

	"k8s.io/client-go/tools/cache"

	operatorv1helpers "github.com/openshift/library-go/pkg/operator/v1helpers"
)

// StaticPodNodeProvider returns the node list from the node status in the static pod operator status.
type StaticPodNodeProvider struct {
	OperatorClient operatorv1helpers.StaticPodOperatorClient
}

var (
	_ MasterNodeProvider = &StaticPodNodeProvider{}
)

func (p StaticPodNodeProvider) MasterNodeNames(ctx context.Context) ([]string, error) {
	_, status, _, err := p.OperatorClient.GetStaticPodOperatorState(ctx)
	if err != nil {
		return nil, err
	}
	ret := make([]string, 0, len(status.NodeStatuses))
	for _, n := range status.NodeStatuses {
		ret = append(ret, n.NodeName)
	}
	return ret, nil
}

func (p StaticPodNodeProvider) AddEventHandler(handler cache.ResourceEventHandler) []cache.InformerSynced {
	p.OperatorClient.Informer().AddEventHandler(handler)
	return []cache.InformerSynced{p.OperatorClient.Informer().HasSynced}
}
