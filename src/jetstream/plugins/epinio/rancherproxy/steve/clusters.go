package steve

import (
	"fmt"

	"github.com/labstack/echo/v4"

	"github.com/epinio/ui-backend/src/jetstream/plugins/epinio/rancherproxy/interfaces"
)

func NewClusters(ec echo.Context) *interfaces.Collection {
	col := interfaces.Collection{
		Type:         interfaces.CollectionType,
		ResourceType: interfaces.ClusterResourceType,
		Actions:      make(map[string]string),
		Links:        make(map[string]string),
	}

	col.Links["self"] = interfaces.GetSelfLink(ec)

	baseURL := interfaces.GetSelfLink(ec)

	col.Data = make([]interface{}, 1)
	col.Data[0] = NewCluster(baseURL, "local") // TODO: RC tie in with cnsi guid. NO? has to be local

	return &col
}

func NewCluster(baseURL, id string) *interfaces.Cluster {
	cluster := interfaces.Cluster{}
	cluster.Actions = make(map[string]string)
	cluster.APIVersion = "management.cattle.io/v3"
	cluster.ID = id
	cluster.Kind = "Cluster"
	cluster.Links = make(map[string]string)
	cluster.Links["self"] = fmt.Sprintf("%s/%s", baseURL, id)
	cluster.Metadata = interfaces.Metadata{
		Name: "local",
	}
	cluster.Spec = make(map[string]interface{})
	cluster.Status = make(map[string]interface{})
	cluster.Type = "management.cattle.io.cluster"

	return &cluster
}
