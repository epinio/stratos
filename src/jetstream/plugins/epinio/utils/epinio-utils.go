package epinio_utils

import (
	"fmt"

	eInterfaces "github.com/epinio/ui-backend/src/jetstream/plugins/epinio/interfaces"
	jInterfaces "github.com/epinio/ui-backend/src/jetstream/repository/interfaces"

	log "github.com/sirupsen/logrus"
)

func FindEpinioEndpoint(p jInterfaces.PortalProxy) (*jInterfaces.CNSIRecord, error) {
	endpoints, err := p.ListEndpoints()
	if err != nil {
		msg := "failed to fetch list of endpoints: %+v"
		log.Errorf(msg, err)
		return nil, fmt.Errorf(msg, err)
	}

	var epinioEndpoint *jInterfaces.CNSIRecord
	for _, e := range endpoints {
		if e.CNSIType == eInterfaces.EndpointType {
			epinioEndpoint = e
			break
		}
	}

	if epinioEndpoint == nil {
		msg := "failed to find an epinio endpoint"
		log.Error(msg)
		return nil, fmt.Errorf(msg)
	}

	return epinioEndpoint, nil
}
