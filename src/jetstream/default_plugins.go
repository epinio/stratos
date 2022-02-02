package main

// These imports bring in the default set of plugins

import (
	_ "github.com/epinio/ui-backend/src/jetstream/plugins/backup"
	_ "github.com/epinio/ui-backend/src/jetstream/plugins/cloudfoundryhosting"
	_ "github.com/epinio/ui-backend/src/jetstream/plugins/metrics"
	_ "github.com/epinio/ui-backend/src/jetstream/plugins/userfavorites"
	_ "github.com/epinio/ui-backend/src/jetstream/plugins/userinfo"
)
