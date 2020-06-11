package ops

import (
	"github.com/gravitational/gravity/lib/loc"
	"github.com/gravitational/gravity/lib/modules"
	"github.com/gravitational/gravity/lib/storage"
)

// ClusterStatus describes the status of the cluster
type ClusterStatus struct {
	// App references the installed application
	App loc.Locator `json:"application"`
	// State describes the cluster state
	State string `json:"state"`
	// Reason specifies the reason for the state
	Reason storage.Reason `json:"reason,omitempty"`
	// Domain provides the name of the cluster domain
	Domain string `json:"domain"`
	// ActiveOperations is a list of operations currently active in the cluster
	ActiveOperations []SiteOperation `json:"active_operations,omitempty"`
	// Endpoints contains cluster and application endpoints
	Endpoints AllEndpoints `json:"endpoints"`
	// Token specifies the provisioning token used for joining nodes to cluster if any
	Token storage.ProvisioningToken `json:"token"`
	// ServerVersion is version of the server the operator is talking to
	ServerVersion *modules.Version `json:"server_version,omitempty"`
	// TeleportNodes lists nodes as reported by teleport
	TeleportNodes Nodes
}

// AllEndpoints contains information about cluster and application endpoints.
type AllEndpoints struct {
	// Applications contains endpoints for installed applications.
	Applications ApplicationsEndpoints `json:"applications,omitempty"`
	// Cluster contains system cluster endpoints.
	Cluster ClusterEndpoints `json:"cluster"`
}

// ClusterEndpoints describes cluster system endpoints.
type ClusterEndpoints struct {
	// AuthGateway contains addresses that users should specify via --proxy
	// flag to tsh commands (essentially, address of gravity-site service)
	AuthGateway []string `json:"auth_gateway"`
	// UI contains URLs of the cluster control panel.
	UI []string `json:"ui"`
}

// ApplicationsEndpoints contains endpoints for multiple applications.
type ApplicationsEndpoints struct {
	// Endpoints lists the endpoints of all applications
	Endpoints []ApplicationEndpoints
	// Error indicates whether there was an error fetching endpoints
	Error error `json:"-"`
}

// ApplicationEndpoints contains endpoints for a single application.
type ApplicationEndpoints struct {
	// Application is the application locator.
	Application loc.Locator `json:"application"`
	// Endpoints is a list of application endpoints.
	Endpoints []Endpoint `json:"endpoints"`
}
