package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/gravitational/gravity/lib/constants"
	"github.com/gravitational/gravity/lib/defaults"
	"github.com/gravitational/gravity/lib/httplib"
	utils "github.com/gravitational/gravity/lib/status/internal"
	"github.com/gravitational/gravity/lib/storage"
	pb "github.com/gravitational/satellite/agent/proto/agentpb"

	"github.com/gravitational/roundtrip"
	"github.com/gravitational/trace"
)

// FromPlanetAgent collects the cluster status from the planet agent
func FromPlanetAgent(ctx context.Context, servers []storage.Server) (*Agent, error) {
	return fromPlanetAgent(ctx, false, servers)
}

// FromLocalPlanetAgent collects the node status from the local planet agent
func FromLocalPlanetAgent(ctx context.Context) (*Agent, error) {
	return fromPlanetAgent(ctx, true, nil)
}

func fromPlanetAgent(ctx context.Context, local bool, servers []storage.Server) (*Agent, error) {
	status, err := planetAgentStatus(ctx, local)
	if err != nil {
		return nil, trace.Wrap(err, "failed to query cluster status from agent")
	}

	var nodes []ClusterServer
	if len(servers) != 0 {
		nodes = fromClusterState(*status, servers)
	} else {
		nodes = fromSystemStatus(*status)
	}

	return &Agent{
		SystemStatus: SystemStatus(status.Status),
		Nodes:        nodes,
	}, nil
}

// GetSystemStatus returns the status of the system
func (r Agent) GetSystemStatus() pb.SystemStatus_Type {
	return pb.SystemStatus_Type(r.SystemStatus)
}

// Agent specifies the status of the system and individual nodes
type Agent struct {
	// SystemStatus defines the health status of the whole cluster
	SystemStatus SystemStatus `json:"system_status"`
	// Nodes lists status of each individual cluster node
	Nodes []ClusterServer `json:"nodes"`
}

// ClusterServer describes the status of the cluster node
type ClusterServer struct {
	// Hostname provides the node's hostname
	Hostname string `json:"hostname"`
	// AdvertiseIP specifies the advertise IP address
	AdvertiseIP string `json:"advertise_ip"`
	// Role is the node's cluster service role (master or regular)
	Role string `json:"role"`
	// Profile is the node's profile name from application manifest
	Profile string `json:"profile"`
	// Status describes the node's status
	Status string `json:"status"`
	// FailedProbes lists all failed probes if the node is not healthy
	FailedProbes []string `json:"failed_probes,omitempty"`
	// WarnProbes lists all warning probes
	WarnProbes []string `json:"warn_probes,omitempty"`
	// TeleportNode contains information about Teleport node running on this server
	TeleportNode *TeleportNode `json:"teleport_node,omitempty"`
}

// TeleportNode represents a cluster teleport node
type TeleportNode struct {
	// Hostname is the node hostname
	Hostname string `json:"hostname"`
	// AdvertiseIP is the node advertise IP
	AdvertiseIP string `json:"advertise_ip"`
	// PublicIP is the node public IP
	PublicIP string `json:"public_ip"`
	// Profile is the node profile
	Profile string `json:"profile"`
	// InstanceType is the node instance type
	InstanceType string `json:"instance_type"`
}

// String returns a textual representation of this system status
func (r SystemStatus) String() string {
	switch pb.SystemStatus_Type(r) {
	case pb.SystemStatus_Running:
		return "running"
	case pb.SystemStatus_Degraded:
		return "degraded"
	case pb.SystemStatus_Unknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// GoString returns a textual representation of this system status
func (r SystemStatus) GoString() string {
	return r.String()
}

// SystemStatus is an alias for system status type
type SystemStatus pb.SystemStatus_Type

const (
	// NodeHealthy is the status of a healthy node
	NodeHealthy = "healthy"
	// NodeOffline is the status of an unreachable/unavailable node
	NodeOffline = "offline"
	// NodeDegraged is the status of a node with failed probes
	NodeDegraded = "degraded"
)

// fromSystemStatus returns the list of node statuses in the absence
// of the actual cluster server list so it might be missing information
// about nodes agent status did not get response back from
func fromSystemStatus(systemStatus pb.SystemStatus) (out []ClusterServer) {
	out = make([]ClusterServer, 0, len(systemStatus.Nodes))
	for _, node := range systemStatus.Nodes {
		out = append(out, fromNodeStatus(*node))
	}
	return out
}

// fromClusterState generates accurate node status report including nodes missing
// in the agent report
func fromClusterState(systemStatus pb.SystemStatus, cluster []storage.Server) (out []ClusterServer) {
	out = make([]ClusterServer, 0, len(systemStatus.Nodes))
	nodes := nodes(systemStatus)
	for _, server := range cluster {
		node, found := nodes[server.AdvertiseIP]
		if !found {
			out = append(out, emptyNodeStatus(server))
			continue
		}

		status := fromNodeStatus(*node)
		status.Hostname = server.Hostname
		status.Profile = server.Role
		out = append(out, status)
	}
	return out
}

func planetAgentStatus(ctx context.Context, local bool) (*pb.SystemStatus, error) {
	urlFormat := "https://%v:%v"
	if local {
		urlFormat = "https://%v:%v/local"
	}
	planetClient, err := httplib.GetPlanetClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	httpClient := roundtrip.HTTPClient(planetClient)
	addr := fmt.Sprintf(urlFormat, constants.Localhost, defaults.SatelliteRPCAgentPort)
	client, err := roundtrip.NewClient(addr, "", httpClient)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	resp, err := client.Get(addr, url.Values{})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var status pb.SystemStatus
	err = json.Unmarshal(resp.Bytes(), &status)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return &status, nil
}

// nodes returns the set of node status objects keyed by IP
func nodes(systemStatus pb.SystemStatus) (out map[string]*pb.NodeStatus) {
	out = make(map[string]*pb.NodeStatus)
	for _, node := range systemStatus.Nodes {
		publicIP := node.MemberStatus.Tags[publicIPAddrTag]
		out[publicIP] = node
	}
	return out
}

func fromNodeStatus(node pb.NodeStatus) (status ClusterServer) {
	status.AdvertiseIP = node.MemberStatus.Tags[publicIPAddrTag]
	status.Role = node.MemberStatus.Tags[roleTag]
	switch node.Status {
	case pb.NodeStatus_Unknown:
		status.Status = NodeOffline
	case pb.NodeStatus_Running:
		status.Status = NodeHealthy
	case pb.NodeStatus_Degraded:
		status.Status = NodeDegraded
	}
	for _, probe := range node.Probes {
		if probe.Status != pb.Probe_Running {
			if probe.Severity != pb.Probe_Warning {
				status.FailedProbes = append(status.FailedProbes,
					utils.ProbeErrorDetail(*probe))
			} else {
				status.WarnProbes = append(status.WarnProbes,
					utils.ProbeErrorDetail(*probe))
			}
		}
	}
	if len(status.FailedProbes) != 0 {
		status.Status = NodeDegraded
	}
	return status
}

func emptyNodeStatus(server storage.Server) ClusterServer {
	return ClusterServer{
		Status:      NodeOffline,
		Hostname:    server.Hostname,
		AdvertiseIP: server.AdvertiseIP,
	}
}

const (
	// publicIPAddrTag is the name of the tag containing node IP
	publicIPAddrTag = "publicip"
	// roleTag is the name of the tag containing node role
	roleTag = "role"
)
