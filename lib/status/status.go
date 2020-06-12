/*
Copyright 2018 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package status

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/gravitational/gravity/lib/constants"
	"github.com/gravitational/gravity/lib/loc"
	"github.com/gravitational/gravity/lib/modules"
	"github.com/gravitational/gravity/lib/ops"
	"github.com/gravitational/gravity/lib/status/agent"
	"github.com/gravitational/gravity/lib/storage"

	pb "github.com/gravitational/satellite/agent/proto/agentpb"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
)

// FromCluster collects cluster status information.
// The function returns the partial status if not all details can be collected
func FromCluster(ctx context.Context, operator ops.Operator, operationID string) (status *Status, err error) {
	status = &Status{
		Cluster: &Cluster{
			// Default to degraded - reset on successful query
			State:         ops.SiteStateDegraded,
			ClientVersion: modules.Get().Version(),
			Extension:     newExtension(),
		},
	}

	clusterStatus, err := operator.GetAndUpdateLocalClusterStatus(ctx, ops.ClusterStatusRequest{
		OperationID: operationID,
	})
	if err != nil {
		logrus.WithError(err).Warn("Failed to query cluster state.")
	} else {
		status.Cluster.App = clusterStatus.App
		status.Cluster.State = clusterStatus.State
		status.Cluster.Reason = clusterStatus.Reason
		status.Cluster.Domain = clusterStatus.Domain
		status.Cluster.Endpoints = Endpoints{
			Applications: ApplicationsEndpoints(clusterStatus.Endpoints.Applications),
			Cluster:      ClusterEndpoints(clusterStatus.Endpoints.Cluster),
		}
		status.Cluster.Token = clusterStatus.Token
		status.Cluster.ServerVersion = clusterStatus.ServerVersion
	}

	// FIXME: have status extension accept the operator/environment
	err = status.Cluster.Extension.Collect()
	if err != nil {
		logrus.WithError(err).Warn("Failed to query extension state.")
	}

	if clusterStatus != nil {
		for _, op := range clusterStatus.ActiveOperations {
			status.ActiveOperations = append(status.ActiveOperations,
				fromOperationAndProgress(op))
		}
		if clusterStatus.Operation != nil {
			status.Operation = fromOperationAndProgress(*clusterStatus.Operation)
		}
	}

	if clusterStatus != nil {
		status.Agent = clusterStatus.Agent
	}
	if status.Agent == nil {
		status.Agent, err = agent.FromPlanetAgent(ctx, nil)
		if err != nil {
			logrus.WithError(err).Warn("Failed to collect system status from agents.")
		}
	}

	if status.IsDegraded() {
		status.Cluster.State = ops.SiteStateDegraded
	}
	return status, nil
}

// IsDegraded returns whether the cluster is in degraded state
func (r Status) IsDegraded() bool {
	return (r.Cluster == nil ||
		r.Cluster.State == ops.SiteStateDegraded ||
		r.Agent == nil ||
		r.Agent.GetSystemStatus() != pb.SystemStatus_Running)
}

// Status describes the status of the cluster as a whole
type Status struct {
	// Cluster describes the operational status of the cluster
	*Cluster `json:",inline,omitempty"`
	// Agent describes the status of the system and individual nodes
	*agent.Agent `json:",inline,omitempty"`
}

// Cluster encapsulates collected cluster status information
type Cluster struct {
	// App references the installed application
	App loc.Locator `json:"application"`
	// State describes the cluster state
	State string `json:"state"`
	// Reason specifies the reason for the state
	Reason storage.Reason `json:"reason,omitempty"`
	// Domain provides the name of the cluster domain
	Domain string `json:"domain"`
	// ActiveOperations is a list of operations currently active in the cluster
	ActiveOperations []*ClusterOperation `json:"active_operations,omitempty"`
	// Endpoints contains cluster and application endpoints
	Endpoints Endpoints `json:"endpoints"`
	// Token specifies the provisioning token used for joining nodes to cluster if any
	Token storage.ProvisioningToken `json:"token"`
	// Operation describes a cluster operation.
	// This can either refer to the last completed or a specific operation
	Operation *ClusterOperation `json:"operation,omitempty"`
	// Extension is a cluster status extension
	Extension `json:",inline,omitempty"`
	// ClientVersion is version of the binary collecting the status.
	ClientVersion modules.Version `json:"client_version"`
	// ServerVersion is version of the server the operator is talking to
	ServerVersion *modules.Version `json:"server_version,omitempty"`
}

// Key returns key structure that identifies this operation
func (r ClusterOperation) Key() ops.SiteOperationKey {
	return ops.SiteOperationKey{
		AccountID:   r.accountID,
		OperationID: r.ID,
		SiteDomain:  r.siteDomain,
	}
}

// ClusterOperation describes a cluster operation.
// This can either refer to the last or a specific operation
type ClusterOperation struct {
	// Type of the operation
	Type string `json:"type"`
	// ID of the operation
	ID string `json:"id"`
	// State of the operation (completed, in progress, failed etc)
	State string `json:"state"`
	// Created specifies the time the operation was created
	Created time.Time `json:"created"`
	// Progress describes the progress of an operation
	Progress   ClusterOperationProgress `json:"progress"`
	accountID  string
	siteDomain string
}

// IsCompleted returns whether this progress entry identifies a completed
// (successful or failed) operation
func (r ClusterOperationProgress) IsCompleted() bool {
	return r.Completion == constants.Completed
}

// Progress describes the progress of an operation
type ClusterOperationProgress struct {
	// Message provides the free text associated with this entry
	Message string `json:"message"`
	// Completion specifies the progress value in percent (0..100)
	Completion int `json:"completion"`
	// Created specifies the time the progress entry was created
	Created time.Time `json:"created"`
}

func (r ClusterOperation) isFailed() bool {
	return r.State == ops.OperationStateFailed
}

// Endpoints contains information about cluster and application endpoints.
type Endpoints struct {
	// Applications contains endpoints for installed applications.
	Applications ApplicationsEndpoints `json:"applications,omitempty"`
	// Cluster contains system cluster endpoints.
	Cluster ClusterEndpoints `json:"cluster"`
}

// ClusterEndpoints describes cluster endpoints
type ClusterEndpoints ops.ClusterEndpoints

// WriteTo writes cluster endpoints to the provided writer.
func (e ClusterEndpoints) WriteTo(w io.Writer) (n int64, err error) {
	var errors []error
	errors = append(errors, fprintf(&n, w, "Cluster endpoints:\n"))
	errors = append(errors, fprintf(&n, w, "    * Authentication gateway:\n"))
	for _, e := range e.AuthGateway {
		errors = append(errors, fprintf(&n, w, "        - %v\n", e))
	}
	errors = append(errors, fprintf(&n, w, "    * Cluster management URL:\n"))
	for _, e := range e.UI {
		errors = append(errors, fprintf(&n, w, "        - %v\n", e))
	}
	return n, trace.NewAggregate(errors...)
}

// ApplicationEndpoints describes cluster application endpoints
type ApplicationsEndpoints ops.ApplicationsEndpoints

// WriteTo writes all application endpoints to the provided writer.
func (e ApplicationsEndpoints) WriteTo(w io.Writer) (n int64, err error) {
	if len(e.Endpoints) == 0 {
		if e.Error != nil {
			err := fprintf(&n, w, "Application endpoints: <unable to fetch>")
			return n, trace.Wrap(err)
		}
		return 0, nil
	}
	var errors []error
	errors = append(errors, fprintf(&n, w, "Application endpoints:\n"))
	for _, app := range e.Endpoints {
		errors = append(errors, fprintf(&n, w, "    * %v:%v:\n",
			app.Application.Name, app.Application.Version))
		for _, ep := range app.Endpoints {
			errors = append(errors, fprintf(&n, w, "        - %v:\n", ep.Name))
			for _, addr := range ep.Addresses {
				errors = append(errors, fprintf(&n, w, "            - %v\n", addr))
			}
		}
	}
	return n, trace.NewAggregate(errors...)
}

func fprintf(n *int64, w io.Writer, format string, a ...interface{}) error {
	written, err := fmt.Fprintf(w, format, a...)
	if err != nil {
		return trace.ConvertSystemError(err)
	}
	*n += int64(written)
	return nil
}

func fromOperationAndProgress(state ops.ClusterOperationState) *ClusterOperation {
	return &ClusterOperation{
		Type:       state.Operation.Type,
		ID:         state.Operation.ID,
		State:      state.Operation.State,
		Created:    state.Operation.Created,
		siteDomain: state.Operation.SiteDomain,
		accountID:  state.Operation.AccountID,
		Progress:   fromProgressEntry(state.Progress),
	}
}

func fromProgressEntry(src ops.ProgressEntry) ClusterOperationProgress {
	return ClusterOperationProgress{
		Message:    src.Message,
		Completion: src.Completion,
		Created:    src.Created,
	}
}
