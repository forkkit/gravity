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

package opsservice

import (
	"context"
	"fmt"

	"github.com/gravitational/gravity/lib/app"
	"github.com/gravitational/gravity/lib/defaults"
	"github.com/gravitational/gravity/lib/ops"
	"github.com/gravitational/gravity/lib/schema"
	"github.com/gravitational/gravity/lib/status/agent"
	"github.com/gravitational/gravity/lib/storage"

	"github.com/gravitational/satellite/agent/proto/agentpb"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
)

// CheckSiteStatus runs application status hook and updates cluster status appropriately
func (o *Operator) CheckSiteStatus(key ops.SiteKey) error {
	cluster, err := o.openSite(key)
	if err != nil {
		return trace.Wrap(err)
	}

	// pause status checks while the cluster is undergoing an operation
	switch cluster.backendSite.State {
	case ops.SiteStateActive, ops.SiteStateDegraded:
	default:
		o.Infof("Status checks are paused, cluster is %v.",
			cluster.backendSite.State)
		return nil
	}

	statusErr := cluster.checkPlanetStatus(context.TODO())
	reason := storage.ReasonClusterDegraded
	if statusErr == nil {
		statusErr = cluster.checkStatusHook(context.TODO())
		reason = storage.ReasonStatusCheckFailed
	}

	if statusErr != nil {
		err := o.DeactivateSite(ops.DeactivateSiteRequest{
			AccountID:  key.AccountID,
			SiteDomain: cluster.backendSite.Domain,
			Reason:     reason,
		})
		if err != nil {
			return trace.Wrap(err)
		}
		return trace.Wrap(statusErr)
	}

	// all status checks passed so if the cluster was previously degraded
	// because of those checks, reset its status
	if cluster.canActivate() {
		err := o.ActivateSite(ops.ActivateSiteRequest{
			AccountID:  key.AccountID,
			SiteDomain: cluster.backendSite.Domain,
		})
		if err != nil {
			return trace.Wrap(err)
		}
	}

	return nil
}

// GetAndUpdateLocalClusterStatus queries and returns the cluster status.
// Updates the cluster state in database accordingly
func (o *Operator) GetAndUpdateLocalClusterStatus(ctx context.Context, req ops.ClusterStatusRequest) (*ops.ClusterStatus, error) {
	cluster, err := o.GetLocalSite()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	status := &ops.ClusterStatus{
		Domain: cluster.Domain,
		Reason: cluster.Reason,
		App:    cluster.App.Package,
	}
	token, err := o.GetExpandToken(cluster.Key())
	if err != nil && !trace.IsNotFound(err) {
		return status, trace.Wrap(err)
	}
	if token != nil {
		status.Token = *token
	}
	status.ServerVersion, err = o.GetVersion(ctx)
	if err != nil {
		logrus.WithError(err).Warn("Failed to query server version information.")
	}
	// Collect application endpoints.
	endpoints, err := o.GetApplicationEndpoints(cluster.Key())
	if err != nil {
		logrus.WithError(err).Warn("Failed to fetch application endpoints.")
		status.Endpoints.Applications.Error = err
	}
	if len(endpoints) != 0 {
		// Right now only 1 application is supported, in the future there
		// will be many applications each with its own endpoints.
		status.Endpoints.Applications.Endpoints = append(status.Endpoints.Applications.Endpoints,
			ops.ApplicationEndpoints{
				Application: cluster.App.Package,
				Endpoints:   endpoints,
			})
	}
	// For cluster endpoints, they point to gravity-site service on master nodes.
	masters := cluster.ClusterState.Servers.Masters()
	for _, master := range masters {
		status.Endpoints.Cluster.AuthGateway = append(status.Endpoints.Cluster.AuthGateway,
			fmt.Sprintf("%v:%v", master.AdvertiseIP, defaults.GravitySiteNodePort))
		status.Endpoints.Cluster.UI = append(status.Endpoints.Cluster.UI,
			fmt.Sprintf("https://%v:%v", master.AdvertiseIP, defaults.GravitySiteNodePort))
	}

	// FIXME: move to dedicated function
	activeOperations, err := ops.GetActiveOperations(cluster.Key(), o)
	if err != nil && !trace.IsNotFound(err) {
		return status, trace.Wrap(err)
	}
	for _, operation := range activeOperations {
		progress, err := o.GetSiteOperationProgress(operation.Key())
		if err != nil {
			return status, trace.Wrap(err)
		}
		status.ActiveOperations = append(status.ActiveOperations,
			ops.ClusterOperationState{Operation: operation, Progress: *progress})
	}
	var operation *ops.SiteOperation
	var progress *ops.ProgressEntry
	// if operation ID is provided, get info for that operation, otherwise
	// get info for the most recent operation
	if req.OperationID != "" {
		operation, progress, err = ops.GetOperationWithProgress(
			cluster.OperationKey(req.OperationID), o)
	} else {
		operation, progress, err = ops.GetLastCompletedOperation(
			cluster.Key(), o)
	}
	if err != nil {
		return status, trace.Wrap(err)
	}
	status.Operation = &ops.ClusterOperationState{Operation: *operation, Progress: *progress}
	// FIXME

	status.Agent, err = agent.FromPlanetAgent(ctx, cluster.ClusterState.Servers)
	if err != nil {
		return status, trace.Wrap(err)
	}

	// Collect registered Teleport nodes
	teleportNodes, err := o.GetClusterNodes(cluster.Key())
	if err != nil {
		return status, trace.Wrap(err, "failed to query teleport nodes")
	}
	for i, node := range status.Agent.Nodes {
		status.Agent.Nodes[i].TeleportNode = findTeleportNode(teleportNodes, node.AdvertiseIP)
	}
	return status, nil
}

// canActivate retursn true if the cluster is disabled b/c of status checks
func (s *site) canActivate() bool {
	return s.backendSite.State == ops.SiteStateDegraded &&
		s.backendSite.Reason != storage.ReasonLicenseInvalid
}

// checkPlanetStatus checks the cluster health using planet agents
func (s *site) checkPlanetStatus(ctx context.Context) error {
	planetStatus, err := agent.FromPlanetAgent(ctx, nil)
	if err != nil {
		return trace.Wrap(err)
	}
	if planetStatus.GetSystemStatus() != agentpb.SystemStatus_Running {
		return trace.BadParameter("cluster is not healthy: %#v", planetStatus)
	}
	return nil
}

// checkStatusHook executes the application's status hook
func (s *site) checkStatusHook(ctx context.Context) error {
	if !s.app.Manifest.HasHook(schema.HookStatus) {
		s.Debugf("Application %s does not have status hook.", s.app)
		return nil
	}
	ref, out, err := app.RunAppHook(ctx, s.service.cfg.Apps, app.HookRunRequest{
		Application: s.backendSite.App.Locator(),
		Hook:        schema.HookStatus,
		ServiceUser: s.serviceUser(),
	})
	if ref != nil {
		err := s.service.cfg.Apps.DeleteAppHookJob(ctx, app.DeleteAppHookJobRequest{
			HookRef: *ref,
			Cascade: true,
		})
		if err != nil {
			s.Warnf("Failed to delete status hook %v: %v.",
				ref, trace.DebugReport(err))
		}
	}
	if err != nil {
		return trace.Wrap(err, "status hook failed: %s", out)
	}
	return nil
}

func findTeleportNode(nodes ops.Nodes, nodeAddr string) *agent.TeleportNode {
	node := nodes.FindByIP(nodeAddr)
	if node == nil {
		return nil
	}
	return &agent.TeleportNode{
		AdvertiseIP:  node.AdvertiseIP,
		Hostname:     node.Hostname,
		PublicIP:     node.PublicIP,
		Profile:      node.Profile,
		InstanceType: node.InstanceType,
	}
}
