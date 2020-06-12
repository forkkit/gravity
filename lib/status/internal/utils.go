package internal

import (
	"encoding/json"
	"fmt"

	"github.com/gravitational/gravity/lib/defaults"
	"github.com/gravitational/gravity/lib/state"
	"github.com/gravitational/gravity/lib/utils"
	pb "github.com/gravitational/satellite/agent/proto/agentpb"

	"github.com/gravitational/satellite/monitoring"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
)

// ProbeErrorDetail describes the failed probe
func ProbeErrorDetail(p pb.Probe) string {
	if p.Checker == monitoring.DiskSpaceCheckerID {
		detail, err := diskSpaceProbeErrorDetail(p)
		if err == nil {
			return detail
		}
		logrus.Warnf(trace.DebugReport(err))
	}
	detail := p.Detail
	if p.Detail == "" {
		detail = p.Checker
	}
	return fmt.Sprintf("%v (%v)", detail, p.Error)
}

// diskSpaceProbeErrorDetail returns an appropriate error message for disk
// space checker probe
//
// The reason is that state directory disk space checker always checks
// /var/lib/gravity which is default path inside planet but may be different
// on host so determine the real state directory if needed
func diskSpaceProbeErrorDetail(p pb.Probe) (string, error) {
	var data monitoring.HighWatermarkCheckerData
	err := json.Unmarshal(p.CheckerData, &data)
	if err != nil {
		return "", trace.Wrap(err)
	}
	// not state directory checker, return error as-is
	if data.Path != defaults.GravityDir {
		return p.Detail, nil
	}
	// if status command was run inside planet, the default error message is fine
	if utils.CheckInPlanet() {
		return p.Detail, nil
	}
	// otherwise determine the real state directory on host and reconstruct the message
	data.Path, err = state.GetStateDir()
	if err != nil {
		return "", trace.Wrap(err)
	}

	if p.Severity == pb.Probe_Critical {
		return data.CriticalMessage(), nil
	}

	if p.Severity == pb.Probe_Warning {
		return data.WarningMessage(), nil
	}

	return "", trace.BadParameter("probe does not have warning or critical severity")
}
