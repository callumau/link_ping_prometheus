package prober

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"
)

// TargetStatus is a live snapshot of one target's probe-loop state,
// served as JSON at /status so operators can debug a flapping target
// without log access.
type TargetStatus struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	LinkUp  bool   `json:"link_up"`
	// SendFailures is the CURRENT consecutive local write-failure streak
	// (reset to 0 by the first successful send), not a lifetime total. The
	// JSON field name is kept as-is for existing consumers.
	SendFailures      int     `json:"send_failures"`
	Pending           int     `json:"probes_inflight"`
	ConsecutiveMisses int     `json:"consecutive_misses"`
	RTOSeconds        float64 `json:"rto_seconds"`
	JitterSeconds     float64 `json:"jitter_seconds"`
	SRTTSeconds       float64 `json:"srtt_seconds"`
	LastSeq           uint64  `json:"last_seq"`
	SocketAgeSeconds  float64 `json:"socket_age_seconds"`
	// PathMTUBytes is the largest DF frame the MTU sweep proved
	// round-trips; 0 = no successful sweep yet. LastEchoAgeSeconds is
	// seconds since the last matched echo, -1 when none has arrived.
	PathMTUBytes       int     `json:"path_mtu_bytes"`
	LastEchoAgeSeconds float64 `json:"last_echo_age_seconds"`
}

// StatusRegistry collects per-target live state from the probe loops.
// Updates happen once per probe interval (not per packet), so a single
// mutex is plenty even at MaxTargetsCount targets.
type StatusRegistry struct {
	mu      sync.Mutex
	targets map[string]TargetStatus
}

// NewStatusRegistry returns an empty registry.
func NewStatusRegistry() *StatusRegistry {
	return &StatusRegistry{targets: make(map[string]TargetStatus)}
}

// Update stores a snapshot keyed by target name. Nil-receiver safe so
// call sites never need a nil check (registry absent in server-only
// mode and most unit tests).
func (r *StatusRegistry) Update(s TargetStatus) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.targets[s.Name] = s
}

// Remove drops a target's snapshot so a target deleted from the targets
// file does not linger as a ghost at /status. Nil-receiver safe, like
// Update: callers never need a nil check.
func (r *StatusRegistry) Remove(name string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.targets, name)
}

// Snapshot returns all target states sorted by name. An empty registry
// yields an empty, non-nil slice so the JSON endpoint renders "targets": [].
func (r *StatusRegistry) Snapshot() []TargetStatus {
	if r == nil {
		return []TargetStatus{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]TargetStatus, 0, len(r.targets))
	for _, s := range r.targets {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Handler serves the registry snapshot as JSON.
func (r *StatusRegistry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string][]TargetStatus{"targets": r.Snapshot()})
	})
}
