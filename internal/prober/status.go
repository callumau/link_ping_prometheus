package prober

import (
	"encoding/json"
	"net/http"
	"runtime"
	"sort"
	"sync"
	"time"
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

// AnyReady reports whether any target currently holds a working socket
// (socket_age_seconds > 0) — the condition /readyz is built on. It iterates in
// place and returns on the first hit: /readyz is deliberately unauthenticated
// AND uncapped, so copying and sorting the whole registry per request (an
// orchestrator probes it every few seconds; ~100KB plus a sort at 1000
// targets) is real garbage on a process whose job is measuring RTT.
func (r *StatusRegistry) AnyReady() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.targets {
		if s.SocketAgeSeconds > 0 {
			return true
		}
	}
	return false
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

// ProcessStatus is a snapshot of the agent's own runtime memory and
// goroutine counts, served as the /status "process" object. It exists to
// make the scrape-driven heap high-water mark observable remotely: a
// heap_sys_bytes that climbs with a flat heap_alloc_bytes and near-zero
// heap_released_bytes is the signature of a heap the runtime has stopped
// returning to the OS (Windows reports it as RSS/commit growth).
type ProcessStatus struct {
	HeapAllocBytes    uint64 `json:"heap_alloc_bytes"`
	HeapSysBytes      uint64 `json:"heap_sys_bytes"`
	HeapIdleBytes     uint64 `json:"heap_idle_bytes"`
	HeapReleasedBytes uint64 `json:"heap_released_bytes"`
	StackInuseBytes   uint64 `json:"stack_inuse_bytes"`
	GCSysBytes        uint64 `json:"gc_sys_bytes"`
	SysBytes          uint64 `json:"sys_bytes"`
	GCCount           uint32 `json:"gc_count"`
	Goroutines        int    `json:"goroutines"`
}

// processStatusTTL bounds how often /status pays for runtime.ReadMemStats.
// That call STOPS THE WORLD to produce consistent numbers, and /status (unlike
// /metrics) has no concurrency cap and is reachable without credentials when
// no metrics auth is configured — so a burst of requests would inject pauses
// into a process whose whole purpose is measuring RTT, inflating its own
// samples. One second keeps the readout fresh while bounding the cost to one
// ReadMemStats per second regardless of request rate.
const processStatusTTL = time.Second

var (
	procStatusMu sync.Mutex
	procStatus   ProcessStatus
	procStatusAt time.Time
)

// ReadProcessStatus snapshots the current process runtime state, cached for
// processStatusTTL (see above).
func ReadProcessStatus() ProcessStatus {
	procStatusMu.Lock()
	defer procStatusMu.Unlock()
	if time.Since(procStatusAt) < processStatusTTL {
		return procStatus
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	procStatus = ProcessStatus{
		HeapAllocBytes:    m.HeapAlloc,
		HeapSysBytes:      m.HeapSys,
		HeapIdleBytes:     m.HeapIdle,
		HeapReleasedBytes: m.HeapReleased,
		StackInuseBytes:   m.StackInuse,
		GCSysBytes:        m.GCSys,
		SysBytes:          m.Sys,
		GCCount:           m.NumGC,
		Goroutines:        runtime.NumGoroutine(),
	}
	procStatusAt = time.Now()
	return procStatus
}

// Handler serves the registry snapshot plus the process runtime state as
// JSON. A nil receiver still answers with an empty target list.
func (r *StatusRegistry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"targets": r.Snapshot(),
			"process": ReadProcessStatus(),
		})
	})
}
