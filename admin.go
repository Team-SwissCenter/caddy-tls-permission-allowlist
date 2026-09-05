package allowlist

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sync"

	"github.com/caddyserver/caddy/v2"
)

// The admin route exists because "running from a snapshot" is a STATE, not an
// event. A log line at startup scrolls away, and a monitoring check that reads a
// time window would watch its own alert resolve while the degradation continued.
// Querying state is always current.
//
// Admin API modules are instantiated by Caddy automatically and need no config,
// so the endpoint is available as soon as the module is in the binary:
//
//	curl -s http://localhost:2019/permission-allowlist/status
//	{"from":"primary","path":"/etc/caddy/allowlist.txt","entries":1234,"loaded_at":1788600000,"on_empty":"deny"}

func init() {
	caddy.RegisterModule(adminAPI{})
}

var errMethodNotAllowed = errors.New("method not allowed")

// Package-level, because the admin module and the permission module are separate
// module instances with no reference to each other.
//
// A stack rather than a single pointer, because of how Caddy reloads: the new
// config's modules are provisioned -- and register here -- BEFORE the old ones
// are cleaned up. On success the old instance is then cleaned up and the new
// one is the survivor. If the new config fails to start, Caddy cleans up only
// the NEW instance and the old one keeps serving every handshake. A single
// pointer cleared by whichever instance is cleaned up would report
// "not_configured" for a module that is live. In both orders the most recently
// registered instance still standing is the one serving.
var (
	stateMu sync.RWMutex
	live    []*Permission
)

func registerState(p *Permission) {
	stateMu.Lock()
	live = append(live, p)
	stateMu.Unlock()
}

func unregisterState(p *Permission) {
	stateMu.Lock()
	live = slices.DeleteFunc(live, func(q *Permission) bool { return q == p })
	stateMu.Unlock()
}

// activeState returns the instance currently serving, or nil.
func activeState() *Permission {
	stateMu.RLock()
	defer stateMu.RUnlock()
	if len(live) == 0 {
		return nil
	}
	return live[len(live)-1]
}

type adminAPI struct{}

func (adminAPI) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.permission_allowlist",
		New: func() caddy.Module { return new(adminAPI) },
	}
}

func (a adminAPI) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{
			Pattern: "/permission-allowlist/status",
			Handler: caddy.AdminHandlerFunc(a.status),
		},
	}
}

func (adminAPI) status(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return caddy.APIError{HTTPStatus: http.StatusMethodNotAllowed, Err: errMethodNotAllowed}
	}

	p := activeState()

	w.Header().Set("Content-Type", "application/json")

	// Reported rather than 404'd, so a monitoring check can tell "this instance
	// does not use the module" apart from "the endpoint is missing", which would
	// otherwise look identical.
	if p == nil {
		return json.NewEncoder(w).Encode(State{From: "not_configured"})
	}

	p.mu.RLock()
	st := p.state
	p.mu.RUnlock()
	st.OnEmpty = p.OnEmpty

	return json.NewEncoder(w).Encode(st)
}

var _ caddy.AdminRouter = (*adminAPI)(nil)
