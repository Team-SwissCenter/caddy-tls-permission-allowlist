// Package allowlist implements a Caddy on-demand TLS permission module that
// answers from an allow-list file held in memory.
//
// # Why
//
// Caddy consults the on-demand permission module on every handshake for a name
// it does not already hold in memory -- including names whose certificate is
// already in storage, because the module gates loading from storage as well as
// issuance. With the stock "ask" module that makes an HTTP endpoint a hard,
// per-handshake dependency for TLS on every site: while the endpoint is
// unreachable or returning errors, even certificates you already hold cannot be
// served. See https://caddy.community/t/33898.
//
// This module removes the endpoint. The list is read into memory, every
// decision is a map lookup, and there is no listener that can be down.
package allowlist

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
	"golang.org/x/net/idna"
)

// hostnames validates and maps an allow-list entry the way certmagic maps an
// SNI before asking for permission -- the idna.Lookup rules: STD3 characters
// only, hyphen and joiner placement, bidi -- plus the DNS length limits that
// profile leaves out. The two sides must agree, or an entry never matches the
// name a handshake actually carries.
var hostnames = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.VerifyDNSLength(true))

const (
	defaultReloadInterval = 2 * time.Second

	// snapshotKey is where the last good list is kept in Caddy's storage. A
	// distinct top-level prefix, so certificate maintenance never touches it.
	snapshotKey = "permission_allowlist/snapshot"

	// certsPrefix is certmagic's top-level storage prefix for certificates.
	certsPrefix = "certificates"

	// How often to repeat the "running degraded" complaint. Degradation is a
	// condition, not an event: logged once at startup it would scroll away, and
	// any time-windowed alert would watch itself resolve while the degradation
	// continued.
	degradedLogEvery = 5 * time.Minute

	// How often the watch goroutine relists the certificates in storage. Only
	// while there is no allow-list at all and on_empty=storage, so this trades
	// a rare relisting for picking up a certificate a cluster peer obtained
	// after the degradation began.
	certListEvery = time.Minute

	// How many consecutive failed polls demote a list read from the source to
	// "stale". A single bad poll is what a publisher that truncates and
	// rewrites in place looks like; that must not flip /status or fire the
	// alert for a 2s blip. The error itself is recorded at once.
	staleAfterFailures = 2

	// OnEmpty modes.
	onEmptyDeny    = "deny"
	onEmptyStorage = "storage"
	onEmptyAllow   = "allow"

	sourcePrimary  = "primary"
	sourceStale    = "stale"
	sourceSnapshot = "snapshot"
	sourceNone     = "none"
)

func init() {
	// Registered as a pointer: the struct carries a mutex, so a value receiver
	// on CaddyModule would copy the lock.
	caddy.RegisterModule(new(Permission))
}

// Permission decides whether a certificate may be obtained or loaded for a
// hostname, from an allow-list file held in memory.
type Permission struct {
	// Source is the allow-list file: one hostname per line. Blank lines and
	// lines beginning with '#' are ignored, names are matched
	// case-insensitively, and a trailing dot is tolerated. Required.
	Source string `json:"source,omitempty"`

	// Snapshot keeps a copy of the last successfully loaded list in Caddy's
	// storage, and loads it at startup if the source cannot be read. Enabled by
	// default.
	//
	// The in-memory list survives a reload but not a restart, and a restart is
	// exactly when the source is most likely to be disturbed as well -- an
	// unattended package upgrade restarts Caddy. Without a snapshot, such a
	// restart means no allow-list at all.
	Snapshot *bool `json:"snapshot,omitempty"`

	// OnEmpty decides what happens when NEITHER the source nor the snapshot
	// could be loaded, i.e. there is no allow-list at all.
	//
	//	deny    (default) refuse every name. Safe, but a total TLS outage.
	//	storage allow a name only if a certificate for it is already in
	//	        storage: everything currently being served keeps working and
	//	        nothing new is issued. Recommended.
	//	allow   allow every name. Dangerous -- see below.
	//
	// Why "allow" is dangerous: granting permission makes Caddy attempt
	// ISSUANCE for every name presented to it, and a host exposed to the
	// internet sees a large volume of bogus SNI. Let's Encrypt permits 300 new
	// orders per account per 3 hours, and the limit is ACCOUNT-wide, so a few
	// minutes of this can block renewals for real domains for hours -- long
	// after the list was repaired. It converts a brief list problem into a
	// longer and wider outage.
	//
	// "storage" gives the same protection without that risk: keep serving
	// certificates already held, issue nothing new.
	OnEmpty string `json:"on_empty,omitempty"`

	// ReloadInterval is how often the source is re-read and hashed. The list is
	// only rebuilt when the CONTENT changed. Default 2s.
	//
	// Deliberately a poll rather than inotify. A publisher that writes
	// atomically replaces the file by rename, and an inotify watch follows the
	// INODE -- a watch on the file keeps watching the old, unlinked one and
	// never fires again. Correct inotify means watching the directory for
	// IN_MOVED_TO, and it can still silently miss events on queue overflow, so
	// a poll backstop is needed regardless.
	//
	// Deliberately hashing the content rather than comparing size/mtime/inode:
	// every metadata scheme leaves a residue. An in-place write with an
	// identical size and a restored mtime (rsync --inplace -t, or any tool that
	// preserves timestamps) changes none of the three and would be missed
	// forever. Hashing also avoids rebuilding the list when a publisher rewrites
	// the file unconditionally with identical content.
	ReloadInterval caddy.Duration `json:"reload_interval,omitempty"`

	logger  *zap.Logger
	storage certmagic.Storage
	stop    chan struct{}

	mu    sync.RWMutex
	names map[string]struct{}
	// certs maps a storage-safe name to its site prefix in storage, for every
	// certificate held there. Maintained by the watch goroutine only while
	// there is no list at all and on_empty=storage; nil otherwise.
	certs map[string]string
	state State

	// Poll bookkeeping, owned by the watch goroutine (loadInitial runs before
	// it starts). sourceFailures is also written under mu by
	// recordSourceResult, which is only ever called from that goroutine.
	lastHash       [32]byte
	sourceFailures int
	certsListedAt  time.Time
	lastLogged     map[string]time.Time
}

// State is the module's externally visible health, served by the admin route.
type State struct {
	// From is "primary", "stale", "snapshot" or "none". Anything but "primary"
	// means decisions are being made from stale or absent data.
	//
	// "stale" is the last good list read from the source, still being served
	// while the source itself has become unreadable or unusable for more than
	// a single poll.
	From string `json:"from"`

	Path     string `json:"path,omitempty"`
	Entries  int    `json:"entries"`
	LoadedAt int64  `json:"loaded_at,omitempty"`

	// Error is why the most recent load of the source failed, if it did. It is
	// kept even while serving happily from a snapshot.
	Error string `json:"error,omitempty"`

	// OnEmpty is echoed back so monitoring can tell whether this instance would
	// fail open or closed without reading the config.
	OnEmpty string `json:"on_empty,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (*Permission) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.permission.allowlist",
		New: func() caddy.Module { return new(Permission) },
	}
}

// Provision validates the config, loads the list and starts the watch.
func (p *Permission) Provision(ctx caddy.Context) error {
	p.logger = ctx.Logger()
	p.storage = ctx.Storage()

	if p.Source == "" {
		return fmt.Errorf("source is required")
	}
	if p.ReloadInterval == 0 {
		p.ReloadInterval = caddy.Duration(defaultReloadInterval)
	}
	if p.ReloadInterval < 0 {
		return fmt.Errorf("reload_interval must not be negative")
	}
	switch p.OnEmpty {
	case "":
		p.OnEmpty = onEmptyDeny
	case onEmptyDeny, onEmptyStorage, onEmptyAllow:
	default:
		return fmt.Errorf("on_empty must be %q, %q or %q, got %q",
			onEmptyDeny, onEmptyStorage, onEmptyAllow, p.OnEmpty)
	}
	if p.OnEmpty == onEmptyAllow {
		// Logged at ERROR rather than Warn on purpose: a deployment running at
		// log level ERROR would not see a Warn, and this is a standing hazard
		// on exactly those hosts.
		p.logger.Error("on_empty=allow: if the allow-list becomes unavailable this instance will "+
			"attempt certificate issuance for EVERY name presented to it, which can exhaust the "+
			"ACME account order rate limit and block renewals for real domains",
			zap.String("safer_alternative", onEmptyStorage))
	}

	p.names = make(map[string]struct{})
	p.stop = make(chan struct{})

	p.loadInitial(ctx)
	go p.watch()

	registerState(p)
	return nil
}

// Cleanup stops the watch and withdraws this instance from the admin route.
func (p *Permission) Cleanup() error {
	if p.stop != nil {
		close(p.stop)
	}
	unregisterState(p)
	return nil
}

// snapshotEnabled reports whether the snapshot is configured AND usable. Caddy
// always provides storage, so the nil case only arises for a bare test
// instance; the rule still lives here rather than as a guard at every call site.
func (p *Permission) snapshotEnabled() bool {
	return (p.Snapshot == nil || *p.Snapshot) && p.storage != nil
}

// CertificateAllowed implements caddytls.OnDemandPermission.
//
// Note the two kinds of refusal. A name that is simply not on the list is an
// ordinary denial, wrapped in ErrPermissionDenied, which Caddy logs at debug --
// so the constant background of requests for names you do not host produces no
// noise. Having no list at all is NOT a denial: it is a failure of this module,
// and is returned as a plain error, which Caddy logs at ERROR. Failing closed
// stays loud. An HTTP endpoint cannot make this distinction: there, every
// response including 500 and 503 is treated as a denial and logged at debug.
func (p *Permission) CertificateAllowed(ctx context.Context, name string) error {
	normalized := normalize(name)

	p.mu.RLock()
	_, ok := p.names[normalized]
	from := p.state.From
	p.mu.RUnlock()

	if from == sourceNone {
		return p.decideWithoutList(ctx, normalized)
	}
	if ok {
		return nil
	}
	return fmt.Errorf("%w: %s is not in %s", caddytls.ErrPermissionDenied, name, p.Source)
}

// decideWithoutList applies the OnEmpty policy. Every refusal returns a plain
// (non-ErrPermissionDenied) error so Caddy logs it at ERROR.
func (p *Permission) decideWithoutList(ctx context.Context, name string) error {
	switch p.OnEmpty {
	case onEmptyAllow:
		return nil

	case onEmptyStorage:
		if p.haveCertFor(ctx, name) {
			return nil
		}
		return fmt.Errorf("no allow-list loaded (%s unreadable or empty) and no certificate "+
			"in storage for %s; refusing", p.Source, name)

	default:
		return fmt.Errorf("no allow-list loaded (%s unreadable or empty); refusing all "+
			"certificates", p.Source)
	}
}

// haveCertFor reports whether a certificate for name is in storage.
//
// Answered from a set the watch goroutine maintains (see maybeRefreshCerts),
// the same way every other decision in this module is made. Caddy consults a
// permission module on every handshake for a name it does not already hold, and
// a DENIED name is never loaded, so it is asked again on the very next handshake
// -- forever. A public host sees a constant flood of bogus SNI, and this runs
// precisely while the module is already degraded, so a denial must not cost a
// storage round trip.
//
// A stored wildcard covers its subdomains: certmagic falls back to the
// "*.<parent>" certificate when loading, so the answer here has to agree or
// every name behind a wildcard is refused.
//
// A hit is confirmed against storage before it is granted. A grant makes Caddy
// load the certificate -- or, if it is gone, ISSUE one -- and the set can be up
// to certListEvery old, long enough for the storage cleaner to have removed it.
// Only grants pay this, and at most once: a granted name is loaded into Caddy's
// cache and not asked about again.
func (p *Permission) haveCertFor(ctx context.Context, name string) bool {
	p.mu.RLock()
	certs := p.certs
	p.mu.RUnlock()
	for _, candidate := range []string{name, wildcardOf(name)} {
		site, ok := certs[certmagic.StorageKeys.Safe(candidate)]
		if ok && p.storage.Exists(ctx, certFileIn(site)) {
			return true
		}
	}
	return false
}

// wildcardOf returns the wildcard name certmagic would try in place of name.
func wildcardOf(name string) string {
	labels := strings.Split(name, ".")
	labels[0] = "*"
	return strings.Join(labels, ".")
}

// certFileIn returns the certificate key within a site prefix as listed from
// storage: certmagic keeps it as <site>/<safe name>.crt.
func certFileIn(site string) string {
	return path.Join(site, path.Base(site)+".crt")
}

// maybeRefreshCerts relists storage when the module is deciding from it and the
// last listing is old enough. Off the handshake path by construction: called
// from loadInitial and from the watch goroutine, never from a handshake, so a
// slow or large backend costs latency nowhere a client can see it, and a
// client's context can never cancel it half way.
//
// A failed listing keeps the last good set and is retried next tick, exactly as
// a failed source read keeps the last good list. A failure is never remembered
// as the answer -- that would make on_empty=storage behave like deny for the
// life of the process, the outage the option exists to prevent.
func (p *Permission) maybeRefreshCerts(ctx context.Context) {
	p.mu.RLock()
	from := p.state.From
	p.mu.RUnlock()
	if from != sourceNone || p.OnEmpty != onEmptyStorage || p.storage == nil {
		return
	}
	if time.Since(p.certsListedAt) < certListEvery {
		return
	}
	certs, err := p.listCerts(ctx)
	if err != nil {
		if p.shouldLog("certs:" + err.Error()) {
			p.logger.Error("cannot list certificate storage", zap.Error(err))
		}
		return
	}
	p.certsListedAt = time.Now()
	p.mu.Lock()
	p.certs = certs
	p.mu.Unlock()
}

// listCerts enumerates the certificates in storage the way certmagic's own
// storage walker does: the issuers under "certificates", then the site prefixes
// under each, both non-recursive -- the only listing shape every backend has to
// support -- and a site key's last component is already the sanitized name.
// Storage is addressed through Caddy's abstraction rather than filesystem paths,
// so this works on any backend.
//
// A store that has never held a certificate has no "certificates" prefix at all
// (FileStorage creates it on the first Store) and lists as ErrNotExist. That is
// an empty set, not a failure; certmagic treats the same call the same way.
//
// A partial listing is discarded rather than returned: half a set would answer
// "no certificate" for names we are holding, which during degradation is the
// wrong direction to fail in.
func (p *Permission) listCerts(ctx context.Context) (map[string]string, error) {
	issuers, err := p.storage.List(ctx, certsPrefix, false)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	certs := make(map[string]string)
	for _, issuer := range issuers {
		sites, err := p.storage.List(ctx, issuer, false)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("listing %s: %w", issuer, err)
		}
		for _, site := range sites {
			certs[path.Base(site)] = site
		}
	}
	return certs, nil
}

// normalize lowercases and strips a trailing dot. Caddy normalizes the SNI
// before asking, but the list is normalized on load so both sides must agree
// regardless of what the file contains.
func normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
}

// loadInitial fills the list at startup: the source if usable, otherwise the
// snapshot, otherwise nothing -- and then every decision follows OnEmpty.
func (p *Permission) loadInitial(ctx context.Context) {
	defer p.maybeRefreshCerts(ctx)

	raw, err := os.ReadFile(p.Source)
	if err == nil {
		if err = p.adopt(ctx, raw, p.Source, sourcePrimary); err == nil {
			p.lastHash = hashOf(raw)
			p.recordSourceResult(nil)
			return
		}
	}
	p.recordSourceResult(err)
	p.logger.Error("cannot load allow-list", zap.String("source", p.Source), zap.Error(err))
	p.shouldLog(reloadLogKey(err)) // the watch must not repeat that line 2s later

	if !p.snapshotEnabled() {
		p.logger.Error("no snapshot available; refusing certificates until the source is readable")
		return
	}
	snap, serr := p.storage.Load(ctx, snapshotKey)
	if serr == nil {
		serr = p.adopt(ctx, snap, snapshotKey, sourceSnapshot)
	}
	if serr != nil {
		p.logger.Error("snapshot unusable too; refusing certificates", zap.Error(serr))
		return
	}
	p.logger.Error("SERVING FROM SNAPSHOT: the allow-list source is unusable, decisions are "+
		"being made from a stale copy", zap.String("source", p.Source))
}

// adopt validates an already-read list and installs it.
//
// An empty list is treated as a failure, never as "deny everything". A truncated
// write, a broken generator or an empty input directory all produce an empty
// file, and adopting one would take every site offline until the next good
// write.
func (p *Permission) adopt(ctx context.Context, raw []byte, path, origin string) error {
	names, skipped, err := parse(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if len(names) == 0 {
		return fmt.Errorf("%s parsed to zero valid names; refusing to adopt an empty allow-list", path)
	}

	// Error is deliberately not touched here: recordSourceResult owns it. A
	// snapshot load keeps the reason we are on the snapshot at all, and /status
	// reporting a bare {"from":"snapshot"} would send the operator digging
	// through logs for it.
	p.mu.Lock()
	p.names = names
	p.certs = nil // a list is loaded; storage is no longer consulted
	p.state.From = origin
	p.state.Path = path
	p.state.Entries = len(names)
	p.state.LoadedAt = time.Now().Unix()
	p.mu.Unlock()

	p.logger.Info("loaded on-demand allow-list",
		zap.String("from", origin), zap.String("path", path), zap.Int("entries", len(names)))
	if len(skipped) > 0 {
		// ERROR rather than Warn for the same reason as elsewhere: a host
		// logging at ERROR must still see it. Not a flood: adopt runs only
		// when the content changes.
		p.logger.Error("skipped entries that are not valid hostnames; they could never be issued a certificate",
			zap.String("path", path), zap.Int("skipped", len(skipped)),
			zap.Strings("examples", skipped[:min(len(skipped), 5)]))
	}

	if origin == sourcePrimary && p.snapshotEnabled() {
		p.writeSnapshot(ctx, names)
	}
	return nil
}

func hashOf(raw []byte) [32]byte { return sha256.Sum256(raw) }

// parse splits raw into validated, normalized names, and returns the lines it
// skipped.
//
// Two kinds of bad line, treated differently. Bytes that are not text -- invalid
// UTF-8 or a control character -- are never legitimate here: the file is
// corrupt, and the whole of it is refused so the last good list and the
// snapshot survive. (Measured before this check existed: 2000 bytes of
// /dev/urandom were adopted as a healthy 13-entry list, every real site was
// refused after the next restart, and the snapshot was overwritten with the
// noise.) A line that is text but not a valid hostname -- an underscore, a
// misplaced hyphen, an over-long label -- can legitimately arrive from a
// customer's ServerAlias; such a name could never be issued a certificate
// anyway, so it is skipped and reported rather than freezing every other
// update on the host. Nothing valid left falls through to the empty-list rule.
//
// Entries are mapped the way certmagic maps an SNI before asking (lowercase,
// punycode), so an entry written in unicode matches the handshake's name.
func parse(raw []byte) (names map[string]struct{}, skipped []string, err error) {
	if !utf8.Valid(raw) {
		return nil, nil, errors.New("not valid UTF-8; refusing to adopt a corrupt allow-list")
	}
	names = make(map[string]struct{})
	for n, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.ContainsFunc(line, unicode.IsControl) {
			return nil, nil, fmt.Errorf("line %d contains control characters; refusing to adopt a corrupt allow-list", n+1)
		}
		name, err := hostnames.ToASCII(normalize(line))
		if err != nil {
			skipped = append(skipped, line)
			continue
		}
		names[name] = struct{}{}
	}
	return names, skipped, nil
}

// writeSnapshot persists the current good list, sorted and normalized. Only ever
// called for a validated load, so a bad state is never persisted as the thing we
// would fall back to.
func (p *Permission) writeSnapshot(ctx context.Context, names map[string]struct{}) {
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)

	if err := p.storage.Store(ctx, snapshotKey, []byte(strings.Join(sorted, "\n")+"\n")); err != nil {
		p.logger.Error("cannot write snapshot", zap.Error(err))
	}
}

func (p *Permission) watch() {
	ticker := time.NewTicker(time.Duration(p.ReloadInterval))
	defer ticker.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
			p.checkOnce(context.Background())
		}
	}
}

func (p *Permission) checkOnce(ctx context.Context) {
	p.checkSource(ctx)
	p.maybeRefreshCerts(ctx)
	p.complainIfDegraded()
}

// checkSource re-reads the source and adopts it if the content changed.
func (p *Permission) checkSource(ctx context.Context) {
	raw, err := os.ReadFile(p.Source)
	if err != nil {
		p.recordSourceResult(err)
		p.logReloadFailure(err)
		return
	}
	if h := hashOf(raw); h != p.lastHash {
		if err := p.adopt(ctx, raw, p.Source, sourcePrimary); err != nil {
			// Keep the list we already have: a bad read must never cost us a
			// good one. This is the whole reason it is held in memory. The
			// hash is NOT recorded here, so a file that stays bad is retried
			// every interval rather than being written off as "already seen".
			p.recordSourceResult(err)
			p.logReloadFailure(err)
			return
		}
		p.lastHash = h
	}
	// The read succeeded. Unchanged content is a healthy source too: one
	// restored byte-identical must stop being reported as degraded.
	p.recordSourceResult(nil)
}

// recordSourceResult is the one transition for the outcome of reading the
// source, from loadInitial and from every poll.
//
// The invariant: a readable source vouches only for a list that came from the
// source. "primary" never carries an error; a failure demotes it to "stale"
// once the failure has persisted for staleAfterFailures polls. "snapshot" and
// "none" keep their reason until something is adopted from the source, because
// a readable source says nothing about data being served from somewhere else.
//
// Recovery also resets the log throttles: a condition that returns after
// clearing is new information and must announce itself at once, not wait out
// a budget the previous occurrence consumed.
func (p *Permission) recordSourceResult(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		p.state.Error = err.Error()
		p.sourceFailures++
		switch {
		case p.state.From == "":
			p.state.From = sourceNone
		case p.state.From == sourcePrimary && p.sourceFailures >= staleAfterFailures:
			p.state.From = sourceStale
		}
		return
	}
	p.sourceFailures = 0
	switch p.state.From {
	case sourceStale, sourcePrimary:
		p.state.From, p.state.Error = sourcePrimary, ""
		clear(p.lastLogged)
	}
}

// logReloadFailure reports a failed poll at ERROR, worded for the state the
// module is actually in, and throttled: the poll runs every ReloadInterval and
// a source that stays broken stays broken, so one line per attempt is tens of
// thousands of identical lines a day burying the DEGRADED line that reports
// the same condition.
func (p *Permission) logReloadFailure(err error) {
	if !p.shouldLog(reloadLogKey(err)) {
		return
	}
	p.mu.RLock()
	from := p.state.From
	p.mu.RUnlock()
	fields := []zap.Field{zap.String("source", p.Source), zap.Error(err)}
	switch from {
	case sourceNone:
		p.logger.Error("cannot load allow-list; no list is loaded and decisions follow on_empty",
			append(fields, zap.String("on_empty", p.OnEmpty))...)
	case sourceSnapshot:
		p.logger.Error("cannot load allow-list; still serving from the snapshot", fields...)
	default:
		p.logger.Error("reload failed, keeping the previously loaded list", fields...)
	}
}

func reloadLogKey(err error) string { return "reload:" + err.Error() }

// shouldLog rate-limits a standing condition's ERROR line to one per
// degradedLogEvery for the same key. A different key -- a different error text
// -- is new information and logs at once; so does every key after the source
// recovers, because recordSourceResult clears the table.
//
// Owned by the watch goroutine, like the rest of the poll bookkeeping.
func (p *Permission) shouldLog(key string) bool {
	if time.Since(p.lastLogged[key]) < degradedLogEvery {
		return false
	}
	if p.lastLogged == nil {
		p.lastLogged = make(map[string]time.Time)
	}
	p.lastLogged[key] = time.Now()
	return true
}

func (p *Permission) complainIfDegraded() {
	p.mu.RLock()
	from, entries := p.state.From, p.state.Entries
	p.mu.RUnlock()
	if from == sourcePrimary || !p.shouldLog("degraded") {
		return
	}
	p.logger.Error("on-demand permission is DEGRADED",
		zap.String("from", from), zap.Int("entries", entries),
		zap.String("source", p.Source), zap.String("on_empty", p.OnEmpty))
}

// UnmarshalCaddyfile parses:
//
//	permission allowlist {
//	    source          /path/to/allowlist.txt
//	    snapshot        true
//	    on_empty        deny|storage|allow
//	    reload_interval 2s
//	}
func (p *Permission) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume the module name
	for d.NextBlock(0) {
		switch d.Val() {
		case "source":
			if !d.NextArg() {
				return d.ArgErr()
			}
			p.Source = d.Val()
		case "snapshot":
			if !d.NextArg() {
				return d.ArgErr()
			}
			switch d.Val() {
			case "true", "on", "yes":
				v := true
				p.Snapshot = &v
			case "false", "off", "no":
				v := false
				p.Snapshot = &v
			default:
				return d.Errf("snapshot must be true or false, got '%s'", d.Val())
			}
		case "on_empty":
			if !d.NextArg() {
				return d.ArgErr()
			}
			p.OnEmpty = d.Val()
		case "reload_interval":
			if !d.NextArg() {
				return d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return d.Errf("bad reload_interval: %v", err)
			}
			p.ReloadInterval = caddy.Duration(dur)
		default:
			return d.Errf("unrecognized option '%s'", d.Val())
		}
	}
	return nil
}

var (
	_ caddy.Module                = (*Permission)(nil)
	_ caddy.Provisioner           = (*Permission)(nil)
	_ caddy.CleanerUpper          = (*Permission)(nil)
	_ caddyfile.Unmarshaler       = (*Permission)(nil)
	_ caddytls.OnDemandPermission = (*Permission)(nil)
)
