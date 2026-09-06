package allowlist

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestNormalize(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"example.com", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"Example.Com", "example.com"},
		{"example.com.", "example.com"},    // trailing dot from a fully qualified SNI
		{"  example.com  ", "example.com"}, // stray whitespace in the file
		{"", ""},
	} {
		if got := normalize(tc.in); got != tc.want {
			t.Errorf("normalize(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParse(t *testing.T) {
	names, skipped, err := parse([]byte("a.example.com\n\n# a comment\nB.EXAMPLE.COM\n  c.example.com  \na.example.com\n"))
	if err != nil || len(skipped) != 0 {
		t.Fatalf("clean input: err = %v, skipped = %v", err, skipped)
	}

	// Duplicates collapse, case folds, comments and blanks are skipped.
	if len(names) != 3 {
		t.Fatalf("got %d names, want 3: %v", len(names), names)
	}
	for _, want := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		if _, ok := names[want]; !ok {
			t.Errorf("missing %q", want)
		}
	}
}

func TestParseEmptyInputs(t *testing.T) {
	for _, in := range []string{"", "\n\n\n", "# only a comment\n", "   \n\t\n"} {
		if got, _, err := parse([]byte(in)); err != nil || len(got) != 0 {
			t.Errorf("parse(%q) = %v, %v, want empty and no error", in, got, err)
		}
	}
}

// newTestPermission returns a module wired up enough to exercise decisions,
// without a Caddy context.
func newTestPermission(t *testing.T, source string) *Permission {
	t.Helper()
	return &Permission{
		Source:  source,
		OnEmpty: onEmptyDeny,
		logger:  zap.NewNop(),
		names:   make(map[string]struct{}),
		state:   State{From: sourceNone},
	}
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAdoptRejectsEmptyList(t *testing.T) {
	p := newTestPermission(t, "/nonexistent")

	if err := p.adopt(context.Background(), []byte("good.example.com\n"), "src", sourcePrimary); err != nil {
		t.Fatalf("adopt of a valid list failed: %v", err)
	}
	if p.state.Entries != 1 {
		t.Fatalf("entries = %d, want 1", p.state.Entries)
	}

	// An empty file must be refused rather than adopted as "deny everything":
	// a truncated write or a broken generator would otherwise take every site
	// offline until the next good write.
	err := p.adopt(context.Background(), []byte("\n# nothing\n"), "src", sourcePrimary)
	if err == nil {
		t.Fatal("adopt of an empty list succeeded, want error")
	}
	if p.state.Entries != 1 || p.state.From != sourcePrimary {
		t.Errorf("a rejected load changed state: %+v", p.state)
	}
	if _, ok := p.names["good.example.com"]; !ok {
		t.Error("a rejected load discarded the previously good list")
	}
}

func TestCertificateAllowed(t *testing.T) {
	p := newTestPermission(t, "src")
	if err := p.adopt(context.Background(), []byte("allowed.example.com\n"), "src", sourcePrimary); err != nil {
		t.Fatal(err)
	}

	if err := p.CertificateAllowed(context.Background(), "allowed.example.com"); err != nil {
		t.Errorf("listed name refused: %v", err)
	}
	// Caddy lowercases SNI before asking, but the module must not rely on it.
	if err := p.CertificateAllowed(context.Background(), "ALLOWED.example.com."); err != nil {
		t.Errorf("listed name refused when uppercased and dot-terminated: %v", err)
	}

	err := p.CertificateAllowed(context.Background(), "other.example.com")
	if err == nil {
		t.Fatal("unlisted name allowed")
	}
	// An ordinary denial must be ErrPermissionDenied, which Caddy logs at debug:
	// hosts see a constant background of requests for names they do not serve,
	// and that must not fill the error log.
	if !errors.Is(err, caddytls.ErrPermissionDenied) {
		t.Errorf("ordinary denial is not ErrPermissionDenied: %v", err)
	}
}

func TestNoListIsNotAnOrdinaryDenial(t *testing.T) {
	// Having no list at all is a failure of this module, not a policy decision.
	// It must NOT be ErrPermissionDenied, so that Caddy logs it at ERROR and
	// failing closed stays loud.
	p := newTestPermission(t, "src")

	err := p.CertificateAllowed(context.Background(), "anything.example.com")
	if err == nil {
		t.Fatal("allowed a name with no list loaded and on_empty=deny")
	}
	if errors.Is(err, caddytls.ErrPermissionDenied) {
		t.Error("no-list refusal is ErrPermissionDenied; it would be logged at debug and go unnoticed")
	}
}

func TestOnEmptyAllow(t *testing.T) {
	p := newTestPermission(t, "src")
	p.OnEmpty = onEmptyAllow

	if err := p.CertificateAllowed(context.Background(), "anything.example.com"); err != nil {
		t.Errorf("on_empty=allow refused a name: %v", err)
	}
}

func TestOnEmptyStorageWithoutStorage(t *testing.T) {
	// With no storage handle there is nothing to consult, so it must refuse
	// rather than fall open.
	p := newTestPermission(t, "src")
	p.OnEmpty = onEmptyStorage

	if err := p.CertificateAllowed(context.Background(), "anything.example.com"); err == nil {
		t.Error("on_empty=storage allowed a name with no storage available")
	}
}

func TestCheckOnceKeepsGoodListOnBadReload(t *testing.T) {
	dir := t.TempDir()
	src := writeFile(t, dir, "list.txt", "good.example.com\n")

	p := newTestPermission(t, src)
	p.loadFromSourceForTest(t)

	// Truncating the file must not cost us the good list.
	writeFile(t, dir, "list.txt", "")
	p.checkOnce(context.Background())

	if p.state.Entries != 1 {
		t.Errorf("entries = %d after a truncated reload, want 1", p.state.Entries)
	}
	if err := p.CertificateAllowed(context.Background(), "good.example.com"); err != nil {
		t.Errorf("previously good name refused after a truncated reload: %v", err)
	}
	if p.state.Error == "" {
		t.Error("state.Error is empty after a failed reload")
	}

	// ...and the module must recover once the file is good again, proving the
	// bad content was not recorded as "already seen".
	writeFile(t, dir, "list.txt", "recovered.example.com\n")
	p.checkOnce(context.Background())

	if err := p.CertificateAllowed(context.Background(), "recovered.example.com"); err != nil {
		t.Errorf("did not recover after the source was repaired: %v", err)
	}
	if p.state.Error != "" {
		t.Errorf("state.Error not cleared after a good reload: %q", p.state.Error)
	}
}

func TestCheckOnceSkipsRebuildWhenContentUnchanged(t *testing.T) {
	dir := t.TempDir()
	src := writeFile(t, dir, "list.txt", "a.example.com\n")

	p := newTestPermission(t, src)
	p.loadFromSourceForTest(t)
	first := p.state.LoadedAt

	// A publisher that rewrites the file unconditionally must not cause a
	// rebuild when the content is identical.
	time.Sleep(1100 * time.Millisecond)
	writeFile(t, dir, "list.txt", "a.example.com\n")
	p.checkOnce(context.Background())

	if p.state.LoadedAt != first {
		t.Error("rebuilt the list even though the content was unchanged")
	}

	// Changed content must be picked up, even though size and mtime could match.
	writeFile(t, dir, "list.txt", "b.example.com\n")
	p.checkOnce(context.Background())

	if err := p.CertificateAllowed(context.Background(), "b.example.com"); err != nil {
		t.Errorf("changed content not picked up: %v", err)
	}
}

// loadFromSourceForTest mimics the initial load without needing a caddy.Context.
func (p *Permission) loadFromSourceForTest(t *testing.T) {
	t.Helper()
	raw, err := os.ReadFile(p.Source)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.adopt(context.Background(), raw, p.Source, sourcePrimary); err != nil {
		t.Fatal(err)
	}
	p.lastHash = hashOf(raw)
}

func TestUnmarshalCaddyfile(t *testing.T) {
	d := caddyfile.NewTestDispenser(`allowlist {
		source /tmp/list.txt
		snapshot false
		on_empty storage
		reload_interval 5s
	}`)

	var p Permission
	if err := p.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.Source != "/tmp/list.txt" {
		t.Errorf("source = %q", p.Source)
	}
	if p.Snapshot == nil || *p.Snapshot {
		t.Error("snapshot should be explicitly false")
	}
	if p.OnEmpty != onEmptyStorage {
		t.Errorf("on_empty = %q", p.OnEmpty)
	}
	if time.Duration(p.ReloadInterval) != 5*time.Second {
		t.Errorf("reload_interval = %v", time.Duration(p.ReloadInterval))
	}
}

func TestUnmarshalCaddyfileRejects(t *testing.T) {
	for name, cfg := range map[string]string{
		"unknown option": "allowlist {\n nonsense yes\n}",
		"missing value":  "allowlist {\n source\n}",
		"bad snapshot":   "allowlist {\n snapshot maybe\n}",
		"bad duration":   "allowlist {\n reload_interval later\n}",
	} {
		var p Permission
		if err := p.UnmarshalCaddyfile(caddyfile.NewTestDispenser(cfg)); err == nil {
			t.Errorf("%s: accepted, want error", name)
		}
	}
}

func TestSnapshotEnabledDefault(t *testing.T) {
	p := Permission{storage: newStorage(t)}
	if !p.snapshotEnabled() {
		t.Error("snapshot should default to enabled")
	}
	no := false
	p.Snapshot = &no
	if p.snapshotEnabled() {
		t.Error("snapshot should be disabled when set to false")
	}
}

func TestSourceDisappearingMarksTheListStale(t *testing.T) {
	dir := t.TempDir()
	src := writeFile(t, dir, "list.txt", "good.example.com\n")

	p := newTestPermission(t, src)
	p.loadFromSourceForTest(t)

	if err := os.Remove(src); err != nil {
		t.Fatal(err)
	}
	p.checkOnce(context.Background())
	p.checkOnce(context.Background())

	// The last good list is still served, but it is no longer backed by a
	// readable source. Reporting "primary" here hides the degradation from
	// /status and stops the DEGRADED alert from ever firing.
	if p.state.From == sourcePrimary {
		t.Errorf("from = %q after the source was deleted, want a degraded value", p.state.From)
	}
	if p.state.Error == "" {
		t.Error("state.Error is empty after the source was deleted")
	}
	if err := p.CertificateAllowed(context.Background(), "good.example.com"); err != nil {
		t.Errorf("stale list no longer served: %v", err)
	}
}

func TestRestoringAnIdenticalSourceClearsDegradation(t *testing.T) {
	dir := t.TempDir()
	src := writeFile(t, dir, "list.txt", "good.example.com\n")

	p := newTestPermission(t, src)
	p.loadFromSourceForTest(t)

	if err := os.Remove(src); err != nil {
		t.Fatal(err)
	}
	p.checkOnce(context.Background())
	p.checkOnce(context.Background())

	// Restored with byte-identical content, so the content hash is unchanged
	// and no rebuild happens -- but the source is readable again and the module
	// must stop reporting itself degraded.
	writeFile(t, dir, "list.txt", "good.example.com\n")
	p.checkOnce(context.Background())

	if p.state.From != sourcePrimary {
		t.Errorf("from = %q after the source was restored, want %q", p.state.From, sourcePrimary)
	}
	if p.state.Error != "" {
		t.Errorf("state.Error not cleared after the source was restored: %q", p.state.Error)
	}
}

func TestReadableSourceVouchesOnlyForItsOwnList(t *testing.T) {
	// The rule recordSourceResult states once: a readable source vouches only
	// for a list that came from the source. Serving a snapshot, or nothing at
	// all, the recorded reason must survive a successful read that adopted
	// nothing -- otherwise /status drops the "why" while the "what" is
	// unchanged.
	for _, from := range []string{sourceSnapshot, sourceNone} {
		p := newTestPermission(t, "src")
		p.state = State{From: from, Error: "source unreadable at startup"}

		p.recordSourceResult(nil)

		if p.state.From != from {
			t.Errorf("from %q became %q on a read that adopted nothing", from, p.state.From)
		}
		if p.state.Error == "" {
			t.Errorf("from %q: the recorded reason was cleared by a read that adopted nothing", from)
		}
	}
}

func TestLoadInitialWithoutStorageDoesNotPanic(t *testing.T) {
	// Snapshot is enabled by default and Provision calls loadInitial, so an
	// unreadable source on an instance with no storage handle must degrade to
	// "no list", not take the whole process down.
	p := newTestPermission(t, filepath.Join(t.TempDir(), "missing.txt"))
	p.state = State{}

	p.loadInitial(context.Background())

	if p.state.From != sourceNone {
		t.Errorf("from = %q, want %q", p.state.From, sourceNone)
	}
	if p.state.Error == "" {
		t.Error("state.Error is empty after the source could not be read")
	}
}

func TestReloadFailureIsNotLoggedEveryTick(t *testing.T) {
	core, logs := observer.New(zapcore.ErrorLevel)
	dir := t.TempDir()
	src := writeFile(t, dir, "list.txt", "good.example.com\n")

	p := newTestPermission(t, src)
	p.logger = zap.New(core)
	p.loadFromSourceForTest(t)

	writeFile(t, dir, "list.txt", "\n") // parses to zero names, so adopt refuses it
	for range 20 {
		p.checkOnce(context.Background())
	}

	// At the default 2s interval, one line per tick is ~43k ERROR lines a day
	// for a condition that does not change -- burying the deliberately
	// throttled DEGRADED line that reports the same thing.
	if n := logs.Len(); n > 2 {
		t.Errorf("%d ERROR lines for 20 identical failed reloads, want at most 2", n)
		for _, e := range logs.All() {
			t.Logf("  %s", e.Message)
		}
	}
	if logs.Len() == 0 {
		t.Error("a persistently failing reload logged nothing at all")
	}
}

func TestReloadFailureLogsAgainAfterRecovery(t *testing.T) {
	core, logs := observer.New(zapcore.ErrorLevel)
	dir := t.TempDir()
	src := writeFile(t, dir, "list.txt", "good.example.com\n")

	p := newTestPermission(t, src)
	p.logger = zap.New(core)
	p.loadFromSourceForTest(t)

	writeFile(t, dir, "list.txt", "\n")
	p.checkOnce(context.Background())
	writeFile(t, dir, "list.txt", "recovered.example.com\n")
	p.checkOnce(context.Background())
	before := logs.Len()

	// Throttling must not swallow a NEW occurrence: the condition returning
	// after it cleared is information, not a repeat.
	writeFile(t, dir, "list.txt", "\n")
	p.checkOnce(context.Background())

	if logs.Len() == before {
		t.Error("a failure that recurred after a recovery was suppressed as a repeat")
	}
}

func TestSnapshotRequiresStorage(t *testing.T) {
	// "Enabled" must mean usable. Caddy always provides storage, so this only
	// ever bites a bare test instance -- but the rule belongs in one place
	// rather than as a nil check at every call site that touches the snapshot.
	var p Permission
	if p.snapshotEnabled() {
		t.Error("snapshot reported enabled with no storage to hold it")
	}
}

// countingStorage wraps certmagic.FileStorage -- the backend Caddy runs on by
// default -- counting the calls the handshake path makes and letting a test make
// listing fail. A hand-written fake would encode its own idea of the Storage
// contract; the real one is what the module has to agree with.
type countingStorage struct {
	certmagic.Storage
	mu      sync.Mutex
	listErr error
	ops     int
}

func newStorage(t *testing.T) *countingStorage {
	t.Helper()
	return &countingStorage{Storage: &certmagic.FileStorage{Path: t.TempDir()}}
}

func (s *countingStorage) opCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ops
}

func (s *countingStorage) failList(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listErr = err
}

func (s *countingStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	s.mu.Lock()
	s.ops++
	err := s.listErr
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s.Storage.List(ctx, prefix, recursive)
}

func (s *countingStorage) Exists(ctx context.Context, key string) bool {
	s.mu.Lock()
	s.ops++
	s.mu.Unlock()
	return s.Storage.Exists(ctx, key)
}

// storeCert writes a certificate file exactly where certmagic would.
func (s *countingStorage) storeCert(t *testing.T, issuer, domain string) {
	t.Helper()
	key := certmagic.StorageKeys.SiteCert(issuer, domain)
	if err := s.Store(context.Background(), key, []byte("cert")); err != nil {
		t.Fatal(err)
	}
}

// degradedWithStorage returns a module in the state on_empty=storage exists for:
// no list at all, so every decision consults what is in storage.
func degradedWithStorage(t *testing.T, st certmagic.Storage, logger *zap.Logger) *Permission {
	t.Helper()
	p := newTestPermission(t, filepath.Join(t.TempDir(), "missing.txt"))
	p.OnEmpty = onEmptyStorage
	p.storage = st
	p.logger = logger
	p.state = State{}
	p.loadInitial(context.Background())
	if p.state.From != sourceNone {
		t.Fatalf("from = %q, want %q", p.state.From, sourceNone)
	}
	return p
}

func errorLines(logs *observer.ObservedLogs, containing string) int {
	n := 0
	for _, e := range logs.All() {
		if strings.Contains(e.Message, containing) {
			n++
		}
	}
	return n
}

func TestSnapshotFallbackKeepsTheSourceError(t *testing.T) {
	st := newStorage(t)
	if err := st.Store(context.Background(), snapshotKey, []byte("snap.example.com\n")); err != nil {
		t.Fatal(err)
	}
	p := newTestPermission(t, filepath.Join(t.TempDir(), "missing.txt"))
	p.storage = st
	p.state = State{}

	p.loadInitial(context.Background())

	if p.state.From != sourceSnapshot {
		t.Fatalf("from = %q, want %q", p.state.From, sourceSnapshot)
	}
	// Without the reason, /status reports a bare {"from":"snapshot"} and an
	// operator has to go digging in the logs for why it is on the snapshot.
	if p.state.Error == "" {
		t.Error("state.Error was wiped by the snapshot load; the reason for the fallback is lost")
	}
}

func TestOnEmptyStorageOnFreshInstallIsQuietAndCheap(t *testing.T) {
	core, logs := observer.New(zapcore.ErrorLevel)
	// A fresh node: FileStorage only creates "certificates/" on the first
	// Store, and while the module refuses everything nothing is ever stored, so
	// the directory never appears. Listing it returns ENOENT. That is an
	// ordinary empty store -- certmagic's own storage walker treats it as
	// "hasn't been created yet; no big deal" -- not a failure to retry and log
	// on every handshake for the life of the process.
	st := newStorage(t)
	p := degradedWithStorage(t, st, zap.New(core))
	for range 5 {
		p.checkOnce(context.Background())
	}
	primed := st.opCount()

	for i := range 50 {
		name := fmt.Sprintf("bogus%d.example.com", i)
		if err := p.CertificateAllowed(context.Background(), name); err == nil {
			t.Fatalf("allowed %s on an empty store", name)
		}
	}

	if got := st.opCount() - primed; got != 0 {
		t.Errorf("%d storage calls in the handshake path for 50 denials, want 0", got)
	}
	if n := errorLines(logs, "cannot list certificate storage"); n != 0 {
		t.Errorf("%d 'cannot list certificate storage' lines on an empty store, want 0", n)
	}
}

func TestOnEmptyStorageServesHeldCertificate(t *testing.T) {
	st := newStorage(t)
	st.storeCert(t, "issuer", "held.example.com")
	p := degradedWithStorage(t, st, zap.NewNop())
	primed := st.opCount()

	// The set is built before the first handshake, off the handshake path: a
	// denied name never touches storage. Caddy re-asks about a denied name on
	// every handshake, so this is the cost of every bogus SNI a public host
	// sees while degraded.
	if err := p.CertificateAllowed(context.Background(), "bogus.example.com"); err == nil {
		t.Fatal("allowed a name with no certificate in storage")
	}
	if got := st.opCount() - primed; got != 0 {
		t.Errorf("%d storage calls for a denied handshake, want 0", got)
	}

	// A grant may confirm against storage, but at most once: a granted name is
	// loaded into Caddy's cache and not asked about again.
	if err := p.CertificateAllowed(context.Background(), "held.example.com"); err != nil {
		t.Fatalf("refused a name whose certificate is in storage: %v", err)
	}
	if got := st.opCount() - primed; got > 1 {
		t.Errorf("%d storage calls for a granted handshake, want at most 1", got)
	}
}

func TestCertificateObtainedLaterIsPickedUpByTheWatch(t *testing.T) {
	st := newStorage(t)
	p := degradedWithStorage(t, st, zap.NewNop())
	if err := p.CertificateAllowed(context.Background(), "later.example.com"); err == nil {
		t.Fatal("allowed a name before its certificate existed")
	}

	// Another node in the cluster obtains a certificate. The watch goroutine
	// notices on its next listing; the handshake itself does not go looking.
	st.storeCert(t, "issuer", "later.example.com")
	p.certsListedAt = time.Time{} // the relisting interval has elapsed
	p.checkOnce(context.Background())
	primed := st.opCount()

	if err := p.CertificateAllowed(context.Background(), "later.example.com"); err != nil {
		t.Errorf("certificate obtained after startup not picked up: %v", err)
	}
	if got := st.opCount() - primed; got > 1 {
		t.Errorf("%d storage calls in the handshake, want at most the one confirmation", got)
	}
}

func TestListingFailureKeepsThePreviousSet(t *testing.T) {
	core, logs := observer.New(zapcore.ErrorLevel)
	st := newStorage(t)
	st.storeCert(t, "issuer", "held.example.com")
	p := degradedWithStorage(t, st, zap.New(core))

	// Storage goes away. The last good set is still served, the retry happens
	// in the watch goroutine and the ERROR line is throttled like every other
	// standing condition -- not once per tick, and never once per handshake.
	st.failList(errors.New("storage unavailable"))
	p.certsListedAt = time.Time{}
	for range 20 {
		p.checkOnce(context.Background())
	}
	primed := st.opCount()

	for i := range 20 {
		name := fmt.Sprintf("bogus%d.example.com", i)
		if err := p.CertificateAllowed(context.Background(), name); err == nil {
			t.Fatalf("allowed %s", name)
		}
	}
	if got := st.opCount() - primed; got != 0 {
		t.Errorf("%d storage calls in the handshake path while listing fails, want 0", got)
	}
	if err := p.CertificateAllowed(context.Background(), "held.example.com"); err != nil {
		t.Errorf("a listing failure cost the previously good set: %v", err)
	}
	if n := errorLines(logs, "cannot list certificate storage"); n > 1 {
		t.Errorf("%d 'cannot list certificate storage' lines for 20 failed ticks, want at most 1", n)
	}
}

func TestOnEmptyStorageRecoversAfterAFailedList(t *testing.T) {
	st := newStorage(t)
	st.failList(errors.New("storage unavailable"))
	p := degradedWithStorage(t, st, zap.NewNop())
	if err := p.CertificateAllowed(context.Background(), "held.example.com"); err == nil {
		t.Fatal("allowed a name while storage was unavailable")
	}

	// A failure at startup must not be remembered for the life of the process.
	st.failList(nil)
	st.storeCert(t, "issuer", "held.example.com")
	p.checkOnce(context.Background())

	if err := p.CertificateAllowed(context.Background(), "held.example.com"); err != nil {
		t.Errorf("refused a name whose certificate is in storage after storage recovered: %v", err)
	}
}

func TestStoredWildcardCoversItsSubdomains(t *testing.T) {
	st := newStorage(t)
	st.storeCert(t, "issuer", "*.example.com")
	p := degradedWithStorage(t, st, zap.NewNop())

	// An SNI never contains "*" -- certmagic's name normalisation rejects it
	// before any permission check. What a handshake asks for is a subdomain,
	// and certmagic serves it from the stored wildcard on load. The module has
	// to agree, or "everything currently being served keeps working" is false
	// for every name behind a wildcard.
	if err := p.CertificateAllowed(context.Background(), "www.example.com"); err != nil {
		t.Errorf("refused a subdomain covered by a stored wildcard: %v", err)
	}
	if err := p.CertificateAllowed(context.Background(), "www.other.example"); err == nil {
		t.Error("allowed a name no stored certificate covers")
	}
}

func TestGrantIsConfirmedAgainstStorage(t *testing.T) {
	st := newStorage(t)
	st.storeCert(t, "issuer", "held.example.com")
	p := degradedWithStorage(t, st, zap.NewNop())
	if err := p.CertificateAllowed(context.Background(), "held.example.com"); err != nil {
		t.Fatal(err)
	}

	// certmagic's storage cleaner removes the certificate. The set is not a
	// minute old yet, but granting from it would make Caddy fail the load and
	// fall through to ISSUANCE -- the one thing on_empty=storage promises never
	// happens.
	key := certmagic.StorageKeys.SiteCert("issuer", "held.example.com")
	if err := st.Delete(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if err := p.CertificateAllowed(context.Background(), "held.example.com"); err == nil {
		t.Error("granted a name whose certificate is no longer in storage")
	}
}

func TestOneFailedPollDoesNotDemoteToStale(t *testing.T) {
	dir := t.TempDir()
	src := writeFile(t, dir, "list.txt", "good.example.com\n")
	p := newTestPermission(t, src)
	p.loadFromSourceForTest(t)

	// A publisher that truncates and rewrites in place produces exactly one
	// bad poll. Reporting that as "stale" flips /status and fires the alert
	// for a 2s blip. The error is recorded immediately; the demotion waits for
	// the condition to persist.
	if err := os.Remove(src); err != nil {
		t.Fatal(err)
	}
	p.checkOnce(context.Background())

	if p.state.From != sourcePrimary {
		t.Errorf("from = %q after a single failed poll, want %q", p.state.From, sourcePrimary)
	}
	if p.state.Error == "" {
		t.Error("state.Error is empty after a failed poll")
	}
}

func TestRecoveryResetsTheDegradedAlert(t *testing.T) {
	core, logs := observer.New(zapcore.ErrorLevel)
	dir := t.TempDir()
	src := writeFile(t, dir, "list.txt", "good.example.com\n")
	p := newTestPermission(t, src)
	p.logger = zap.New(core)
	p.loadFromSourceForTest(t)

	degrade := func() {
		t.Helper()
		if err := os.Remove(src); err != nil {
			t.Fatal(err)
		}
		p.checkOnce(context.Background())
		p.checkOnce(context.Background())
		if p.state.From != sourceStale {
			t.Fatalf("from = %q, want %q", p.state.From, sourceStale)
		}
	}

	degrade()
	if n := errorLines(logs, "DEGRADED"); n != 1 {
		t.Fatalf("%d DEGRADED lines after degrading, want 1", n)
	}

	writeFile(t, dir, "list.txt", "good.example.com\n")
	p.checkOnce(context.Background())
	if p.state.From != sourcePrimary {
		t.Fatalf("from = %q after restore, want %q", p.state.From, sourcePrimary)
	}

	// A degradation that starts again within the 5-minute window is a NEW
	// condition: the alert must fire immediately, not wait out a throttle
	// budget the previous one consumed.
	degrade()
	if n := errorLines(logs, "DEGRADED"); n != 2 {
		t.Errorf("%d DEGRADED lines after a second degradation, want 2", n)
	}
}

func TestReadFailureMessageMatchesState(t *testing.T) {
	core, logs := observer.New(zapcore.ErrorLevel)
	p := newTestPermission(t, filepath.Join(t.TempDir(), "missing.txt"))
	p.logger = zap.New(core)
	p.state = State{}
	p.loadInitial(context.Background())
	logs.TakeAll()

	// No list was ever loaded and every handshake is being refused. Telling
	// the operator we are "keeping the previously loaded list" describes a
	// benign condition that does not exist.
	p.checkOnce(context.Background())
	for _, e := range logs.All() {
		if strings.Contains(e.Message, "keeping the previously loaded list") {
			t.Errorf("logged %q with no list loaded", e.Message)
		}
	}
}

func statusFor(t *testing.T) State {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/permission-allowlist/status", nil)
	if err := (adminAPI{}).status(rec, req); err != nil {
		t.Fatal(err)
	}
	var st State
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestStatusSurvivesAFailedReload(t *testing.T) {
	old := newTestPermission(t, "old.txt")
	old.state = State{From: sourcePrimary, Path: "old.txt", Entries: 1}
	registerState(old)
	t.Cleanup(func() { unregisterState(old) })

	// A reload provisions the new config's modules -- the new instance
	// registers itself -- and then something else in the config fails to
	// start. Caddy cleans up only the new instance; the old one keeps serving
	// every handshake. /status must keep describing it.
	fresh := newTestPermission(t, "new.txt")
	registerState(fresh)
	unregisterState(fresh)

	if st := statusFor(t); st.Path != "old.txt" {
		t.Errorf("status after a failed reload = %+v, want the old instance, which is still serving", st)
	}
}

func TestStatusFollowsASuccessfulReload(t *testing.T) {
	// The successful order: the new instance registers, THEN the old one is
	// cleaned up. Characterises existing behaviour so the fix above cannot
	// regress it.
	old := newTestPermission(t, "old.txt")
	old.state = State{From: sourcePrimary, Path: "old.txt", Entries: 1}
	registerState(old)
	fresh := newTestPermission(t, "new.txt")
	fresh.state = State{From: sourcePrimary, Path: "new.txt", Entries: 2}
	registerState(fresh)
	t.Cleanup(func() { unregisterState(fresh) })
	unregisterState(old)

	if st := statusFor(t); st.Path != "new.txt" {
		t.Errorf("status after a successful reload = %+v, want the new instance", st)
	}
	unregisterState(fresh)
	if st := statusFor(t); st.From != "not_configured" {
		t.Errorf("status with no live instance = %+v, want not_configured", st)
	}
}

// adoptFor runs adopt on raw for a module already serving one good name, and
// returns the error, so tests can check both the verdict and what survived.
func adoptFor(t *testing.T, p *Permission, raw string) error {
	t.Helper()
	return p.adopt(context.Background(), []byte(raw), "src", sourcePrimary)
}

func servingGood(t *testing.T, logger *zap.Logger) *Permission {
	t.Helper()
	p := newTestPermission(t, "src")
	p.logger = logger
	if err := adoptFor(t, p, "good.example.com\n"); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAdoptRefusesACorruptFile(t *testing.T) {
	// Measured on a live host: 2000 bytes of /dev/urandom were adopted as a
	// healthy 13-entry primary list, every real site was refused after the
	// next restart, and the snapshot was overwritten with the noise. Bytes
	// that are not text are never legitimate in this file: the whole file is
	// refused, the last good list stays, and so does the snapshot.
	for name, raw := range map[string]string{
		"binary noise":            "\x00\x8f\x13garbage\x01\n\xfe\xff\n",
		"control character":       "good.example.com\nbad\x07.example.com\n",
		"invalid UTF-8":           "good.example.com\n\xff\xfe.example.com\n",
		"junk spliced into names": "a.example.com\n\x00\x00\x00\x1b[0m\nb.example.com\n",
	} {
		p := servingGood(t, zap.NewNop())
		if err := adoptFor(t, p, raw); err == nil {
			t.Errorf("%s: adopted, want refused", name)
		}
		if _, ok := p.names["good.example.com"]; !ok || p.state.Entries != 1 {
			t.Errorf("%s: a refused file cost the last good list: %+v", name, p.state)
		}
	}
}

func TestAdoptSkipsAnInvalidHostname(t *testing.T) {
	core, logs := observer.New(zapcore.ErrorLevel)
	p := servingGood(t, zap.New(core))

	// Apache accepts an underscore ServerAlias, so a customer can create one
	// through the panel at any time. Such a name can never get a certificate
	// anyway -- SNI normalisation rejects it before the module is asked -- so
	// refusing the whole file for it would freeze every other update on the
	// host for nothing. Skip it, say so, adopt the rest.
	err := adoptFor(t, p, "one.example.com\nunder_score.example.com\n-hyphen.example.com\ntwo.example.com\n")
	if err != nil {
		t.Fatalf("a file with an individually invalid hostname was refused: %v", err)
	}
	if p.state.Entries != 2 {
		t.Errorf("entries = %d, want 2 (the valid ones)", p.state.Entries)
	}
	for _, want := range []string{"one.example.com", "two.example.com"} {
		if _, ok := p.names[want]; !ok {
			t.Errorf("missing %q", want)
		}
	}
	if _, ok := p.names["under_score.example.com"]; ok {
		t.Error("an invalid hostname was adopted")
	}
	if n := errorLines(logs, "skipp"); n != 1 {
		t.Errorf("%d lines about skipped entries, want exactly 1 (with the count)", n)
	}
}

func TestAdoptRefusesWhenNothingValidRemains(t *testing.T) {
	// Text junk without control characters is skipped line by line -- and
	// with nothing left the existing empty-list rule refuses the file, by a
	// different route to the same safe outcome.
	p := servingGood(t, zap.NewNop())
	if err := adoptFor(t, p, "hello world\n<?php echo 1; ?>\n!!!! broken !!!!\n"); err == nil {
		t.Fatal("adopted a file with no valid hostname")
	}
	if p.state.Entries != 1 {
		t.Errorf("a refused file changed state: %+v", p.state)
	}
}

func TestHostnameValidation(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	label64 := strings.Repeat("a", 64)
	// 4 x 63 + 3 dots = 255 > 253.
	tooLong := strings.Join([]string{label63, label63, label63, label63}, ".")

	valid := []string{
		"example.com",
		"localhost", // single label: Caddy's internal issuer can serve it
		"a-b.c",
		"xn--bcher-kva.example", // punycode must pass untouched
		"2023.DEV.SwissCenter.COM.",
		label63 + ".example.com",
		"1.2.3.4", // digits-only labels are valid; SNI never carries an IP, harmless
	}
	invalid := []string{
		"under_score.example.com",
		"-hyphen.example.com",
		"hyphen-.example.com",
		"a..b",
		label64 + ".example.com",
		tooLong,
		"*.example.com", // SNI never contains "*", so the entry could never match
		"hello world",
		"<?php echo 1; ?>",
		"!!!! broken !!!!",
		"example.com:443",
	}
	for _, name := range valid {
		p := newTestPermission(t, "src")
		if err := adoptFor(t, p, name+"\n"); err != nil {
			t.Errorf("valid %q refused: %v", name, err)
		}
	}
	for _, name := range invalid {
		p := newTestPermission(t, "src")
		if err := adoptFor(t, p, name+"\n"); err == nil {
			t.Errorf("invalid %q accepted (adopted %d names)", name, p.state.Entries)
		}
	}
}

func TestUnicodeEntryMatchesPunycodeSNI(t *testing.T) {
	// The SNI arrives in punycode; certmagic runs it through idna before
	// asking. An entry written in unicode must be mapped the same way, or it
	// silently never matches.
	p := newTestPermission(t, "src")
	if err := adoptFor(t, p, "bücher.example\n"); err != nil {
		t.Fatal(err)
	}
	if err := p.CertificateAllowed(context.Background(), "xn--bcher-kva.example"); err != nil {
		t.Errorf("unicode entry did not match its punycode SNI: %v", err)
	}
}
