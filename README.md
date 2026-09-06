# caddy-tls-permission-allowlist

A [Caddy](https://caddyserver.com) on-demand TLS permission module that answers
from an allow-list file held in memory, instead of asking an HTTP endpoint.

## Why

Caddy consults the on-demand permission module on **every handshake for a name it
does not already hold in memory**, including names whose certificate is already
in storage, because the module gates *loading from storage* as well as issuance.
This is intended behaviour, [confirmed by the
maintainer](https://caddy.community/t/33898).

With the stock `ask` module that makes an HTTP endpoint a hard, per-handshake
dependency for TLS on every site you serve. While it is unreachable or returning
errors, even certificates you already hold cannot be served, so a brief blip in a
helper service becomes a total TLS outage, and a restart at the wrong moment turns
it into a long one.

This module removes the endpoint. The list is read into memory, every decision is
a map lookup, and there is no listener that can be down.

It is intended for hosts serving many hostnames that change at runtime (a control
panel, a multi-tenant platform), where the set of permitted names lives in a file
some other process keeps up to date.

## Install

```
xcaddy build --with github.com/team-swisscenter/caddy-tls-permission-allowlist
```

## Usage

```caddyfile
{
	on_demand_tls {
		permission allowlist {
			source /etc/caddy/allowlist.txt
		}
	}
}

# Serve any hostname; the allow-list decides which ones may get a certificate.
https:// {
	tls {
		on_demand
	}
	respond "hello"
}
```

The allow-list is one hostname per line. Blank lines and lines starting with `#`
are ignored, names are matched case-insensitively, a trailing dot is tolerated,
and duplicates collapse.

```
example.com
www.example.com
# a comment
customer-domain.net
```

Every entry is validated as a hostname with the same rules certmagic applies to
an SNI before asking for permission (RFC 1123 labels, punycode allowed, a
unicode entry is mapped to its punycode form so it matches the name a handshake
actually carries). Two kinds of bad line are treated differently:

- **Corruption** — invalid UTF-8 or a control character anywhere in the file —
  is never legitimate, so the **whole file is refused**: the last good list keeps
  serving and the snapshot is left alone. Without this, 2000 bytes of
  `/dev/urandom` were once adopted as a healthy 13-entry list, every real site
  was refused after the next restart, and the snapshot was overwritten with the
  noise.
- **An individually invalid hostname** — an underscore, a misplaced hyphen, an
  over-long label, a wildcard — can legitimately arrive from a customer's
  `ServerAlias`. Such a name could never be issued a certificate anyway, so it
  is **skipped** and reported at ERROR with a count and examples, and the rest
  of the file is adopted rather than freezing every other update on the host.
  A file with nothing valid left is refused like an empty one.

**Entries are literal hostnames, not patterns.** A line like `*.example.com` is
matched literally and will therefore never match anything. This is deliberate:
on-demand issues one certificate *per name*, so a wildcard entry would not mean
"one certificate for the zone" but "unbounded issuance for every name under it",
which is a fast route into your CA's rate limits. List the names you serve.

### Options

| option | default | meaning |
|---|---|---|
| `source` | *(required)* | path to the allow-list file |
| `reload_interval` | `2s` | how often the file is re-read and hashed |
| `snapshot` | `true` | keep a copy of the last good list in Caddy's storage, and load it at startup if the source is unreadable |
| `on_empty` | `deny` | what to do with no list at all: `deny`, `storage` or `allow` |

Equivalent JSON:

```json
{
  "permission": {
    "module": "allowlist",
    "source": "/etc/caddy/allowlist.txt",
    "reload_interval": 2000000000,
    "snapshot": true,
    "on_empty": "deny"
  }
}
```

## Behaviour

**An empty list is a failure, never a result.** A truncated write, a broken
generator or an empty input directory all produce an empty file, and adopting one
would refuse every name, taking every site offline until the next good write. An
empty parse is rejected and the previous list is kept.

**A failed reload keeps the previous list.** Loading and deciding are separate,
which is the point of holding the list in memory: a bad read cannot cost you a
good list. A file that stays bad is retried every interval rather than written off
once.

**Failing closed stays loud.** There are two kinds of refusal. A name that is
simply not on the list is wrapped in `ErrPermissionDenied`, which Caddy logs at
*debug*, so the constant background of requests for names you do not serve
produces no noise. Having *no list at all* is returned as a plain error, which
Caddy logs at *ERROR*. An HTTP endpoint cannot make this distinction: there, every
response including `500` and `503` is treated as a denial and logged at debug, so
a failing endpoint is invisible in the error log.

**Changes are detected by hashing the content**, not by comparing size, mtime or
inode. Every metadata scheme leaves a residue: an in-place write with an
identical size and a restored mtime (`rsync --inplace -t`, or any tool that
preserves timestamps) changes none of the three and would be missed indefinitely.
Hashing also avoids rebuilding the list when a publisher rewrites the file
unconditionally with identical content.

**Polling, not inotify.** A publisher that writes atomically replaces the file by
rename, and an inotify watch follows the *inode*: a watch on the file keeps
watching the old, unlinked one and never fires again. Correct inotify means
watching the directory for `IN_MOVED_TO`, and it can still silently miss events on
queue overflow, so a poll backstop would be needed anyway. A poll cannot silently
stop working.

**The snapshot covers restarts.** The in-memory list survives a config reload but
not a restart, and a restart is exactly when the source is most likely to be
disturbed too: an unattended package upgrade restarts Caddy. The snapshot is
written to Caddy's storage (so it works with any storage backend) and only ever
from a validated load, so a bad state is never persisted as the thing you fall
back to.

### `on_empty`

Applies only when **neither** the source nor the snapshot could be loaded.

| mode | behaviour |
|---|---|
| `deny` *(default)* | refuse every name. Safe, but a total TLS outage. |
| `storage` | allow a name **only if a certificate for it is already in storage**. Everything currently being served keeps working; nothing new is issued. |
| `allow` | allow every name. **Dangerous. See below.** |

`storage` is usually what you want as a safety net. It keeps serving certificates
you already hold while issuing nothing new, so a problem with the allow-list does
not take down live sites.

While in this mode the module lists what is in storage once a minute, in the
background, and decides from that: a denial never touches storage, a stored
wildcard covers its subdomains, and a grant is confirmed against storage first so
a certificate the storage cleaner has since removed is not granted (which would
make Caddy try to issue one). A certificate another node obtains is honoured
within a minute.

> **Why `allow` is dangerous.** Granting permission makes Caddy attempt
> *issuance* for every name presented to it, and a host exposed to the internet
> sees a large volume of bogus SNI. Let's Encrypt permits 300 new orders per
> account per 3 hours, and **the limit is account-wide**. A few minutes of this
> can exhaust it and block renewals for your real domains for hours, long after
> the allow-list was repaired. It can turn a brief problem into a longer and wider
> outage. The module logs a standing warning at ERROR level when this mode is
> configured.

## Status endpoint

The module registers an admin API route, available without configuration:

```
$ curl -s http://localhost:2019/permission-allowlist/status
{"from":"primary","path":"/etc/caddy/allowlist.txt","entries":1234,"loaded_at":1788600000,"on_empty":"deny"}
```

`from` is `primary`, `stale`, `snapshot`, `none`, or `not_configured` (the module
is in the binary but the config does not use it, distinguishable from a missing
endpoint, which would otherwise look identical to a monitoring check).

`stale` means the last good list is still being served but the source itself has
been unreadable or unusable for more than one poll; `error` says why. A single
failed poll (what a publisher that truncates and rewrites in place looks like)
records `error` but does not change `from`. Alert on anything that is not
`primary`.

Running from a snapshot is a *state*, not an event: a log line at startup scrolls
away, and a monitoring check reading a time window would watch its own alert
resolve while the degradation continued. Query this endpoint instead. The module
also re-logs a `DEGRADED` line every 5 minutes while it is not serving from the
primary source.

The reason a reload failed is logged at ERROR when it first occurs and whenever
it changes, but a failure that simply persists is not repeated on every poll.
At the default 2s interval that would be tens of thousands of identical lines a
day, burying the `DEGRADED` line that reports the same condition. The same
failure is re-logged at most every 5 minutes, and immediately if it recurs after
a recovery.

## File permissions

The allow-list must be readable by the user Caddy runs as, which is often not the
user that writes it. Check the whole path, not just the file.

If the publisher replaces the file by rename, which it should so a reader never
sees a partial file, then **any ACL you set on the file is destroyed by the next
publish**, because the new inode carries only its own permissions. A grant applied
by hand survives exactly until the next regeneration, and the failure only appears
at Caddy's next restart. Apply ownership, mode and any ACL to the *temporary file,
before the rename*, on every publish.

Under systemd, check what the **service** can read, not what the user can.
`sudo -u caddy cat …` tests the user's permissions; the unit may add a mount
namespace on top. `ProtectSystem=full` or `strict` only remount paths read-only,
which is fine here, but `InaccessiblePaths`, `ProtectHome` or a `RootDirectory`
would hide the file from the process while the `sudo` test still passed. To test
what the running service actually sees:

```
pid=$(systemctl show -p MainPID --value caddy)
nsenter -m -t "$pid" -- setpriv --reuid=caddy --regid=caddy --clear-groups \
    head -c1 /etc/caddy/allowlist.txt
```

Or just start Caddy and read the status endpoint: `from` will be `none` with the
error if the file could not be read.

## Prior art

Other permission modules solve adjacent problems:
[`caddy-tls-permission-policy`](https://github.com/pberkel/caddy-tls-permission-policy)
(regex/subdomain/DNS policy rules),
[`caddyfile-tls-permission`](https://github.com/moddengine/caddyfile-tls-permission)
(names taken from the Caddyfile's own host matchers), and
[`caddy-tls-unixask`](https://github.com/moddengine/caddy-tls-unixask) (`ask` over
a unix socket). This one is for the case where the permitted names are numerous,
change at runtime, and are maintained in a file by another process.

## License

Apache-2.0. Copyright OpenBusiness S.A.
