# @junction41/secure-setup

Security auto-setup for J41 Dispatcher and Jailbox. On first run it detects the host platform, installs the best available isolation layer (gVisor or bubblewrap), deploys seccomp and AppArmor profiles, creates financial and network allowlists, and runs a full self-test. Operators and buyers do not need to do anything — security is wired directly into the first-run flow of both products.

## Security update — 2026-06-05 install-flow fixes (v0.3.4)

Found by end-to-end testing the sudo-install on a KVM-less host (the fail-closed `/etc/j41` contract from 0.3.3 surfaced these). All make the privileged install actually work for a non-root product:

- **`/etc/j41` is `0711`, profile files `0644`** (were `0700`/`0600`). The profiles are public (they ship in this tarball), so there's no content to hide; the non-root jailbox/dispatcher CLI must `existsSync` + read them to detect and integrity-verify. Under `0700`/`0600` the CLI fail-closed on a profile that was in fact deployed. Tamper-resistance is `chattr +i` + hash pinning, not read perms.
- **Runtime detection uses `docker info`**, not reading root-only `/etc/docker/daemon.json` — so `quickCheck` no longer reports bwrap mode while gVisor is actually the default runtime. Matches jailbox `docker.ts`.
- **First-run marker honors `SUDO_USER`** — written to (and chowned to) the invoking user's `~/.j41`, not `/root/.j41`, so the user-run product sees it instead of re-triggering the first-run gate.
- **Re-deploys clear the `chattr +i` immutable bit** before re-copying, so `setup`/`--fix` is idempotent instead of `EPERM`-ing on a locked profile.

Validated live: `quickCheck` 10/10 mode gvisor as a non-root user, and a container booted with jailbox's exact HostConfig runs under gVisor (`4.19.0-gvisor`), network blocked, rootfs read-only, all caps dropped, with the MCP server blocking every repo-escape payload.

## Security update — 2026-06-05 jailbox confinement review (v0.3.3)

Companion changes to jailbox 2.1.3, closing two false-confidence gaps and one coverage gap:

**Self-check is fail-closed on `/etc/j41` (Linux).** `quickCheck` previously fell back to `~/.j41` when `/etc/j41` was absent and reported the seccomp profile "active" — but the runtime launchers (jailbox `docker.ts`, dispatcher `cli.js`) load seccomp **only** from `/etc/j41`. So the self-check could report 8/10 while the container ran Docker-default seccomp. `quickCheck` now checks `/etc/j41` only on Linux (no `~/.j41` fallback), and `setup()` refuses to silently deploy profiles to `~/.j41` (re-run with `sudo` to write `/etc/j41`).

**`gvisor-or-bwrap` is product-aware.** bwrap counts as kernel isolation only for the **dispatcher** (whose agent container actually execs under bwrap). For **jailbox** — whose container runs `node` directly with no bwrap — bwrap no longer satisfies the kernel-isolation check; gVisor (or the macOS Docker Desktop VM) is required.

**gVisor installs without KVM (systrap platform).** Setup previously skipped gVisor entirely when `/dev/kvm` was absent and fell back to bubblewrap. gVisor's modern **systrap** platform needs no KVM, so setup now always attempts gVisor — selecting `--platform=kvm` when `/dev/kvm` exists (fastest) and `--platform=systrap` otherwise. KVM-less cloud VMs now get real Wall-1 kernel isolation.

## Security update — 2026-06-02 audit (v0.3.0)

This release closes 1 critical + 8 highs + 6 mediums from the 2026-06-02 cross-repo security audit. The behavioral changes operators should know about:

**The gVisor binary install path is hash-pinned (breaking).** Previously fetched runsc + runsc.sha512 from the SAME Google Cloud Storage URL — a same-origin checksum is a transport check, not authenticity. Now: `assets/pinned-gvisor.json` ships inside the npm tarball with J41-qualified release entries (sha512 per architecture + gVisor signing-key fingerprint). The binary path **refuses to install** unless the requested release (env `GVISOR_RELEASE`, default first pin entry) is in the file with a real sha512. The default placeholder is `"TBD"` — operators who hit this must follow the qualification checklist in the file header (verify upstream GPG sig offline, sha512, append entry, republish).

**The apt path requires a bundled GPG key (breaking).** Previously did `curl https://gvisor.dev/archive.key | sudo gpg --dearmor` with no fingerprint pin. Now: refuses to install unless `assets/gvisor-archive-keyring.gpg` is bundled in the tarball. When present, the keyring is `sudo cp`'d (not curl-piped) into `/usr/share/keyrings`.

**`deployProfiles` checks `known-good-hashes.json` BEFORE copying** (H7). Source files in `profiles/` are hashed and compared against the in-package known-good before deploy. A supply-chain compromise that ships tampered profiles + an updated known-good is no longer self-consistent. Missing or unparseable `known-good-hashes.json` is fatal.

**Deployed profiles are immutable + 0600** (H3). `chattr +i` after deploy (best-effort, ext4/xfs only); mode tightened from 0644 → 0600. Target directory created `mode: 0700` with explicit chmod.

**Network allowlist filtered to signed baseline** (H1). `resolveAndPinDNS` refuses entries in `~/.j41/network-allowlist.json` that aren't in the in-package `DEFAULT_ENDPOINTS` baseline. Operators who need extras opt in via `J41_ALLOWLIST_EXTRA=host:port,host:port`. A brief operator-context tamper can no longer pin an attacker IP into iptables ACCEPT.

**`/etc/j41` now created mode 0o700** + explicit chmod (M-funds-1).

**`isInitialized()` validates the marker file** (L-funds-2). Reads + parses the JSON, checks the timestamp is well-formed and less than 90 days old. Bare file existence is no longer trusted.

**New env vars**: `GVISOR_RELEASE` (selects qualified release), `J41_ALLOWLIST_EXTRA` (additional iptables hosts).

---

## How it works

Every agent container is wrapped in three concentric walls. Any single wall being breached does not expose the host.

```
Host (keys, WIF, money)
 +-- Wall 1: gVisor  (fake kernel — syscalls never reach the host)
      +-- Wall 2: Docker  (namespaces, seccomp, caps dropped, dedicated bridge)
           +-- Wall 3: Bubblewrap  (minimal fs view, no network namespace)
                +-- Agent  (LLM worker — holds only a session token)
```

**Auto-detection order (Linux):**

1. KVM available → install gVisor as the default Docker runtime (Wall 1 active, Wall 3 skipped)
2. gVisor fails → install bubblewrap as the inner sandbox (Wall 3 active, Wall 1 skipped)
3. Neither works → refuse to start without `--dev-unsafe`

**macOS:** Docker Desktop runs inside a Hypervisor.framework VM, which replaces both Wall 1 and Wall 3. Setup verifies the VM is active, then deploys seccomp profiles.

The installer is idempotent. Re-running updates profiles, re-pins DNS, and re-runs the self-test.

---

## Security scores

| Environment | Walls active | Score |
|---|---|---|
| Linux + KVM (gVisor installs) | gVisor + Docker + seccomp + AppArmor | **10/10** |
| Linux VPS / AWS (no KVM, bubblewrap) | Bubblewrap + Docker + seccomp + AppArmor | **8/10** |
| macOS Docker Desktop | VM + Docker + seccomp | **8/10** |
| Docker only (gVisor and bwrap both failed) | Docker + seccomp | **4/10** — dev mode only |
| Local mode (no container) | None | **0/10** — dev mode only |

The minimum production bar is **8/10**. The auto-setup guarantees this on any normal Linux box or macOS machine.

---

## CLI usage

```
j41-secure-setup --dispatcher          # first-run setup for the dispatcher
j41-secure-setup --jailbox             # first-run setup for the jailbox
j41-secure-setup --check               # quick-check all initialized products
j41-secure-setup --check --dispatcher  # quick-check dispatcher only
j41-secure-setup --test --dispatcher   # full self-test (spawns containers)
j41-secure-setup --fix                 # re-run setup for all products
```

`--check` is fast (no container spawned). `--test` spawns containers and attempts escapes.

If iptables rules require elevated permissions, setup will warn and instruct you to run `sudo j41-secure-setup --fix`.

---

## Programmatic API

Both products call this on startup before accepting work:

```javascript
import { setup, isInitialized, quickCheck } from '@junction41/secure-setup';

// On first run
if (!isInitialized('dispatcher')) {
  const result = await setup('dispatcher');
  // result: { success, log, score, mode }
}

// On every startup
const check = quickCheck('dispatcher');
if (!check.passed) process.exit(1);
```

Additional exports: `detectPlatform`, `detectIsolation`, `selfTest`

---

## What gets installed

| File | Location | Product |
|---|---|---|
| `seccomp-agent.json` | `/etc/j41/` or `~/.j41/` | dispatcher |
| `seccomp-jailbox.json` | `/etc/j41/` or `~/.j41/` | jailbox |
| `seccomp-bwrap.json` | `/etc/j41/` or `~/.j41/` | both (bubblewrap mode) |
| `apparmor-agent` | `/etc/j41/` or `~/.j41/` | dispatcher (Linux) |
| `apparmor-jailbox` | `/etc/j41/` or `~/.j41/` | jailbox (Linux) |
| `financial-allowlist.json` | `~/.j41/` | dispatcher only |
| `network-allowlist.json` | `~/.j41/` | dispatcher only |
| `profile-hashes.json` | `~/.j41/` | both |
| `{product}-security-initialized` | `~/.j41/` | marker file |

Profile directory: Linux with write access to `/etc/j41` uses that path. All others fall back to `~/.j41/`.

---

## Profiles

| Profile | Applies to | Purpose |
|---|---|---|
| `seccomp-agent.json` | Dispatcher containers | Whitelists ~80 syscalls needed by Node.js + networking. Blocks `ptrace`, `mount`, `reboot`, `keyctl`, `bpf`, and other escape-relevant calls. |
| `seccomp-jailbox.json` | Jailbox MCP containers | Same whitelist minus all network syscalls (container has `NetworkMode: none`). |
| `seccomp-bwrap.json` | Both (bubblewrap mode) | Extends the agent profile with `unshare`, `mount`, `pivot_root` for bubblewrap setup. Dropped after namespace creation. |
| `apparmor-agent` | Dispatcher containers (Linux) | Restricts file access to explicit paths, blocks raw sockets, mounting, cross-namespace signals. |
| `apparmor-jailbox` | Jailbox containers (Linux) | Same restrictions plus network deny rules. Allows `/jailbox/**` read access. |

Profile integrity is verified on every startup against SHA256 hashes in `profile-hashes.json`.

---

## Requirements

- Node.js >= 18
- Docker (daemon running)
- Linux or macOS
- sudo access is **optional** — profiles fall back to `~/.j41/` when `/etc/j41` is not writable, iptables failure is non-fatal

## Recent Changes

- **No sudo required** — all 3 modules (`detect-isolation.js`, `self-test.js`, `index.js`) fall back to `~/.j41/` from `/etc/j41`
- **iptables is warn, not fail** — dev machines without sudo still get full security except firewall rules
- **Network setup non-fatal** — `setup()` continues if iptables fails, logs a warning with fix instructions
