# @j41/secure-setup

Security auto-setup for J41 Dispatcher and Jailbox. On first run it detects the host platform, installs the best available isolation layer (gVisor or bubblewrap), deploys seccomp and AppArmor profiles, creates financial and network allowlists, and runs a full self-test. Operators and buyers do not need to do anything — security is wired directly into the first-run flow of both products.

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
import { setup, isInitialized, quickCheck } from '@j41/secure-setup';

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
- sudo access (for gVisor install, iptables, AppArmor — requested during first-run)
