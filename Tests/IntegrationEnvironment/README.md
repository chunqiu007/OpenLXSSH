# OpenLXSSH integration environment (ENV-FIXTURE-A)

**Only source/config preparation. No image was downloaded, built or run, no sshd started, and no SSH/SFTP/PAM authentication verified.** This is real Ubuntu OpenSSH plus a test-only policy loaded by the mature `libpam-python` PAM module, not a mock SSH server. It does not prove enterprise MFA compatibility.

## Authorization and resource/network proposal

Before **any** build/run, obtain explicit user approval for **one** local Apple Silicon Linux container runtime (e.g. official [Docker Desktop for Mac](https://docs.docker.com/desktop/setup/install/mac-install/)), its installation if absent, Ubuntu/package downloads, and this test environment. The user has now approved official Docker Desktop, necessary Ubuntu ARM64 image/dependency downloads/builds and these four services plus a separate necessary multi-prompt service, restricted to **127.0.0.1:22221–22225**. This root runner still starts **only the four existing OpenSSH services**; permission is not an implementation or runtime result for the separate service. `--authorized-run` only prevents accidents; it **is not authorization**. No LAN exposure, real credentials/data, host paths/sshd, production access or Apple upload is authorized here. Do not change Remote Login/global config or directly bypass the wrapper with `docker compose up`.

**Current runtime prerequisite:** the official Docker Desktop install has reached its first-run legal/subscription agreement page. The human must personally complete any required agreement and system permission; the agent must not accept them on the human's behalf. The main session stopped Desktop with zero containers and must verify **2 vCPU / 4 GiB RAM** and explicitly declare Engine-ready before any pull/build/run. A briefly responsive Engine API or the existing environment approval does not bypass this condition. Do not restart Desktop or create a privileged `/var/run/docker.sock` link as a workaround.

Single supported source: official `docker.io/library/ubuntu:24.04` (**Ubuntu 24.04 LTS Noble**, `linux/arm64`), with a **mandatory** `@sha256:<64-lowercase-hex>` input. No guessed digest is checked in. After approval, resolve the ARM64 manifest (or multiarch index with arm64) from [Docker Official Ubuntu](https://hub.docker.com/_/ubuntu), verify its official provenance/version, record it, then set `OPENLXSSH_UBUNTU_IMAGE`. Do not substitute `latest`, a mirror or an unreviewed digest. The base is locked; apt package versions are deliberately recorded at image build, not claimed reproducible across future rebuilds (`packages.txt` plus built image ID/base digest are exported on collect). Reuse the reviewed built image for a test campaign.

Suggested runtime VM allocation: **2 vCPU, 4 GiB RAM, 20 GiB disk** initially; reserve **40 GiB+** for 2 GiB round trips and copies on all four services. Compose caps each service at 0.5 CPU / 384 MiB RAM / 128 PIDs, aggregate 2 CPU / 1.5 GiB plus VM overhead; runtime tmpfs is 128 MiB per service. Named-volume disk usage has **no enforced per-volume quota**: check space and remove test data explicitly; out-of-space is not claimed injected here. Host downloads and image layers need additional space. Container results do not replace full Linux VM/systemd/filesystem fault coverage.

Build needs registry HTTPS and Ubuntu apt repositories. Runtime network is an **internal, dedicated Compose bridge**, no external egress, no LAN ingress; all published ports bind **127.0.0.1 only**. No privileged mode, host paths, host namespaces, Docker socket mounts or production addresses. Driver supports only the selected local `default` or `desktop-linux` Docker context with a normalized absolute Unix-socket endpoint; remote/custom contexts, `DOCKER_HOST` and TLS overrides are refused before Docker metadata queries. It pins every subsequent command to that verified context. A user-mode Desktop install may use `~/.docker/run/docker.sock`; no system socket/link or context switch is required. Read-only image, no-new-privileges, all capabilities dropped except `CHOWN,DAC_OVERRIDE,FOWNER,SETUID,SETGID,SYS_CHROOT,KILL`: OpenSSH's root monitor needs user/group drops and its privilege-separation jail; root fixture bootstrap needs test-volume ownership; KILL permits cancellation/reaping of its own user children. High port 2222 needs no NET_BIND_SERVICE; no SYS_ADMIN/NET_ADMIN. These capability/PAM restrictions still require Linux verification; do not add broad capabilities to hide a failure.

Build routing is also local-only: the wrapper ignores inherited `DOCKER_*`, `BUILDX_*`, `BUILDKIT_*` and `COMPOSE_*` routing overrides, retains the reviewed image input, sets `BUILDX_BUILDER` to the verified context's same-named builtin builder, uses the standard user Buildx config directory and disables Compose Bake. Before writing build state it inspects that builder **without `--bootstrap`** and requires driver `docker`, exactly one node and an endpoint matching the verified context name or exact Unix socket. A missing or mismatched builtin builder fails closed, never falls back to another builder. This supports user-mode Desktop without silently selecting the absent `/var/run/docker.sock`; real Compose/Buildx compatibility still needs Engine-ready verification.

## Files and four isolated instances

| Host loopback | Compose service | Required ordered SSH methods |
| --- | --- | --- |
| 22221 | `keyonly` | `publickey` |
| 22222 | `passwordonly` | `password` |
| 22223 | `key-kbd` | `publickey,keyboard-interactive:pam` |
| 22224 | `password-kbd` | `password,keyboard-interactive:pam` |

Each container is a separate OpenSSH/PAM instance, independent host/client keys, random test password and named volume; sole login user **fixture**, UID/GID 10000. No root login, agent/X11/TCP/stream forwarding or user SSH rc. SFTP subsystem is the fixed Ubuntu package path `/usr/lib/openssh/sftp-server`. The user home `/fixture/home` is UID 10000, 0700; root-owned `/fixture/protected` 0755 contains a 0600 denied file and 0700 denied directory for permission errors. **No login/SFTP ChrootDirectory**: shell, manual nested SSH and external sftp-server use the read-only container filesystem; all user writes stay in its volume or /tmp. OpenSSH's own privilege-separation chroot is distinct and retained. Do not treat container filesystem isolation as a production SFTP jail.

Dockerfile suppresses package service autostart and removes build-generated host keys. `server.py` creates fresh host keys, Ed25519/RSA-3072 client keys **both with/without a random passphrase**, and random password at container start in `/run/openlxssh-fixture` tmpfs; secrets 0600 inside 0700 private subdirectories. Root-owned 0644 `authorized_keys` contains only public keys. Secrets never enter argv or env. Key encryption uses standard ssh-keygen askpass: only its private response pipe carries the passphrase, never console/log output. `server.py export` writes a file; wrapper uses `docker cp` into ignored `.runtime/` (0700) with 0600 files, never displays contents. Engine persistent logs are disabled, PAM catches errors without response tracebacks. Do not record terminals, screenshots or `docker exec` traffic containing test responses.

`.runtime/` is ignored by Git and excluded from Docker build context. It temporarily holds **only disposable test** passwords/keys, trust files and provenance; do not import company secrets. Remove after the campaign, and separately delete imported App test keys/Keychain entries. Restart regenerates all runtime secrets and host keys; it is not a seamless reconnect. Ordinary deletion/volume removal is not forensic SSD erasure.

## Commands — only after explicit approval

Run from this directory, **only after the human agreement, resource checks and main-session Engine-ready signal above**. macOS Python 3.9+ and the approved local Docker Engine + Compose v2 (`up --wait`) are required. No script installs the runtime or modifies the host system. If user-mode Docker's CLI is not on PATH, the main session can use the verified official CLI directory in its own shell (normally `~/.docker/bin`); do not install privileged links just for this runner.

```sh
# First set a genuinely verified official image reference, including its digest:
# export OPENLXSSH_UBUNTU_IMAGE='docker.io/library/ubuntu:24.04@sha256:<verified digest>'
./fixture.sh build --authorized-run        # external image/package downloads
./fixture.sh up --authorized-run           # starts exactly the four services
./fixture.sh inspect --authorized-run
./fixture.sh collect --authorized-run      # prints paths only, never secrets
```

Collect prints one `.runtime/<service>/credentials-<unique>/` path per service. Privately open files there to obtain the test password/passphrase or import test keys into App. Do not `cat` secrets into a captured terminal. No default `~/.ssh`, agent, local private key or Keychain reads. Non-secret `fingerprint.txt` / `known_hosts` come via the local container management channel, not unauthenticated `ssh-keyscan`. For first-contact App testing, manually compare the fingerprint before accepting in **App's own** trust UI; collect does not pre-trust anything in App.

For CLI control checks use a selected credential directory in `CRED`, verified explicitly, and an existing test key, e.g. key-only:

```sh
ssh -F /dev/null -p 22221 -l fixture \
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$CRED/known_hosts" \
  -o GlobalKnownHostsFile=/dev/null -o UpdateHostKeys=no \
  -o IdentityAgent=none -o IdentitiesOnly=yes -o ForwardAgent=no \
  -i "$CRED/id_ed25519" 127.0.0.1
```

Do not disable host checking, silently remove stale trust, send a password via argv, or treat CLI success as GUI acceptance.

### Multi-round / zero prompts / approval

```sh
./fixture.sh scenario --authorized-run --service key-kbd --scenario multi
# Start a new App authentication. Pending prompts show a non-secret session ID.
./fixture.sh challenge --authorized-run --service key-kbd --session <24-hex-session-id>
# Keep this foreground command alive; privately open the saved 0600 JSON and
# manually input responses[0], responses[1], responses[2]. It deletes at expiry
# or Ctrl+C. Do not copy responses into a report, log, screenshot or chat.

./fixture.sh scenario --authorized-run --service password-kbd --scenario zero
./fixture.sh scenario --authorized-run --service password-kbd --scenario approval --delay 8
./fixture.sh scenario --authorized-run --service password-kbd --scenario reject --delay 8
./fixture.sh scenario --authorized-run --service password-kbd --scenario cancel --delay 45
```

`multi`: per-auth independent random 8-digit one-use responses, PAM two-message conversation A+B and then C, 75s expiry; failure/cancel removes active material where cleanup runs, stale runtime material swept on next auth/stop. A retry generates new values. Concurrent sessions have distinct IDs/files. Unknown wording B is intentionally not recognizable as a password. `password-kbd` verifies the random account password first, then checks OpenSSH `SSH_AUTH_INFO_0` metadata for the completed password step; no prompt-text guessing. A wrong initial password must not reach OTP. Do not save OTP in App.

`zero`: information-only PAM conversation with zero input prompts, not an empty Python list (that would never call OpenSSH). `approval`: simulated informational wait then accept; `reject`: wait then reject; `cancel`: bounded wait then reject unless the client is closed earlier. While pending, close App tab / cancel authentication, verify UI responsiveness and child/PTY/FD cleanup; a disconnected server-side PAM worker may remain until the configured wait (max 60s) / LoginGraceTime (90s). No real phone provider is contacted. Native OpenSSH may defer PAM informational text until completion, so a visible live approval message and genuine zero-prompt wire packet are **not** asserted before real testing.

**Important uncovered requirement:** upstream OpenSSH 9.6 `sshpam_thread_conv`/`sshpam_query` serializes PAM multiple prompts into **one-prompt SSH rounds**. This fixture's A+B is two PAM prompts, **not guaranteed a single SSH Keyboard-Interactive message with two prompts**. Real wire-level multi-prompt acceptance remains unverified/uncovered; client unit/control-plane tests do not replace it. Do not patch/implement SSH or introduce a mock server to claim coverage.

### Host rotation, disconnect, SFTP data and nested SSH

```sh
./fixture.sh rotate-host --authorized-run --service keyonly
# Try a NEW connection with the unchanged old App/CLI trust: must reject changed
# identity. Existing sessions are not evidence of a new host-key handshake.
# collect again to a NEW directory to compare out-of-band; never overwrite old
# known_hosts or automatically update App trust.
./fixture.sh collect --authorized-run --service keyonly
./fixture.sh disconnect --authorized-run --service keyonly  # stop owned service
./fixture.sh start --authorized-run --service keyonly       # NEW credentials/keys
./fixture.sh data --authorized-run --service keyonly
```

Data generation runs as unprivileged UID/GID 10000, refuses existing `corpus`, and writes a **real non-sparse 2 GiB** file + **1,000** small files (plus Unicode/space/special-name example), SHA-256 manifest, relative symlink, loop and outside-corpus link. Streamed with a 1 MiB block; no 2 GiB allocation. Requires enough named-volume free space and does not run automatically. Root-owned denied paths are outside writable corpus. Download/upload via App and verify a selected **downloaded** corpus without following symlinks:

```sh
python3 generate_data.py verify --authorized-run --root /absolute/path/to/downloaded/corpus
```

Hash verification is necessary but not all AC-31: separately record actual round-trip hashes, elapsed/throughput, peak memory, cancellation/forced service-stop results and target preservation. Malicious manifests/absolute or `..` paths/symlink traversal are rejected. Disk-full, packet-loss/blackhole timeout and unsupported rename capabilities need later approved Linux fault scenarios; `disconnect` is a real abrupt service stop, not those faults.

For **manual** nested SSH: first connect App to `password-kbd` (22224), then type this **inside the remote shell**:

```sh
ssh -F /fixture/home/.ssh/config -p 2222 -l fixture \
  -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive 127.0.0.1
```

It connects from that container to its own independent second sshd session, with private server-known trust provisioned at bootstrap; no host networking/ProxyJump required. The inner client has **no private keys/agent**. Manually type the disposable account password and OTPs (fetch the new session challenge with `--service password-kbd` on the host); do not copy any App key. Test Ctrl+C, resizing, exit to outer shell, unknown prompts and cancellation. App must never inject any local Keychain/App secret into the inner process; no automatic credential handling, agent forwarding, copied private key, ProxyJump or graphical SFTP to the inner layer. `keyonly` / `key-kbd` intentionally cannot self-nest successfully without an inner private key. This same-server nested session tests the client boundary, not separate-host routing or enterprise jump networks. Rotation intentionally leaves nested trust unchanged too.

### Stop / remove only owned resources

```sh
./fixture.sh stop --authorized-run
./fixture.sh remove --authorized-run
```

A random per-workspace Compose project is recorded in 0600 state. Wrapper checks **both** that project's Compose label and `org.openlxssh.fixture=env-fixture-a` before stop/remove/exec; never uses global prune, wildcard resources, force-removal or host paths. `remove` stops/removes only these containers, dedicated internal network and named test volumes, then its own ignored `.runtime/`; it refuses symlinks. It retains the fixture image and build cache (not secret-bearing); no automatic deletion of other images or runtime VM. If state is lost/tampered, do not guess resource names: inspect exact labels with user/主管 coordination, do not run global cleanup. Also clear any App-imported disposable credentials manually.

## Offline verification and remaining Linux checks

```sh
bash -n fixture.sh
PYTHONDONTWRITEBYTECODE=1 python3 test_static.py
```

These only compile Python in memory, parse Compose YAML via system Ruby, check config/auth/ownership/path boundaries, refusal without `--authorized-run`, local context/Unix-endpoint pinning and remote-builder rejection using mocks, and create temporary **non-secret metadata**. They never call the real Docker CLI, generate credentials/test corpora, run PAM/sshd, or connect. No `docker compose config`, package install, build or Linux test was performed here. Mock builder inspection proves the wrapper's checks, not actual Desktop/Compose/Buildx compatibility.

Must validate after approval: Noble arm64 package availability and `/lib/security/pam_python.so` Python3 ABI, `/usr/lib/openssh/sftp-server`, default PAM module search paths, no-new-privileges/capabilities with OpenSSH root-monitor chroot/PTY/session/PAM, real `sshd -t` (bootstrap checks it before listening), SSH_AUTH_INFO_0 on Ubuntu-patched OpenSSH, password-then-kbd ordering, encrypted RSA/Ed25519 askpass, approval info/zero-query behavior, cancel worker cleanup, internal-network port reachability, Compose `--wait`, real SFTP, host rotation/restart behavior and data round trips. Do not label any AUTH/NEST/FILE AC passed until observed. Real single-message 2-prompt coverage needs a separate mature-backend solution or an explicitly recorded outstanding acceptance item, not a mock.

Public API/design references (not runtime proof): [Ubuntu Noble libpam-python](https://launchpad.net/ubuntu/noble/+package/libpam-python), [Ubuntu package install path](https://git.launchpad.net/ubuntu/+source/pam-python/tree/debian/libpam-python.install?h=ubuntu/noble), [pam-python conversation API](https://pam-python.sourceforge.net/doc/html/), [OpenSSH 9.6p1 auth-pam.c](https://github.com/openssh/openssh-portable/blob/V_9_6_P1/auth-pam.c), [sshd_config Noble](https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html). This directory is not part of App/Packages and has not changed their behavior.
