# MINA keyboard-interactive fixture — integration contract

Task `AUTH-MINA-FIXTURE-A`. Test-only Apache MINA SSHD **2.20.0** public API; no App dependency, host JVM, SSH implementation, upstream patch, or protected multi-round adapter.

**Current boundary:** `AUTH-MINA-BUILD-JAVA-A` completed the explicitly released, child-only ARM64 container build with `managed.sh build --authorized-run`. Both fixture classes compiled with the real JDK and the real-library `FixtureContractTest` passed inside the build. `AUTH-MINA-RELAY-INTEGRATION-A` adds only the source/offline integration of the reviewed shared relay; it does not release or execute runtime use. No host Java, fixture service startup, real relay, SSH connection or wire acceptance was performed here. `up` and `relay` require both explicit `--allow-start` and `--relay-mode` after the primary's separate runtime release; build/source success alone is not that release.

## Fixed inputs and licenses

`inputs.lock.json` records exact HTTPS URLs and **SHA512 for all 17 downloaded inputs**, including POMs and source JARs. `fetch_inputs.py` verifies bytes before writing/using them, limits download size, allows only `downloads.apache.org` / `repo.maven.apache.org`, and refuses cross-host/non-HTTPS redirects. It never executes downloaded code. `.cache/` is ignored/excluded from build context; only a reviewed container build may execute JARs.

- Ubuntu: `docker.io/library/ubuntu:24.04@sha256:18b33ff3829707f31ada654a963b9ee35f2e6f0241b964bd17a22a9b330cb63d`, official ARM64 reference supplied by the primary after registry inspection. Both Dockerfile stages are pinned to it.
- [Official MINA 2.20.0 release page](https://mina.apache.org/sshd-project/download_2.20.0.html); source corresponds to commit `2221febd396cd3daafdfbf2ff982c6d0eb69a203`.
- Source archive `apache-sshd-2.20.0-src.tar.gz` SHA512:
  `fa1c2f498e8681681229062d8c3fe2e730778046ff1c1aaccdff703a97f7aa35ea0d649a3124098666e35ad1fbf93a368ba827fdacbb64908d70472de622bd7c`.
- Official binary archive `apache-sshd-2.20.0.tar.gz` SHA512:
  `3d4812391535afe931c1b8ec449ad9a75fabd134e320c0a270f216ea02ef72d9643f71208d615b3dcbae9e6aa74be5e81904e9dae8a79ccadb831f38e8534fb3`.
- Both archives actually matched their official `.sha512` responses. Four runtime JARs below also matched **byte-for-byte** the corresponding entries in that binary archive. `slf4j-nop` comes from Maven Central only and is separately SHA512 pinned. Maven `.sha1` values were checked as supplementary repository transport checks; SHA1 is not the execution-integrity mechanism. PGP release signatures have **not** been verified; do not claim signature authentication.

Small runtime closure, resolved from the pinned parent/core/common/SLF4J POMs:

| Runtime artifact | Purpose / provenance | License and preserved notice |
| --- | --- | --- |
| `sshd-core:2.20.0` | Actual SSH server/auth; Maven + official archive equality | Apache-2.0; `licenses/MINA-*` |
| `sshd-common:2.20.0` | Required MINA common; same verification | Apache-2.0; `licenses/MINA-*` |
| `slf4j-api:1.7.36` | Inherited non-optional dependency; same verification | MIT; exact copyright/permission header in `licenses/slf4j-api-1.7.36-source-notices.txt` |
| `jcl-over-slf4j:1.7.36` | Inherited non-optional dependency; same verification | Apache-2.0; exact source header in `licenses/jcl-over-slf4j-1.7.36-source-notices.txt` and full Apache text in MINA license |
| `slf4j-nop:1.7.36` | Explicit same-version no-op binding, suppresses all library logs | MIT; exact header in `licenses/slf4j-nop-1.7.36-source-notices.txt` |

No BouncyCastle, eddsa, tomcat-apr, netty, MINA transport module, SFTP, LDAP, Git, mockito, JUnit or Maven plugin is included. NIO2 and RSA-3072 use the JDK's mature implementations. No upstream files are modified. Original source/binary license and NOTICE files are copied unchanged; source-notices files preserve original headers grouped with their originating Java filenames. The final container also retains Ubuntu package copyright metadata at `/usr/share/doc/*/copyright`; OpenJDK is GPL-2.0 with Classpath Exception and other package notices remain applicable. Apt versions are **not** claimed frozen: the runtime build records `/opt/multiprompt/packages.txt`; the parent must record built-image ID and reuse that image for a test campaign.

## Authentication semantics and limits

Sole username: `fixture`; only `keyboard-interactive` is offered. Four ordered password/key methods remain the separate parent OpenSSH fixture's responsibility. MINA provides only one high-level challenge per attempt here:

| Scenario | Actual library call path | Completion |
| --- | --- | --- |
| `two` (default) | One non-null challenge, exactly two `addPrompt` calls, echo `[false,true]` in order; MINA appends both into its single INFO_REQUEST | Both independent answers must match; wrong/order/count mismatch rejects |
| `zero-accept` | Non-null challenge with **empty prompt list**, MINA sends count 0 and receives count 0 | `authenticate(..., emptyList)` accepts |
| `zero-reject` | Same real zero challenge and response callback | Rejects only after that callback; not a null-challenge shortcut |
| `approval` | Same zero challenge, then `authenticate` creates/throws `AsyncAuthException` | Scheduler calls `setAuthed(true)` after delay |
| `reject` | Same async path | Scheduler calls `setAuthed(false)` after delay |
| `cancel` | Same async path; approval would be due after delay | Client must close while pending; `sessionClosed` cancels timer and removes state, and a raced/late callback cannot accept another attempt |
| `timeout` | Same async path, no decision timer | Attempt TTL sends async false; SSH auth timeout is a separate upper bound |

`generateChallenge == null` is reserved for refusal (unknown user, closed/unadmitted session, attempt/pending limit). It is **not** a zero challenge. The fixed source was inspected: MINA `UserAuthKeyboardInteractive.doInitialAuth` invokes `challenge.append` then exactly one `writePacket`; response count mismatch fails before authenticator invocation. The container-only `FixtureContractTest` uses actual `InteractiveChallenge.append`/`ByteArrayBuffer`, ordered mixed echo checks, zero-vs-null, response mismatch and one-shot `AsyncAuthException`; it passed during the authorized build and is **not wire interoperability**.

Bounds are explicit: 8 live admitted SSH sessions, 8 pending attempts total, 3 KBI attempts per session, 75s monotonic attempt TTL, 90s SSH authentication timeout, 120s idle timeout, 1 concurrent channel/session. One 2-thread scheduled executor; admission permits at most 2 timers/attempt, remove-on-cancel enabled. Delay is 1..60s. There is no sleep/provider wait in either authentication callback, no auto retry and no per-attempt thread. Each attempt snapshots the scenario/delay; changing policy only affects new attempts.

Each attempt has a fresh 24-hex non-secret ID and two independent SecureRandom-generated 10-digit answers (only `two`). Echo flags are UI metadata, **not** a secret classifier: both answers remain disposable secrets and must never be retained as passwords. Source never prints answers, prompt objects, response lists, packets or exception details. Secret char arrays are cleared and attempt files deleted on authenticator-visible completion/rejection/replacement/TTL/session close/shutdown; timers are cancelled. A malformed response count rejected inside MINA before the authenticator callback is cleaned on session close/replacement/TTL, not claimed synchronously observed by this public API. Async completion compares the exact attempt object/session and checks close/auth/expiry, then calls `setAuthed` **outside the provider lock**; MINA's own current-auth guard rejects stale completions too. MINA/JDK API strings and serialization necessarily create transient immutable copies; JVM heap erasure is not claimed. Host keys are generated in memory once/container; no private key is exported.

After authentication the only shell/exec behavior is a fixed success line and exit. Exec accepts only literal `fixture-ok`; no local process spawning, shell interpolation, subsystems, SFTP or forwarding is supplied. This is an auth backend, not a terminal compatibility server.

## Runtime and parent-runner integration

`compose.contract.yaml` is a **contract for review**, not an alternate authorized runner. Do not bypass `managed.sh` with direct Compose up. The child runner reads only the parent local-engine/environment helpers and owns its separate immutable project/image metadata; no parent file has been modified here. Docker internal networks have not supplied usable host-published listeners in the reviewed environment. The child now loads the shared root `relay.py` from its exact non-symlink source location, verifies the frozen target fields/serve signature, and delegates transport/cleanup rather than implementing a second relay. `require_reviewed_relay()` rejects a missing/changed API before runtime metadata or Docker operations. The accepted optional keyword-only `startup_deadline=None` is not passed by this child.

- `relay` has no host, port, context, container ID or arbitrary endpoint input. It constructs one `FrozenDockerTarget` from the validated child state, recorded image, exact owned healthy container and attached internal network; service/fixture/host port are fixed to `multiprompt` / `auth-mina-fixture-a` / `22225`.
- Both `up` and `relay` require `--authorized-run --allow-start --relay-mode`. Foreground relay duration is an integer **1..1800 seconds**, default 1800. The source-only checkpoint did not invoke either operation; wait for the primary's explicit runtime release.
- Default container validation still rejects empty effective port bindings. Only explicit `--relay-mode` accepts the exact observed `NetworkSettings.Ports={"2222/tcp":[]}` while retaining strict requested `HostConfig.PortBindings` of `127.0.0.1:22225`. Missing, unknown, LAN/wildcard, IPv6 and extra port metadata are rejected. Acceptance is a confinement check, **not** host reachability proof.
- A short child operation lock protects target snapshot/recheck, then is released before `serve`; scenario/status/trust remain usable while relay is foreground. The same `--relay-mode` is required for those management actions when effective port bindings are empty. The shared library owns listener/worker/signal cleanup; import bindings and lock ownership are restored on failure/cancellation. Stop/remove remain limited to the child's exact owned resources.

- `copy_json` uses only a fixed UID10000 `docker --host <verified Unix endpoint> exec /usr/bin/tar` binary pipe for `trust.json` or `attempts/<24hex>.json`; Docker cp does not reliably read tmpfs/user mounts. Output is captured only, bounded to 64 KiB/15 seconds, parsed as one exact regular 0600 tar entry of at most 4096 bytes, then schema-validated. No shell, arbitrary reader/path, terminal output or host mount is added. This path has offline safety tests only; no real challenge was read in this task.

- Fixed ARM64 Dockerfile, UID/GID `10000:10000`, read-only root, ALL capabilities dropped, no-new-privileges, 0.5 CPU / 512 MiB RAM+swap limit / 128 PIDs, core dumps disabled, no restart, 5s stop grace.
- A dedicated internal bridge, no runtime egress; the current contract requests only **`127.0.0.1:22225:2222`**, but host reachability is unverified and is not inferred from that request. No LAN/public HTTP management endpoint, host bind mounts, Docker socket, host namespaces or production addresses.
- Dedicated tmpfs `/run/openlxssh-multiprompt`, 0700 owned by UID10000 (16 MiB), plus `/tmp` (32 MiB); no persistent secret volume. Runtime logs driver `none`, SLF4J NOP, JVM heap dumps not enabled.
- Parent must require explicit engine-ready/human-license gate, reject remote `DOCKER_HOST`, remote/custom contexts, TLS endpoint overrides and inherited `BUILDX_*`; use its fixed reviewed local builder, not an environment-selected builder. Only verified local default/desktop-linux Unix sockets are allowed.
- Parent must assign a random owned project and check **both** `com.docker.compose.project` and `org.openlxssh.fixture=auth-mina-fixture-a` on container/network/image operations; inspect actual confinement/port bindings after startup; never adopt guessed/unlabeled resources or use prune/global cleanup. Existing parent label `env-fixture-a` is different and must not silently be reused.
- Build stages may reach official Ubuntu apt + fixed official/Maven inputs; no SSH server runs at build. `javac -proc:none --release 21 -Xlint:all` and real-library contracts execute only in the approved container build. No Java install or remote-code execution on macOS.

Container management API (parent invokes `docker exec --user 10000:10000` on its **verified owned container ID**; all command arguments below are non-secret):

```text
python3 /opt/multiprompt/control.py scenario --authorized-run --scenario <name> --delay <1..60>
python3 /opt/multiprompt/control.py status --authorized-run
python3 /opt/multiprompt/control.py check-challenge --authorized-run --attempt <24hex>
python3 /opt/multiprompt/control.py health --authorized-run
```

Management files exported only through the fixed captured `exec tar` pipe (not `docker cp` or stdout):

| Container path | Contents / lifetime |
| --- | --- |
| `/run/openlxssh-multiprompt/trust.json` | Public known_hosts for 127.0.0.1:22225 plus SHA256 fingerprint, fetched out-of-band |
| `/run/openlxssh-multiprompt/attempts/<24hex>.json` | `attempt`, `expires_at`, ordered `responses`, `echo`; 0600, only while an active `two` attempt is pending |
| `/run/openlxssh-multiprompt/status.json` | IDs/scenario/count/response-callback/outcome/queue counters only; no credential values |
| `/opt/multiprompt/inputs.lock.json` and `/opt/multiprompt/packages.txt` | Public provenance; parent also records actual image ID |

Host export contract, only after the managed runner validates ownership and engine readiness (for the child actions below, add `--authorized-run --relay-mode`; no credential appears in argv):

1. `managed.sh trust` captures the fixed trust tar pipe in memory, validates it, and writes a unique owned 0700 `.runtime/trust-*/` with 0600 `known_hosts` and `fingerprint.txt`, printing **path only**. Never overwrite an old known_hosts generation; compare the App's first-contact fingerprint manually.
2. Start a new App auth; its prompt/instruction carries the non-secret 24-hex ID. `managed.sh challenge --attempt <id>` verifies the active challenge, captures only its exact tmpfs file through the fixed pipe, validates schema/TTL, and delegates foreground 0600 retention to `private_export.py`. Privately open the returned path and manually input the two responses; no reports/screenshots/chat/terminal recordings. Foreground deletes at TTL or Ctrl+C. The exporter alone cannot observe remote session close and does **not** claim immediate host cancellation cleanup. SIGKILL/power loss can leave a copy until explicit owned cleanup.
3. Stop the foreground relay and use only managed owned stop/remove operations. Host `.runtime` cleanup must refuse symlinks; immutable build/trust metadata remains owned. Container tmpfs disappears on removal. Ordinary deletion is not forensic SSD erasure. Clear any disposable App-imported/trusted data separately. The old standalone incoming/docker-cp path is not the managed export route.

A CLI control command must use collected public trust and no ambient config/agent, e.g. after reviewed runner starts the service:

```sh
ssh -F /dev/null -p 22225 -l fixture \
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$TRUST/known_hosts" \
  -o GlobalKnownHostsFile=/dev/null -o UpdateHostKeys=no \
  -o PubkeyAuthentication=no -o PasswordAuthentication=no \
  -o PreferredAuthentications=keyboard-interactive -o IdentityAgent=none \
  -o ForwardAgent=no 127.0.0.1 fixture-ok
```

No credential values go into argv/env. This example is not executed here and does not replace App GUI tests.

## Verified container build; runtime/wire tests remain

`AUTH-MINA-BUILD-JAVA-A` first managed build exited **0** after 80.7 seconds. Before it, the real selected `desktop-linux` local context, single builtin `docker` builder, Compose configuration and Docker Desktop 2 CPU / 4 GiB settings passed the reviewed checks. Both Dockerfile stages retained the fixed Ubuntu digest above; no Java source, Dockerfile or lock-file change was needed.

- Image tag: `openlxssh-auth-mina-fixture:2.20.0-arm64`; inspected `linux/arm64` image ID: `sha256:18c77956cd388408edd3141b6d96ace4fce188dd038bea0c8cbc2d4435e1d84a`.
- Source SHA256: `72c6106b34bf3fb09c9e45c4693c04d48a1784ac37130fe1fb61651c034d3242`; owned project: `openlxssh-mina-4ef7485cc4e9`. Both ownership labels, fixed base/source labels and the exact image ID matched the immutable private `state.json`/`build.json` record. Post-build inspection found **zero** child containers and networks.
- The build downloaded and SHA512-verified all **17** fixed public inputs. The non-cached build step ran `javac -proc:none --release 21 -Xlint:all` on both fixture classes, then printed `Real-library serialization/validation contracts passed; no wire connection performed.` Runtime retained the five fixed JARs through the reviewed Dockerfile copies.
- One compiler warning remains: `FixtureServer.java:461`, `[try] explicit call to close() on an auto-closeable resource` in the shutdown hook. It did not fail compilation or the contract test. The original build log is retained; warnings were not suppressed.
- Apt packages were not version-frozen. The log records `openjdk-21-jdk-headless` / `openjdk-21-jre-headless` `21.0.12.1+1-1~24.04.4` and `python3` `3.12.3-0ubuntu2.1`; the image contains the generated `/opt/multiprompt/packages.txt`. A separate file-level image inventory/export has not been performed.
- Local ignored evidence: raw `.logs/build-01fbc68ac16d.log`; `.cache/mina-build-java-a-frozen-preflight.json`, `.cache/mina-build-java-a-attempt1.json` and `.cache/mina-build-java-a-postverify.json`. Runtime metadata and log files are 0600 under owned 0700 directories. No service, host Java or SSH client was executed.

Offline checks remain available from this subtree (absolute paths also work):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 test_static.py
PYTHONDONTWRITEBYTECODE=1 python3 fetch_inputs.py --verify-cache
```

The offline suite parses Python and Compose via system Ruby, checks exact pins/resource/network/ownership/echo/zero/async source boundaries, verifies cancellation guards/timer cleanup, refuses invalid arguments before side effects, and uses temporary **non-secret metadata** to test file permissions/symlink/expiry. It never calls Docker/Java/SSH or creates a test credential. Its build-context check requires exact private-directory exclusions without re-inclusion, refuses a symlink runtime, and validates retained owned state/source/build metadata if present; do not delete the retained owned build metadata merely to rerun checks. With the authorized cache present it checks the fixed upstream zero/single-message code path; absence is explicitly skipped, not passed. Hash verification is a separate mandatory command. Downloads, when explicitly permitted, use `fetch_inputs.py --authorized-download`; no code is executed by that command.

Remaining steps require separate reviewed runtime release; this source checkpoint does not permit executing `up` or `relay`:

1. The primary must review the child source delta and verify the shared root relay's real-runtime readiness before releasing the child's exact runtime lifecycle. Reuse the recorded image; no build input/source hash changed in the child integration. Verify the file-level runtime JAR/package/license inventory when that inspection is authorized.
2. Inspect running container constraints and actual 127.0.0.1-only port/internal network; use the management trust export, never skip host verification.
3. Real wire: `two` correct/wrong/swapped/count mismatch, exactly one client KBI callback with 2 prompts and echo false/true; zero accept/reject each yields an actual 0-prompt client callback and server response-callback counter; null refusal emits no such callback. Counts require actual client/lib test evidence, not this source inspection.
4. Async real wire/UI: delay approve/reject, timeout, cancel waiting client before delayed approval, wait past delay and verify no success/pending timers/material; retries use new IDs/answers, concurrent sessions cannot cross-answer; session/FD/threads/queue return to baseline. Tests must send a new connection for each independent attempt. A test must exercise stale callback races separately if claiming observed late-result behavior.
5. App verification separately checks necessary zero-prompt/approval information rendering, user cancellation responsiveness, unknown prompt manual input/no saved-secret injection, no OTP persistence/logs, cleanup and explicit failed/timeout states. OpenSSH parent handles high-level multi-round separately; no `2→1→0` same-KBI claim, enterprise provider compatibility, macOS26 acceptance or product AC is granted by this fixture.
