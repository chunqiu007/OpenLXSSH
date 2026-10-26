# MINA keyboard-interactive fixture — integration contract

Task `AUTH-MINA-FIXTURE-A`. Test-only Apache MINA SSHD **2.20.0** public API; no App dependency, host JVM, SSH implementation, upstream patch, or protected multi-round adapter.

**Current boundary:** source and offline checks only. No Docker pull/build/up, Java compilation/execution, SSH connection or wire acceptance has been performed. The primary resolved the official Ubuntu digest below; Docker Desktop first-run legal acceptance requires the human, and the engine is not released for this fixture. The user authorized the local test environment, but that does not authorize accepting legal terms or bypassing the primary's engine-ready gate.

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

`generateChallenge == null` is reserved for refusal (unknown user, closed/unadmitted session, attempt/pending limit). It is **not** a zero challenge. The fixed source was inspected: MINA `UserAuthKeyboardInteractive.doInitialAuth` invokes `challenge.append` then exactly one `writePacket`; response count mismatch fails before authenticator invocation. The container-only `FixtureContractTest` uses actual `InteractiveChallenge.append`/`ByteArrayBuffer`, ordered mixed echo checks, zero-vs-null, response mismatch and one-shot `AsyncAuthException`; it has not run and, even when it runs, is **not wire interoperability**.

Bounds are explicit: 8 live admitted SSH sessions, 8 pending attempts total, 3 KBI attempts per session, 75s monotonic attempt TTL, 90s SSH authentication timeout, 120s idle timeout, 1 concurrent channel/session. One 2-thread scheduled executor; admission permits at most 2 timers/attempt, remove-on-cancel enabled. Delay is 1..60s. There is no sleep/provider wait in either authentication callback, no auto retry and no per-attempt thread. Each attempt snapshots the scenario/delay; changing policy only affects new attempts.

Each attempt has a fresh 24-hex non-secret ID and two independent SecureRandom-generated 10-digit answers (only `two`). Echo flags are UI metadata, **not** a secret classifier: both answers remain disposable secrets and must never be retained as passwords. Source never prints answers, prompt objects, response lists, packets or exception details. Secret char arrays are cleared and attempt files deleted on authenticator-visible completion/rejection/replacement/TTL/session close/shutdown; timers are cancelled. A malformed response count rejected inside MINA before the authenticator callback is cleaned on session close/replacement/TTL, not claimed synchronously observed by this public API. Async completion compares the exact attempt object/session and checks close/auth/expiry, then calls `setAuthed` **outside the provider lock**; MINA's own current-auth guard rejects stale completions too. MINA/JDK API strings and serialization necessarily create transient immutable copies; JVM heap erasure is not claimed. Host keys are generated in memory once/container; no private key is exported.

After authentication the only shell/exec behavior is a fixed success line and exit. Exec accepts only literal `fixture-ok`; no local process spawning, shell interpolation, subsystems, SFTP or forwarding is supplied. This is an auth backend, not a terminal compatibility server.

## Runtime and parent-runner integration

`compose.contract.yaml` is a **contract for review**, not an alternate authorized runner. Do not bypass the parent wrapper with direct Compose up. The parent writer must add an owned operation or otherwise explicitly review the lifecycle before use; no parent file has been modified here.

- Fixed ARM64 Dockerfile, UID/GID `10000:10000`, read-only root, ALL capabilities dropped, no-new-privileges, 0.5 CPU / 512 MiB RAM+swap limit / 128 PIDs, core dumps disabled, no restart, 5s stop grace.
- A dedicated internal bridge, no runtime egress; exactly **`127.0.0.1:22225:2222`** published. No LAN/public HTTP management endpoint, host bind mounts, Docker socket, host namespaces or production addresses.
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

Files for `docker cp` only, never `exec cat`/stdout:

| Container path | Contents / lifetime |
| --- | --- |
| `/run/openlxssh-multiprompt/trust.json` | Public known_hosts for 127.0.0.1:22225 plus SHA256 fingerprint, fetched out-of-band |
| `/run/openlxssh-multiprompt/attempts/<24hex>.json` | `attempt`, `expires_at`, ordered `responses`, `echo`; 0600, only while an active `two` attempt is pending |
| `/run/openlxssh-multiprompt/status.json` | IDs/scenario/count/response-callback/outcome/queue counters only; no credential values |
| `/opt/multiprompt/inputs.lock.json` and `/opt/multiprompt/packages.txt` | Public provenance; parent also records actual image ID |

Host export contract, only after the parent validates ownership and engine readiness:

1. Run `PYTHONDONTWRITEBYTECODE=1 python3 private_export.py prepare`; it creates only this subtree's ignored `.runtime/` as owned 0700 and refuses stale incoming/symlink paths.
2. Parent uses `docker cp "$VERIFIED_ID:/run/openlxssh-multiprompt/trust.json" .runtime/incoming.json` with captured/suppressed output, never command substitution of content. `python3 private_export.py trust` validates and moves public trust into a unique 0700 `trust-*/` with 0600 files, printing **path only**. Never overwrite an old known_hosts generation; compare the App's first-contact fingerprint manually.
3. Start a new App auth; its prompt/instruction carries the non-secret 24-hex ID. Parent checks active challenge then copies `attempts/<id>.json` to `.runtime/incoming.json`. `python3 private_export.py challenge --attempt <id>` validates schema/TTL and retains 0600 `challenge-<id>.json` in the foreground. Privately open it and manually input the two responses; no reports/screenshots/chat/terminal recordings. Foreground deletes at TTL or Ctrl+C. Parent should also delete host copy on session close; the exporter alone cannot observe remote session close and does **not** claim immediate host cancellation cleanup. SIGKILL/power loss can leave a copy until explicit owned cleanup.
4. Parent finally removes only its known incoming/challenge paths, stops the owned container and removes its labeled internal network; host `.runtime` cleanup must refuse symlinks. Container tmpfs disappears on removal. Ordinary deletion is not forensic SSD erasure. Clear any disposable App-imported/trusted data separately.

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

## Offline checks now; container/wire tests later

From this subtree (absolute paths also work):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 test_static.py
PYTHONDONTWRITEBYTECODE=1 python3 fetch_inputs.py --verify-cache
```

The offline suite parses Python and Compose via system Ruby, checks exact pins/resource/network/ownership/echo/zero/async source boundaries, verifies cancellation guards/timer cleanup, refuses invalid arguments before side effects, and uses temporary **non-secret metadata** to test file permissions/symlink/expiry. It never calls Docker/Java/SSH or creates a test credential. With the authorized cache present it checks the fixed upstream zero/single-message code path; absence is explicitly skipped, not passed. Hash verification is a separate mandatory command. Downloads, when explicitly permitted, use `fetch_inputs.py --authorized-download`; no code is executed by that command.

After the human handles Docker Desktop legal acceptance and the primary releases engine/resource/context/builder checks, exact remaining steps are:

1. Integrate/review the contract in the owned parent runner; build only this pinned context for `linux/arm64`. Capture build output in non-secret verification logs. Check real `javac` and `FixtureContractTest` success, apt package versions, runtime JAR inventory, image ID/base digest/license notices.
2. Inspect running container constraints and actual 127.0.0.1-only port/internal network; use the management trust export, never skip host verification.
3. Real wire: `two` correct/wrong/swapped/count mismatch, exactly one client KBI callback with 2 prompts and echo false/true; zero accept/reject each yields an actual 0-prompt client callback and server response-callback counter; null refusal emits no such callback. Counts require actual client/lib test evidence, not this source inspection.
4. Async real wire/UI: delay approve/reject, timeout, cancel waiting client before delayed approval, wait past delay and verify no success/pending timers/material; retries use new IDs/answers, concurrent sessions cannot cross-answer; session/FD/threads/queue return to baseline. Tests must send a new connection for each independent attempt. A test must exercise stale callback races separately if claiming observed late-result behavior.
5. App verification separately checks necessary zero-prompt/approval information rendering, user cancellation responsiveness, unknown prompt manual input/no saved-secret injection, no OTP persistence/logs, cleanup and explicit failed/timeout states. OpenSSH parent handles high-level multi-round separately; no `2→1→0` same-KBI claim, enterprise provider compatibility, macOS26 acceptance or product AC is granted by this fixture.
