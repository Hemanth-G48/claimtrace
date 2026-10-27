# ClaimTrace Architecture

**Status:** target architecture for Problem Statement 1. This document describes the
single-package dependency-assessment tool, not the registry scanner. Package code runs only in
an isolated environment. The assessment is not a malware verdict, and "clean" is not an outcome.

**Status distinctions:** *target architecture* is this document; *existing code* is summarized in
section D; *verified integration* exists only after Milestone 2 passes. `archive_path` support is
verified for the local Tetragon path; the recording-sinkhole/fake-DNS path is implemented and
verified for common TCP ports, with the limits recorded in §E.

All diagrams are ASCII.

---

## A. Purpose and invariants

The tool takes one package at a time, from a local artifact or a direct `name@version` lookup,
and answers a narrow question: **does the observed install/import behavior match what the
package's own README and metadata claim?**

Invariants:

- The input is a local artifact or a direct package coordinate. It is not a registry release,
  and it does not pass through ingest gates.
- The assessment never reuses the registry scanner's `Scan.verdict`. It never uses the words
  `malicious` or `safe`.
- Static findings and LLM triage are optional stretch context. They are not required for the
  core assessment and never change an observation outcome or the package result.
- Missing documentation or missing telemetry is not proof of safety.
- A sensitive observation remains visible even when claims or coverage are missing.
- Package code never runs on the host and never receives host credentials.
- The flow is sequential: one assessment writer; no concurrent assessment writes.
- Every conclusion points to a claim, an observed event, the package input, and the coverage
  status.
- A human makes the accept/investigate/reject decision.

## B. Architecture at a glance

```text
 Stage 0 input
 local artifact or name@version
            |
            v
 [1] resolve + stage the artifact
     (no ingest gates, queue, eligibility policy,
      no-code-changes skip, or Discord)
            |
            v
 [2] extract claims from the artifact's README/metadata
            |
            v
 [3] hardened sandbox: install -> entry -> import
     (sinkholed, no host credentials)
            |
            v
 [4] capture -> normalize -> coverage
            |
            v
 [5] per-observation classification
     explained | declared-sensitive | unexplained |
     insufficient | unremarkable
            |
            v
 [6] package assessment rule
            |
            v
 [7] report -> human decision
```

There is no asynchronous detonation queue, no second assessment writer, and no reconciliation
machinery in this path. Static findings and LLM triage are optional stretch context; neither is
on this path or changes an observation outcome.

## C. Stage 0 and the sequential workflow

### Stage 0 - input

The input is either:

- a local package artifact (an npm tarball or a PyPI sdist/wheel), or
- a direct `name@version` coordinate that the CLI resolves into a local staged archive once; the
  CLI then passes that staged archive to the detonation API. The API does not resolve or fetch a
  registry release.

Stage 0 deliberately skips:

- registry release discovery and ingest gates;
- the scan queue;
- `should_detonate`/detonation eligibility policy;
- the no-code-changes skip;
- Discord and all other notifications.

A `name@version` input is a direct lookup, not a registry-release assessment. A local artifact is
the preferred demo input because it is reproducible and does not depend on registry availability.

### Does the detonation API accept a staged local archive?

Yes. The detonation request body requires `ecosystem`, `name`, `version`, `archive_path`, and
`archive_kind`; the sandbox is constructed from `archive_path`. The API does not resolve or fetch
a registry release.

The existing worker has a vault-first path and a registry re-fetch fallback, but Stage 0 does not
use that worker: it stages the local artifact and calls the detonation client/API directly with
the staged path. The local Tetragon path is exercised end to end; the recording sinkhole and
fake DNS resolver are implemented and exercised by `network-demo`, which resolves an unclaimed
hostname to the sinkhole and records the DNS query and TCP acceptance.

Acceptance contract: stage a local artifact, call the API with that path, verify the sandbox reads
the staged bytes, and verify no registry request occurs. This is verified for the local Tetragon
path, including a sinkhole-only network with `--internal` and no upstream DNS.

### Sequence

1. **Resolve and stage.** Accept the local artifact, or let the CLI resolve `name@version` once
   into a local staged archive and pass that path to the API. Record the package identity and
   staged path/digest. No queue, gates, eligibility check, code-change skip, or Discord.
2. **Extract claims.** Read the README and metadata from the artifact. Produce a small,
   source-referenced claim set with confidence and ambiguity.
3. **Run install.** Execute the ecosystem's install phase in the isolated environment.
4. **Run entry.** Resolve the package entry point on the extracted tree and run it as its own
   phase, so entry-time behavior is not mislabeled as install-time behavior.
5. **Run import.** Resolve and execute the import target from the installed layout.
6. **Capture.** Record the supported behavioral events and the phase in which they occurred.
7. **Normalize and assess coverage.** Strip unstable fields, dedupe, and record whether the run
   and capture were complete, incomplete, or unverified.
8. **Classify each observation.** Assign `explained`, `unexplained`, `declared-sensitive`, or
   `insufficient`, with a reason and evidence reference.
9. **Assess the package.** Apply the package-level rule in section G.
10. **Report.** Render the claims, observations, outcomes, context, coverage, and evidence chain.
11. **Human decision.** Record accept/investigate/reject, with reason, author, and time.

Static findings and LLM triage are optional stretch context. They may be added later, but they
are not steps in the core path and are not inputs to steps 8 or 9.

## D. Current implementation status and limits

| Item | Status | Required for demo? | Notes |
|---|---|---|---|
| Local detonation API | Stage 0 path verified with Tetragon | Yes | `/api/v1/assess` accepts a local `archive_path`; Tetragon v1.7.1 captured raw events |
| Direct local-artifact staging | Verified end-to-end locally | Yes | CLI stages the tarball and sends an absolute staged path; no registry fetch |
| npm entry-phase attribution | Verified in local assessment path | Yes | Entry runs separately on the installed tree; install has no entry events |
| Decoy credentials | Verified locally | Yes | Decoy `~/.ssh/id_rsa` read observed; decoy-set hash recorded |
| Sandbox hardening and preflight | Verified on demo host | Yes | Rootless Docker; cap drop, no-new-privileges, PID/workspace limits, read-only rootfs, isolated internal bridge |
| Sinkhole and fake DNS | Implemented and verified locally | Yes | Internal bridge + trusted sinkhole; answers every A query with the sinkhole IP; captures ports 80/443/8080/8443 |
| Claim extraction | Implemented deterministic | Yes | README/metadata claims with source/span; missing README means claims unavailable |
| Behavioral assessment | Implemented | Yes | Assessment store and five observation outcomes |
| Report and CLI | Implemented | Yes | `assess`, `report`, `decide`; append-only decisions |
| Capture policy | Tetragon policy verified | Yes | Tetragon v1.7.1 on kernel 7.2.6; file/process events matched by container id |
| Raw trace retention | Verified for Tetragon path | Yes | Raw Tetragon events persisted with `raw_event_id`; every observation resolved |
| Event-loss measurement | Network path only | No | Cross-stream check compares Tetragon `network.connect` with sinkhole accepts; file/process loss remains unmeasured, so coverage stays `unverified` |
| Environment reads | Partial | No | Only another process's `/proc/<pid>/environ` is observed; mark `env.read` unavailable unless a shim is added |
| DNS host attribution | Implemented for sinkhole traffic | Yes | Fake resolver logs hostname; Tetragon connect to the sinkhole IP is enriched with the preceding DNS query in the same phase |
| Egress | Implemented for common TCP ports | Yes | `--internal` bridge; no upstream DNS; TCP sinkhole ports 80/443/8080/8443; arbitrary ports are not captured |
| Static findings / LLM context | Stretch | No | Existing analyzers persist under a scan row and LLM needs an API key; not on the core path |

## E. Capability vocabulary and capture coverage

The vocabulary is closed. A term is only usable in a claim or an observation if the collector can
produce it.

| Term | Collector source | Sensitive? | Availability |
|---|---|---|---|
| `process.spawn` | Tetragon `process_exec` | Conditional | Generic spawn is not sensitive; toolchain/installer baseline is context |
| `process.spawn.shell` | `process_exec` binary/args | Yes | Shell spawn outside the toolchain baseline is sensitive |
| `process.spawn.downloader` | `process_exec` binary/args | Yes | `curl`, `wget`, and similar downloaders are sensitive |
| `process.inject` | `sys_ptrace`, `__x64_sys_process_vm_writev` | Yes | Available within policy |
| `process.fileless_exec` | `__x64_sys_memfd_create`, `__x64_sys_execveat` | Yes | Available within policy |
| `network.connect` | Tetragon `tcp_connect` | Conditional | TCP only; an unlisted host is sensitive. UDP and DNS queries are not traced |
| `network.udp` | UDP socket activity | No | Unavailable unless a resolver/sinkhole log records it |
| `dns.query` | Fake resolver query log | Conditional | Available only if the resolver logs queries; not currently traced by Tetragon |
| `dns.hostname` | Fake-DNS IP-to-hostname map | Conditional | Mandatory for hostname claims; without it, only IPs are available |
| `file.read.sensitive` | `__x64_sys_openat`, policy-listed paths | Yes | Partial: listed credential paths only |
| `file.write` | `security_file_permission`, policy-listed persistence paths | Yes | Partial: persistence paths only |
| `env.read` | `__x64_sys_openat` on `/proc/<pid>/environ` | Yes | Partial/unavailable: another process's environ only; own-process reads require a shim |
| `credential.honeytoken` | `dyn_honeytoken_exfil` value match | Yes | Available when decoys are planted |
| `files.touched` | General file activity | No | Unavailable; do not claim it |

No registry or package-manager traffic should exist inside the sandbox. Dependencies are
pre-vendored outside the sandbox with scripts off, or the demo uses zero-dependency packages.
Registry traffic is a coverage failure, not baseline noise.

### Network event sources

- **Attempted TCP connection**: Tetragon `tcp_connect`.
- **Sinkhole accepted/refused**: sinkhole log; the package's connect may succeed at the TCP layer
  even when no real destination is reached.
- **DNS query**: fake-resolver log, only if the resolver is configured to log queries.
- **UDP**: unavailable unless the resolver or sinkhole records it.
- **Application-level completion** (request sent and response received): not observed.

The report distinguishes attempted and sinkhole-accepted behavior; application-level completion is
not observed. Absence of application-level completion is not evidence of clean behavior.

### Capture vs classification

The Tetragon policy is fixed at the sandbox host. A reviewer can change classification
sensitivity and allowlists, but cannot change what was captured. The report must record the
captured path/event set (or the policy profile hash) in its coverage section. An absence outside
that set means "not observed", not "did not happen".

### Egress

Use a **recording sinkhole**, not an allowlist. The current implementation uses a per-assessment
`--internal` Docker bridge, a trusted sinkhole container, and `--dns <sinkhole-ip>`. The sinkhole
answers every A query with its own address and records the queried hostname; it does not forward
upstream. Because the answer is a shared sinkhole IP, host attribution comes from the preceding
DNS query in the same phase, not from a unique fake IP. TCP connects are recorded by Tetragon and
accepted by the sinkhole on ports 80, 443, 8080, and 8443; arbitrary destination ports are not
captured, and the report says so. A route failure can still occur before `tcp_connect`, so the
sinkhole path records attempts only on those ports; it is not evidence that no other egress
occurred.

Dependencies must not be fetched inside the sandbox. Pre-vendor `node_modules` outside the
sandbox with scripts off, or use zero-dependency demo packages. Otherwise the install silently
fails under the sinkhole and the entry phase crashes. The coverage consequence is explicit:
behavior that requires a successful external fetch is not exercised, and its absence is not
evidence of clean behavior.

## F. Isolation, phases, and failure behavior

### Mandatory isolation

The only mandatory hardening is the set the project invariants require:

- drop Linux capabilities;
- set `no-new-privileges`;
- enforce PID and disk limits;
- refuse to run if any mandatory control cannot be verified;
- never mount host credentials or scanner credentials into the sandbox.

A failed control check returns `isolation_unverified`; no **package-controlled** process starts.
Trusted staging, preflight, and sandbox-management processes may run before the refusal. Record a
`preflight_refusal` with the failed control, effective profile hash, profile source, and reason so
the refusal is auditable; the assessment has `package_result=insufficient`, `coverage=incomplete`,
and no package observations. The tool may still produce a static-only context result, but it must
not run the package in a weaker profile.

These controls are not in the current Docker argv. Rootless Docker on the demo host may not have
the CPU controller delegated, and PID/disk limits require the pids controller and a size-capped
tmpfs or quota. A preflight test must inspect the effective controls on the demo host before the
first run and whenever the host/profile changes, record the actual profile, and be included in
Milestone 2. If a control cannot be verified, refuse the run; "refuse if unverified" may mean the
demo cannot run until the host profile is fixed.

### Decoy credentials

Before the package runs, plant decoy credentials so a payload that checks for them does not bail:
`~/.ssh/id_*`, `~/.aws`, `~/.npmrc`, `~/.pypirc`, kube/docker config, and decoy secret environment
variables. Use the existing `internal/honeytokens` material; no real secret may be used. The
`dyn_honeytoken_exfil` rule matches a decoy value that surfaces in execution. Record the
decoy-set hash in coverage.

### npm install phase

This is a **controlled install**, not a faithful reproduction of every npm install behavior.
Record `install_mode=controlled` in the report.

Supported and intentionally executed:

- `npm install --ignore-scripts --offline <staged-tarball>` in `/sandbox/app` to create the
  installed package tree from pre-vendored dependencies;
- the package's own `preinstall`, `install`, and `postinstall` scripts from
  `/sandbox/app/node_modules/<name>/package.json`, in that order.

Intentionally omitted:

- dependency lifecycle scripts;
- `prepare`, `prepublish`, `prepublishOnly`, `preprepare`, `postprepare`, and other npm
  lifecycle hooks not listed above;
- npm audit/fund behavior and package-manager side effects outside the controlled install.

Omitted hooks are excluded intentionally to keep execution deterministic and avoid
package-manager behavior unrelated to the package's own install/import assessment.

The manual lifecycle runner reads the installed package's `package.json`, executes
`preinstall`, then `install`, then `postinstall` with the working directory at the installed
package root and the controlled sandbox environment (including decoy variables). It records each
script's start, completion or failure, exit status, and `phase=install`. A failed lifecycle script
is a script failure, not a package-manager installation failure; the report must distinguish them.
Record the environment hash alongside the script results. A failed required lifecycle script marks
the install phase `failed` and coverage `incomplete`; observations captured before the failure are
retained, and the run cannot produce `no mismatch found`.

Dependencies are pre-vendored outside the sandbox with scripts off, or the demo uses
zero-dependency packages. No registry traffic occurs inside the sandbox. The report must state
that install behavior is partial by construction; it must not imply complete npm install coverage.

### npm entry executable policy

The entry phase executes from the **installed package tree** produced by the controlled install,
not from the raw extracted archive. Record `entry_root=/sandbox/app/node_modules/<name>` and the
dependency-layout hash; dependencies resolve from `/sandbox/app/node_modules`.

The entry phase runs files, not package imports. `exports` does not define an executable entry
point:

1. If `main` exists, resolve and run `main`. If the declared file is missing or invalid, fail the
   phase; do not fall back to `index.js`.
2. If no `main` exists, use `index.js` only if it exists; record `entry_method=index_default`.
3. If neither exists, record `entry_method=none`; declared `bin` entries may still run.
4. For every declared `bin` entry, resolve its path and run `node <file>`. A missing or invalid
   bin path fails the phase.

Record the entry method, resolved path, and each bin path. Do not describe the entry phase as
package `exports` resolution.

### npm import resolution policy

The import phase uses Node's package-resolution behavior from the installed layout for the target
Node.js version (Node 22 in the current profile). Resolve from the project root
`import_root=/sandbox/app` and record that path.

1. If `exports` exists, resolve through the phase's conditional exports:
   - require phase: `["node", "require", "default"]`;
   - import phase: `["node", "import", "default"]`.
   Record the matched condition and target. If the target is missing or invalid, fail with
   `import_resolution_failed`; do not silently fall back to `main` or `index.js`.
2. If no `exports` and `main` exists, resolve `main`; if missing or invalid, fail.
3. If neither `exports` nor `main` exists, use `index.js` only if it exists; record
   `import_method=index_default`. Otherwise fail.

Resolve CommonJS versus ESM from the target's `type` and file extension: use `require()` for
CommonJS and `import()` for ESM. Record the resolved path, resolution method, condition, and module
format.

### npm entry and import phases

1. **Entry phase.** Run the entry executable policy against the installed package tree as its own
   phase, then run every declared `bin` entry. Record `entry_root`.
2. **Import phase.** Resolve the installed package/module using the import resolution policy from
   `import_root` and execute that target. This is separate from the entry phase.

The current profile runs `main`/`bin` inside the install container and uses `require(name)` in a
fresh import container where the package may not resolve. That mislabels entry-time behavior as
install-time behavior and breaks PROJECT.md I5. The entry phase is a work item, not an existing
capability.

The entry is backgrounded for 15 seconds and the run has a 10-second settle window. Time-delayed
or environment-gated payloads outside that window are not observed; the report must say so.

### PyPI (later, not the first milestone)

If PyPI is added, define separate sdist and wheel phases, resolve top-level modules for import,
and account for `.pth` files that execute during interpreter start-up. Do not reuse npm phase
assumptions.

### Failure behavior and coverage levels

Coverage has three levels:

- **`complete`**: all required phases completed, tracing was active, and event loss was measured at
  zero across every captured class. This permits `no mismatch found` without a qualifier. It is not
  achievable today: the implementation measures loss only for the network path (Tetragon connects
  versus sinkhole accepts); file/process loss remains unmeasured.
- **`incomplete`**: a required phase failed or timed out, tracing was inactive, or event loss was
  detected. This blocks `no mismatch found`; observed review-worthy behavior may still support a
  review result.
- **`unverified`**: all required phases completed and tracing was active, but loss cannot be
  measured. This allows `no mismatch found` only with a mandatory **`coverage unverified`**
  qualifier.

A failed phase, timeout, or lost telemetry does not erase observations already made. If a payload
runs and then crashes the import phase, the observed sensitive behavior is still reported.

## G. Assessment model

Do not reuse `Scan.verdict`. Define a separate `Assessment`.

### Per-observation outcome

Every observation has one outcome:

| Outcome | Meaning |
|---|---|
| `explained` | A specific claim scopes the exact non-sensitive resource/destination; non-sensitivity alone is not enough |
| `declared-sensitive` | A claim explicitly names the sensitive resource or destination, but the observation is still sensitive; shown for reviewer confirmation |
| `unexplained` | A sensitive observation that is not named by a specific claim. Under the missing-claims policy, sensitive observations remain unexplained by policy when claims are unavailable. Non-sensitive observations never receive this outcome under the current classification rules |
| `insufficient` | A non-sensitive observation cannot be decided because claims or coverage are too weak |
| `unremarkable` | A non-sensitive observation with adequate claims/coverage but no claim that applies; retained as context and ignored by the package rule |

### Sensitive classes

Sensitive classes include credential-file reads, secret environment-variable reads, connections
to hosts not named by a specific claim, shell or downloader spawns outside the toolchain baseline,
persistence-path writes, process injection, fileless execution, and honeytoken exfiltration.

A claim that names `~/.ssh` or a host does **not** turn the observation into `explained`. It
becomes `declared-sensitive`: the behavior is shown, the reviewer must confirm it, and the package
result is `review: declared-sensitive`, never `no mismatch found`. This closes README laundering:
a README cannot announce its own exfiltration and pass.

### Classification precedence

For every sensitive observation, apply this precedence so it receives exactly one outcome:

1. A specific claim names the resource, destination, or capability -> `declared-sensitive`.
2. No specific claim names it, and claims exist -> `unexplained`.
3. Claims are unavailable -> apply the declared missing-claims policy: every sensitive class is
   `unexplained` by policy. This is a conservative policy, not proof that the missing README
   contradicts the behavior. The report states both facts: claims are unavailable and sensitive
   behavior was observed.

### Non-sensitive classification

For every non-sensitive observation, apply this precedence:

1. A specific claim scopes the exact resource or destination **and** the evidence for this
   observation is sufficient -> `explained`.
2. Claims are unavailable, or coverage is `incomplete` -> `insufficient`.
3. Claims and coverage are adequate, but no claim applies -> `unremarkable`; retain it as
   context, do not treat it as a mismatch candidate.

If claims exist but coverage is `incomplete`, classify the observation as `insufficient` unless rule
1 already explains it through a specific claim plus sufficient observation-level evidence. Do not
classify it as `unremarkable` when incomplete coverage prevents a reliable comparison.

`explained` is an observation-level result. A non-sensitive observation may be classified as
`explained` despite incomplete overall run coverage only when the specific claim scopes the exact
observed resource or destination and the evidence for that observation is sufficient. Otherwise,
classify it as `insufficient`. Overall incomplete coverage still prevents `no mismatch found`; run
coverage is applied at the package-level rule, not by rewriting an already-explained observation.

A sensitive observation never enters `explained` or `unremarkable`; it is either
`declared-sensitive` or `unexplained`.

### Package-level rule

Apply this rule in order:

1. If **any** observation is `unexplained`, the package result is **`review: mismatch`**,
   regardless of coverage.
2. Otherwise, if **any** observation is `declared-sensitive`, the package result is
   **`review: declared-sensitive`**, regardless of coverage.
3. Otherwise, if **any** observation is `insufficient`, or claims are missing, or coverage is
   `incomplete`, or `evidence_integrity.status=failed`, the package result is **`insufficient`**.
4. Otherwise, the package result is **`no mismatch found`**. If coverage is `unverified`, append
   the mandatory qualifier **`coverage unverified`**. Never use `safe`, `clean`, or `malicious`.

Evidence-integrity failure is a run-level precedence rule, not an observation outcome. When
`evidence_integrity.status=failed`, rules 1 and 2 can still produce a review result from an
already-captured sensitive observation, but the assessment can never reach rule 4. Missing raw
evidence is never evidence of clean behavior.

A sensitive observation may support a review result only when its existence and sensitive
classification are supported by retained evidence sufficient for review. If its required raw
evidence is unavailable, mark that observation as affected by evidence-integrity failure and
disclose the missing evidence. Do not imply that the missing raw record was retained or
independently verified. If no retained evidence supports the observation's existence and
classification, it cannot support a review result, and the package result is `insufficient`.

A `review: declared-sensitive` result requires explicit reviewer acknowledgement of the named
sensitive resource or destination; a generic accept is not sufficient. A `review:
declared-sensitive` assessment cannot be marked `accept` until every declared-sensitive observation
has an acknowledgement recorded against its observation id.

A human decision records reviewer disposition; it does not override or rewrite the automated
package result. `accept` is permitted for `insufficient` and `review: mismatch` as a reviewer
disposition, but it does not convert either result into `no mismatch found`; the report retains the
automated result and the decision separately.

This asymmetry is intentional:

- a failed phase, inactive tracing, or detected loss cannot produce `no mismatch found`;
- the same failure does not erase a sensitive observation already seen;
- missing documentation makes the comparison insufficient, but observed credential reads,
  unknown-host connections, or other sensitive observations are still reported and can still
  produce `review: mismatch`.

Missing README specifically: claims are unavailable, so the missing-claims policy classifies each
sensitive observation as `unexplained` by policy. The report must say "claims unavailable" and
"sensitive behavior observed"; it must not claim that the absent README proves a contradiction.
The package result is `review: mismatch` if such an observation exists; otherwise it is
`insufficient`.

An incomplete run can still produce `review: mismatch` or `review: declared-sensitive` when the
observations already captured justify it. If no existing observation justifies a review result,
incomplete coverage produces `insufficient`. The report distinguishes "insufficient because the
run was incomplete" from "review because a sensitive observation was captured before the failure."

### Optional static/LLM context (stretch)

Static findings and LLM triage are not on the core path. The existing analyzers run inside
`pipeline._run_analyzers` and persist under a scan row, and LLM triage requires an API key. Using
them here requires a direct, no-database invocation; otherwise they stay a stretch goal.

If added, they are labeled context only. They do not change an observation outcome, the package
rule, or the report's package result, and they never create `malicious` or `safe`.

### Report is part of the core

The report is part of the core flow. The demo cannot work without it. It must show:

- input identity (path/coordinate, package, version, artifact digest where available);
- extracted claims with source locations and ambiguity;
- observations with term, phase, sensitive flag, raw evidence reference, coverage, and outcome;
- captured-path/profile coverage, decoy-set hash, settle window, and telemetry level;
- evidence-integrity status and missing raw event ids when retention failed;
- package result, including the `coverage unverified` qualifier when applicable, and the rule
  that produced it;
- human decision, reason, author, time, `decision_id`, and `decision_revision`.

The `coverage unverified` qualifier must appear in the headline result, not only a footnote. The
report must not imply complete observation or safe behavior.

The human decision record is separate from the automated observations and assessment. It must
not be overwritten when the report is regenerated; a new decision is a new revision.

## H. Claims, normalization, attribution, and record shape

### Claim extraction

Use deterministic rules, or an LLM with cached output keyed by:

- README hash;
- extractor version;
- model;
- prompt hash;
- temperature 0.

Replays must use the cache. Take the README from the artifact; if the registry copy differs, note
the difference in the report.

A claim record contains: exact text, source path/span, extractor version, expected capability,
phase, confidence, ambiguity, and status. Claims are hypotheses; they are not policy overrides.

### Normalization

Before comparison and reporting:

- strip PIDs;
- strip ephemeral ports;
- strip temporary paths that vary per run;
- sort and dedupe events.

The normalized event must point to a raw event with a stable `raw_event_id`. Every observation
must reference exactly one `raw_event_id`; multiple normalized observations may reference the same
raw event. The reference remains mandatory even when the raw record is unavailable: retain the
event ID as an unresolved reference, leave `raw_ref` null, set observation-level
`evidence_integrity=failed`, and add the ID to the assessment's `missing_raw_event_ids[]`. Never
fabricate a raw record or mark an unresolved reference as resolved. Raw evidence and normalized
evidence are separate artifacts: retain the raw event payload and its filter reason separately from
the normalized representation. Target: raw trace records are retained; current API behavior returns
only filtered events and a raw-event count, with no filter reason. Therefore the current report
must be labeled filtered-only; the "raw evidence retained"
invariant is not met until raw traces and filter reasons are persisted. Do not describe filtered
event counts as raw evidence.

### Attribution

Installer noise such as npm reading `~/.npmrc` needs process attribution and a baseline run.
Dependency behavior during an in-process import cannot be separated from the package's own
behavior with the current collector; state that limit in the report instead of attributing it
incorrectly.

### Coverage levels

- `incomplete`: a required phase failed or timed out, tracing was inactive, or event loss was
  detected. This blocks a package result and cannot become `no mismatch found`.
- `unverified`: all required phases completed and tracing was active, but loss cannot be
  measured. This allows `no mismatch found` only with the mandatory `coverage unverified`
  qualifier.
- `complete`: all required phases completed, tracing was active, and loss was measured at zero.
  The current collector cannot measure loss, so `complete` is not claimable today.

Phase states: `not_requested`, `requested_not_started`, `started_completed`, `failed`,
`timed_out`, `completed_with_lost_or_incomplete_telemetry`.

### Record shape and storage

Store assessments in a dedicated assessment store as canonical JSON, not in the registry
scanner's `Scan` table.

**Assessment**

- `schema_version`, `assessment_id`, `input`, package name/version, artifact path/digest;
- `claims[]`;
- `observations[]`;
- `coverage`: level, per-phase status, captured profile/path hash, decoy-set hash, settle window,
  captured path/event list;
- `evidence_integrity`: `status` (`ok` or `failed`) and `missing_raw_event_ids[]`;
- `preflight_refusal`, present only when the run was refused: failed control, effective profile
  hash, profile source, and reason;
- `package_result` and `package_qualifier` (`coverage unverified` when applicable);
- `classification_rules_version`, `extractor_version`, `normalizer_version`,
  `vocabulary_version`, `sensitive_list_version`, `sandbox_profile_hash`, `decoy_set_hash`.

**Observation**

- `observation_id`, `term`, `phase`, `sensitive` boolean;
- normalized resource/destination/process fields;
- `raw_event_id` (mandatory stable reference) and `raw_ref` (nullable locator), optional
  `claim_ref`;
- `evidence_integrity` (`ok` or `failed`); a failed observation with an unavailable raw record
  also appears in the assessment's `missing_raw_event_ids[]`;
- `coverage_level`, `outcome`, `reason`, and `filter_reason` when the event was filtered.

**Decision**

- `decision_id` (stable identifier generated when appended) and `decision_revision` (monotonic
  per assessment, starting at 1);
- `decision` (`accept`, `investigate`, `reject`), `reason`, `author`, `timestamp`, the
  assessment hash it applies to, and `acknowledged_sensitive[]` for every declared-sensitive
  observation the reviewer confirmed.

Decision records are append-only. A new decision is a new record with its own assessment hash; it
never rewrites an earlier decision or turns an automated assessment into `no mismatch found`.
Report identity is `(assessment_hash, decision_revision)`; the latter is the highest decision
revision included in the rendered report.

If raw evidence persistence fails, the assessment is still saved with
`evidence_integrity.status=failed` and the `missing_raw_event_ids[]` list. Coverage becomes
`incomplete`, and the package result is `insufficient` unless an already-captured sensitive
observation that meets the §G review-evidence condition justifies `review: mismatch` or `review:
declared-sensitive`; those results remain review results but are marked as having failed evidence
integrity, including the affected observation and its missing raw event id. A failed
evidence-integrity assessment can never produce `no mismatch found` or claim evidence-backed
results whose raw records are unavailable. The report states the retention failure and lists the
affected observations; no failure is silently discarded.

Canonical JSON is the source of truth for the assessment: sorted keys, no timestamps, no
environment-specific values. Raw evidence retains timestamps, process details, and
environment-specific values; the canonical assessment uses stable identifiers and normalized
observations. The separate Decision record carries its own timestamp. HTML or Markdown is rendered
from the canonical assessment and the decision state.

Determinism is tested at two levels: the same canonical assessment must produce the same canonical
hash, and the same canonical assessment plus the same decision revision must produce the same
rendered-report hash. A newly appended decision may change the report without changing the
assessment. A changed extractor, normalizer, vocabulary, sensitive list, sandbox profile, decoy
set, or classification-rules version creates a new assessment rather than rewriting an old one.

### CLI surface

Three commands are enough:

- `assess <artifact-or-name@version>` - run the assessment and write canonical JSON;
- `report <assessment-id> [--decision-revision N]` - render the human-readable report for the
  assessment and a specific decision revision;
- `decide <assessment-id> --decision accept|investigate|reject --reason <text>
  [--acknowledge <observation-id>]...` - record the human decision separately. The
  `--acknowledge` flag may be repeated (or accept a comma-separated list), and
  `decide --decision accept` must reject with a non-zero exit if any declared-sensitive
  observation remains unacknowledged.

## I. Integrated workflow with Stage 0

```text
 Stage 0: local artifact or name@version
            |
            v
 [1] resolve + stage (direct; no queue/gates/eligibility/no-code-changes/Discord)
            |
            v
 [2] artifact path + identity/digest
            |
            +--> claims from artifact README/metadata
            |
            v
 [3] hardened sandbox: install -> entry -> import
            |
            v
 [4] capture -> normalize -> coverage (complete | unverified | incomplete)
            |
            v
 [5] per-observation outcomes
     explained | declared-sensitive | unexplained |
     insufficient | unremarkable
            |
            v
 [6] package assessment rule
     review: mismatch |
     review: declared-sensitive |
     insufficient |
     no mismatch found (+ coverage unverified)
            |
            v
 [7] report
            |
            v
 [8] human decision: accept / investigate / reject + reason
```

No static or LLM node appears on the main path. They are optional stretch context and cannot
change the result.

The local Stage 0 Tetragon path is verified end to end. The recording sinkhole and fake DNS
resolver are implemented and exercised; coverage remains `unverified` because file/process event
loss is not measured and arbitrary TCP ports are not captured.

No artifact table, alert outbox, CAS/version reconciliation, SARIF/API export, or precision/recall
program is part of this flow. The local artifact path and digest live in the assessment/report
record; cross-version comparison is a stretch goal.

## J. Demo and milestones

### Milestone 1 - comparator with a synthetic trace

Use a synthetic trace to validate the comparison rules without executing code. Cover:

- a documented capability that matches;
- an unexplained sensitive action;
- an unexplained shell/downloader spawn outside the toolchain baseline;
- a non-sensitive observation with no matching claim but adequate coverage → `unremarkable`,
  not a mismatch;
- missing documentation;
- incomplete telemetry;
- a completed run with `unverified` coverage that yields `no mismatch found` plus the
  `coverage unverified` qualifier;
- a README that names the credential file or host, producing `review: declared-sensitive`
  rather than `no mismatch found`;
- disagreeing static context that must not change the result;
- each expected package result.

### Milestone 2 - real inert package execution

Run a synthetic npm package for real in the sandbox, with inert payloads that actually execute.
Use a Stage 0 local artifact and call the detonation API with the staged path; no queue or
registry worker. This is required by PROJECT.md section 10: the demo must exercise real
install/entry/import behavior, not only a synthetic trace.

The payloads must be inert, but the execution must be real. Demonstrate:

- a package whose README describes a formatting utility;
- an entry-time observation tagged `entry`, not `install`;
- an observed read of `~/.ssh/id_rsa` or an unknown-host connection;
- `review: mismatch` with claim, observation, coverage, and report evidence;
- a missing-README run that still reports the sensitive observation;
- a run that fails after the payload but still reports the observed mismatch;
- a mandatory isolation control unverified: no package-controlled process starts, trusted
  preflight may run, and the refusal records the failed control and effective profile;
- a failed required lifecycle script: install phase failed, captured events retained, and no
  `no mismatch found` result;
- a no-registry-access check from inside the sandbox;
- a package that performs a sensitive action and then crashes still produces an assessment that
  contains that observation;
- a missing-raw-evidence case reported as an evidence-retention failure, not a complete
  assessment;
- raw trace retention: every observation has a `raw_event_id` and the report preserves the raw
  evidence, not only a filtered-event count (required for this milestone);
- a deterministic report for the same canonical assessment and the same decision revision; the test
  fixes `(assessment_hash, decision_revision)`, not merely the input and capture, so a new decision
  cannot make a valid report hash mismatch;
- a recorded human decision with reason and author, separate from the automated assessment.

**Acceptance assertions.** Milestone 2 fails if any of these is false:

- **Isolation refusal:** with a mandatory control unverified, zero package-controlled processes
  start; the API returns a refusal and records the failed control and effective profile.
- **Stage 0:** the API receives the staged artifact path and makes no registry request; assert
  this from network capture or registry-request logs, not from the report text alone.
- **Evidence retention:** in a successful run, every reported observation resolves to its retained
  raw event by `raw_event_id`; a missing record fails the assertion.
- **Failure handling:** after a sensitive observation, a subsequent phase failure leaves that
  observation in the canonical assessment and report.
- **Decision flow:** `decide --decision accept` with one unacknowledged declared-sensitive
  observation exits non-zero and writes no decision revision.
- **Determinism:** rendering twice for the same `assessment_hash` and `decision_revision` produces
  identical report hashes; a new decision revision may legitimately change the report.

**Evidence-integrity distinction.** Milestone 2 must test both cases:

- The raw trace is missing, but independently retained evidence (for example a sinkhole/DNS log or
  lifecycle output) sufficiently establishes the sensitive observation: a review result may remain,
  explicitly marked `evidence_integrity=failed`, with the missing `raw_event_id` disclosed.
- The raw trace is missing and no retained evidence sufficiently establishes the observation: it
  cannot support a review result, and the package result is `insufficient` unless another
  adequately evidenced observation independently justifies review.

Milestone 2 passes only when a local archive goes through the API, observations are captured,
the report is generated, a decision can be recorded, and every acceptance assertion above
passes. The local Tetragon path has passed assertions 1–14, including live evidence-retention fault
injection in both directions and the sinkhole/fake-DNS path. Coverage still carries the mandatory
`coverage unverified` qualifier: file/process event loss is not measured and the sinkhole captures
only the documented common TCP ports. This is a scoped PASS with those limits stated, not a claim
of complete egress coverage.

### Implementation order

1. Verify isolation and Stage 0: local archive reaches the API without registry re-fetch; prove
   capability drops, `no-new-privileges`, PID/disk limits, and refusal behavior.
2. Verify observation and evidence: establish collector coverage, persist raw evidence and filter
   reasons, and make coverage levels honest.
3. Implement claims and assessment: deterministic extraction, per-observation outcomes, the package
   rule, and missing-doc/sensitive/incomplete-coverage tests.
4. Complete the report and decision flow: canonical JSON, human-readable report, append-only
   decisions.
5. Pass Milestone 2: run the inert synthetic package through install, entry, and import; retain a
   sensitive observation even after a later failure; verify deterministic assessment output.

### Stretch only

Cross-version comparison, a second ecosystem, richer environment capture, and additional
observers are stretch goals. They must not delay the core report or the real inert-package demo.
