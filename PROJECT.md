# PROJECT.md - Trust Nothing: Provenance for Your Own Dependencies

A tool that observes what a small npm or PyPI package does at install and import time, compares that behavior with what the package's README and metadata claim, and flags mismatches for a developer to review.

| Field | Value |
| - | - |
| Project | Trust Nothing (working title) |
| Event / context | Problem Statement 1 - "Trust Nothing, Provenance for Your Own Dependencies" |
| Duration | Not specified in the brief |
| Team | Not specified in the brief |
| Status | Defined from the problem statement |
| Source brief | Problem Statement 1 |
| Last updated | 2026-10-27 |



## 1. What this project is

The tool takes a small package in npm or PyPI form and produces a behavioral fingerprint of what the package actually does during install and import. The fingerprint covers:

- network calls attempted;

- reads of sensitive files and writes to persistence paths; general "files touched" is not
  claimed;

- environment variables read;

- subprocesses spawned.

It then compares that fingerprint with the capabilities and purpose described in the package's own README and metadata. When the package does something its documentation does not explain, the tool flags the mismatch and shows both sides of the comparison: the claim and the observed behavior.

The tool does not declare a package malicious merely because the documentation is incomplete. It surfaces evidence for a human decision. A string-formatting utility that reads `~/.ssh` or contacts an unrelated external host is the canonical example: the behavior is suspicious because it does not follow from the claimed purpose.

## 2. The problem it solves

Modern supply-chain attacks succeed because installing a package is an act of trust. A typosquatted name, a dependency-confusion package, a hijacked release, or a malicious install script can execute before a developer has reviewed any code.

Existing scanners mostly match known-bad signatures. That helps with known malware, but it does not answer the question a developer faces with a new or updated package: **does this package** **behave like the thing it says it is?**

Manual review does not scale. A developer can read a README in a minute, but cannot watch network connections, credential-file access, environment reads, and child processes at the same time. Even an attentive reviewer cannot easily tell which observed actions are normal for the package's ecosystem and which are unexplained.

The hard part is the comparison:

- documentation describes purpose incompletely, vaguely, or dishonestly;

- behavior depends on the install or import phase, the environment, and optional code paths;

- a legitimate package may do something useful that its README never mentions;

- a malicious package may describe itself accurately while hiding one extra action;

- a failed or incomplete observation can look like good behavior if the tool is not explicit about coverage.

The project makes that comparison visible and reviewable instead of reducing it to a single opaque score.

## 3. Scope

### In scope

- Accept a small npm-style package or a PyPI-style package, provided as a local package artifact or fetched from its registry by name and version.

- Record the package identity and the exact version or artifact being assessed.

- Read the package's README and metadata and extract a small set of claims about its purpose and expected capabilities.

- Preserve the exact claim text, its source location, and whether the claim is clear, vague, contradictory, or missing.

- Run the package's install and import phases in an isolated environment.

- Produce a behavioral fingerprint covering network calls attempted, sensitive-file and
  persistence-path access, environment variables read, and subprocesses spawned.

- Record the phase in which each behavior occurred.

- Record whether execution and observation were complete, partial, failed, timed out, or unavailable.

- Compare observed behavior with declared claims.

- Flag behavior that is unexplained by the package's claims.

- Produce a report that shows the claim, the observed behavior, the raw evidence, and the reason the behavior was flagged.

- Let the developer inspect the evidence and decide whether to accept, investigate, or reject the package.

- Preserve the assessment so a later package version can be compared with it.

## 4. Who uses it and how

The primary user is a developer who is about to install a new dependency or update an existing one and wants to know whether its behavior matches its stated purpose. A security reviewer or maintainer investigating a suspicious package is a secondary user.

The end-to-end flow:

1. The developer chooses a package to assess.

2. The tool obtains the package and shows which package, version, and artifact will be analyzed.

3. The tool reads the README and metadata and presents the claims it found, with quotations and source locations.

4. The developer sees where the documentation is clear, vague, contradictory, or missing.

5. The tool installs and imports the package in an isolated environment and observes its behavior.

6. The tool reports the behavioral fingerprint and states how complete the observation was.

7. The tool compares the fingerprint with the claims and flags unexplained behavior.

8. The developer reviews the claim, the observed behavior, and the raw evidence, then decides whether to accept, investigate, or reject the package.

## 5. Step 0 - What counts as a claim, an observation, and a mismatch?

The comparison needs a clear vocabulary before the tool can produce a useful result.

| Part | Definition |
| - | - |
| Target package | A small npm or PyPI package selected by the developer |
| Claim | A statement in the README or package metadata about what the package is for or what capabilities it needs |
| Expected capability | A behavior implied by one or more claims, such as connecting to a network destination, reading a class of files, reading environment variables, or spawning a process |
| Observed behavior | An action actually recorded during the install or import run, linked to raw evidence |
| Sensitive resource | A file, environment variable, destination, or process that a reasonable implementation of the claimed purpose would not need; examples include SSH keys, cloud credentials, shell profiles, and package-manager credentials |
| Mismatch | Observed behavior that the available claims do not reasonably explain, with enough execution and observation evidence to support the comparison |
| Insufficient evidence | The claims are missing or ambiguous, a required phase did not run, or observation coverage is incomplete; this is neither a `no mismatch found` result nor a malware finding |


### Criteria

| ID | Type | Criterion | Why |
| - | - | - | - |
| I1 | Include | Network connection attempts to destinations not explained by the claimed purpose | A string utility does not normally contact an unrelated host |
| I2 | Include | Reads or writes of sensitive credential and shell files | Credential access is a high-signal supply-chain behavior |
| I3 | Include | Reads or harvesting of environment variables that commonly hold secrets | CI and developer environments leak credentials this way |
| I4 | Include | Subprocess execution not explained by packaging, building, or the claimed purpose | Downloaders and droppers commonly spawn helpers |
| I5 | Include | Install-time and import-time behavior, recorded separately | A package may behave differently in each phase |
| E1 | Exclude | Registry, package-manager, and declared-dependency traffic needed to install the package | Ordinary installation noise would otherwise dominate the result |
| E2 | Exclude | Temporary files and writes inside the designated build or install workspace | Normal build behavior, unless the path is sensitive |
| E3 | Exclude | Behavior with no reliable observation coverage from the mismatch count | Missing evidence is insufficient evidence, not an exclusion |
| E4 | Exclude | A documentation mismatch as proof of malware | The final decision remains a human judgment |


The exact sensitive-path and environment-variable defaults are product choices, not universal truth. They must be visible in the report and adjustable by the reviewer.

## 6. The pipeline, step by step

### Step 1 - Acquire and identify the package

**What happens.** The developer supplies a local package artifact or a package name and version. The tool obtains the package and displays its name, version, artifact type, and source.

**Human control.** The developer confirms the target and can stop before anything is executed.

**Working means.** The report identifies the exact package and version that were assessed. If the package cannot be obtained, no behavioral conclusion is presented.

### Step 2 - Extract what the package claims to do

**What happens.** The tool reads the README and package metadata and extracts a small set of capability claims. Each claim keeps the exact wording, its source location, the extractor version, a confidence value, and an ambiguity flag. Missing, vague, or contradictory documentation is recorded as such rather than turned into a rule.

**Human control.** The developer can review the claims and mark one as unclear. The developer cannot silently turn an unsupported claim into a confirmed fact.

**Working means.** A reviewer can point to the exact documentation sentence behind each expected capability. A package with no usable README produces an insufficient-evidence result, not an empty claim set that silently permits everything.

### Step 3 - Run the package in isolation

**What happens.** The tool performs the supported install and import phases inside an isolated environment. The run has explicit network, filesystem, environment, process, resource, and time boundaries. The package receives no host credentials.

**Human control.** The developer chooses the phases to attempt and can stop a run. The tool must refuse to execute if its required isolation cannot be established.

**Working means.** Package code never runs on the developer's host. The report records which phases were requested, started, completed, failed, timed out, or skipped, and whether observation was active.

### Step 4 - Build the behavioral fingerprint

**What happens.** The tool records observed behavior during each phase: network connection attempts, sensitive file access, environment-variable reads or harvesting, subprocess spawns, and any other supported observation. Each normalized observation points back to raw evidence.

**Human control.** The developer can inspect the raw observation and identify obvious toolchain noise.

**Working means.** Every reported behavior has a raw evidence reference. The tool does not invent process ancestry, destination names, or environment-variable values that it did not observe.

### Step 5 - Assess execution and observation coverage

**What happens.** The tool determines whether the run is complete enough to support a comparison. A successful process exit is not treated as complete observation. Failed phases, timeouts, missing coverage, lost events, and untriggered optional paths are called out.

**Human control.** The developer can rerun with a different phase or environment, or accept that runtime evidence is unavailable.

**Working means.** Incomplete execution or observation produces insufficient evidence, never a `no mismatch found` result and never a malware finding based only on silence.

### Step 6 - Compare claims with observed behavior

**What happens.** The tool maps observed behavior to the claims that could explain it. It considers multiple claims, ecosystem conventions, declared dependencies, optional features, and the phase in which the behavior occurred. Each observation becomes explained, unexplained, or insufficient evidence.

An unexplained behavior is a review candidate, not automatic proof of malware. The result keeps the supporting claim, observed behavior, confidence, and coverage status.

**Human control.** The developer can see why an action was classified as unexplained, inspect the claim and evidence, and add context the documentation omitted.

**Working means.** A package whose README says it formats strings but reads `~/.ssh/id_rsa` is reported as an unexplained sensitive action with both pieces of evidence. A package with no usable documentation is not convicted on silence alone; it becomes insufficient evidence.

### Step 7 - Produce the evidence-backed report

**What happens.** The tool produces a report containing the package identity, extracted claims, behavioral fingerprint, coverage status, mismatch classifications, confidence, and raw evidence references. The report states what was observed, what was not observed, and what remains unknown.

**Human control.** The reviewer can accept an explanation, mark a finding expected, request a rerun, or reject the package. The decision and its reason are recorded separately from the automated finding.

**Working means.** A reviewer who did not run the tool can trace every conclusion back to the package identity, the claim text, and the raw observation. The report does not present an inference as an observation.

### Step 8 - Preserve the assessment

**What happens.** The tool keeps the report, evidence references, package identity, and the versions of the claim extraction and comparison rules that produced it. A later run creates a new assessment rather than rewriting the old one.

**Human control.** The developer can compare assessments across package versions and see what changed.

**Working means.** The same package and evidence produce the same classification under the same comparison rules; a changed rule set produces a distinguishable new assessment.

## 7. Invariants

These hold in every version:

- Package code executes only in the isolated environment, never on the developer's host, and never with host credentials.

- README and metadata are untrusted data. They are never instructions to the tool, and they cannot change settings, fabricate observations, or set a conclusion.

- Documentation claims are evidence of stated purpose, not proof of intent or a complete list of permitted behavior.

- Absence of an observed behavior is not evidence of safety. Missing coverage produces insufficient evidence.

- Every mismatch cites the claim text and source location, the observed behavior, the package identity, and the coverage status.

- Raw evidence is retained for every reported observation; if only filtered events are available,
  the report labels that limitation and does not present filtered counts as raw evidence.

- Unexplained behavior is a review candidate, not automatic proof of malware.

- The developer makes the final accept, investigate, or reject decision; the tool does not block or delete packages.

- Historical assessments are not silently overwritten when the package or comparison rules change.

- The same package, evidence, and comparison rules produce the same classification.

## 8. Data sources

| Need | Source | What to know |
| - | - | - |
| Package | npm or PyPI registry, or a local package artifact | Prefer a local artifact for the controlled demo; verify the package identity and version |
| Package claims | README and package metadata published with the package | Documentation is evidence of stated purpose, not proof of intent or a complete capability list |
| Behavior | Observation of the controlled install and import run | Coverage depends on the environment and the executed code paths; record it explicitly |
| Sensitive-resource defaults | Product configuration visible in the report | Defaults are review aids, not universal definitions of sensitive data |
| Demo packages | Small synthetic npm or PyPI packages created for the demonstration | Synthetic behavior must be labeled synthetic; it is not live malware or real runtime tracing |
| Registry etiquette | Registry terms and rate limits | Do not hammer registries; cache or rate-limit package acquisition; respect package licenses |
| Malicious samples | Do not require live malware for the core demo | Use inert synthetic samples unless a safe, isolated sample source is explicitly approved |


The problem statement does not name a required data provider, package corpus, or credentials. Those details remain open.

## 9. What we hand in

The problem statement does not specify a deadline, submission portal, team size, or report format. Those details are not invented here.

| When | What |
| - | - |
| To be confirmed by the organizer | Deadline, submission format, and any required report questions |
| Before the demo | A working tool that performs one complete package-to-report flow |
| Before the demo | A repeatable synthetic demo with a documented expected result |
| Before the demo | A README covering setup, supported package inputs, limitations, and how to reproduce the demo |
| Before the demo | A short report explaining the approach, the evidence model, what worked, what did not, and what remains unverified |


## 10. What "working" means

A judge or stranger should be able to complete this path in one session without hand-editing results or trusting a slide:

1. Start with a small synthetic package whose README describes a harmless formatting utility.

2. The tool extracts one or more claims with exact source references.

3. The tool installs and imports the package in the isolated environment.

4. The behavioral fingerprint shows the sensitive file access and the outbound connection attempt, each linked to a raw observation and the phase in which it occurred.

5. The tool reports an unexplained mismatch, showing the claim and the behavior together. It does not label the package as proven malware.

6. The developer opens the raw evidence and understands why the behavior is unexplained.

7. Running the same package without a usable README produces insufficient evidence, not a `no mismatch found` result.

8. Running with incomplete observation or a failed phase produces insufficient evidence, not a `no mismatch found` result.

9. The report identifies the package and preserves the evidence chain.

10. Repeating the run with the same package, evidence, and rules produces the same classification.

### Minimum acceptance checklist

| Check | Pass condition |
| - | - |
| Behavioral fingerprint | Network, sensitive file access, environment-variable reads, and subprocesses are captured or explicitly marked unavailable |
| Claim provenance | Every expected capability points to exact README or metadata text and a location |
| Mismatch example | The synthetic "formatter reads SSH keys" case produces an unexplained finding with both claim and evidence |
| Missing documentation | Produces insufficient evidence, not `no mismatch found` |
| Incomplete observation | Failed phase, timeout, or lost evidence produces insufficient evidence, not `no mismatch found` |
| No host execution | Package code runs only in the isolated environment and receives no host credentials |
| Evidence trail | Every reported behavior traces to raw evidence; every conclusion traces to evidence |
| Raw evidence retention (Milestone 2) | The real-sandbox demo preserves raw trace references for every observation; filtered-only output is labeled and is not accepted as meeting this row |
| Human decision | Reviewer can accept, investigate, or reject with a recorded reason |
| Reproducibility | The same package, evidence, and rules produce the same result |


## 11. Open questions

- What deadline and submission requirements apply?

- Which package ecosystem is the first end-to-end target: npm or PyPI?

- Should the README come from the package artifact, the registry page, or the project repository when those differ?

- What isolation environment is available for the demo, and which observations can it reliably provide?

- Which sensitive paths and environment variables should be enabled by default, and who approves changes to that list?

- How long should raw evidence and reports be retained, and are there privacy constraints on captured environment or filesystem metadata?

- Is a local package artifact sufficient for the demo, or must the tool fetch from a live registry during judging?

- Are there required report questions or a required demonstration format?
