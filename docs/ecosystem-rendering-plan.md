# Ecosystem and Investigation Plan

Last updated: 2026-09-07

## Goal

Make eBPF Viz a trusted investigation tool that answers: **what owns this,
how does it connect, and what changed?** An operator should be able to open an
unfamiliar host capture and explain ownership, execution relationships, and
deployment changes using visible evidence.

This plan integrates the project regrouping with the original six ecosystem
tracks. Track numbers are retained for continuity. The previous 1.3.0–1.5.0
assignments are replaced by milestones with acceptance criteria; choose release
versions when scope and validation are established.

## Baseline — complete

- Existing capabilities include namespace topology, live and offline views,
  snapshot/map-entry diffs, packet-chain analysis, and large-program inspection.
- Dependency updates and release gates merged in
  [PR #31](https://github.com/mykola-lysenko/ebpf-viz/pull/31), commit `2d14a3f`.
  Dependency auditing runs separately from code validation. Releases require
  all checks and publish the exact tarball tested on Node 16.20.2.
- Validation at that commit: no known dependency vulnerabilities, 507 passing
  tests, passing typecheck/lint/build, and successful GitHub CI and release runs.
- OS Map already uses worker layout, node memoization, viewport culling, and
  centralized level-of-detail handling. CFG rendering has worker and fallback
  support. Further performance work starts with measurements.

## Milestone A — trustworthy collection and diffs

**A.1 implementation complete locally:** Per-source status and last-good data,
namespace coverage/deferrals, stale-counter handling, capture/import/export
metadata, live UI, and diff coverage warnings are implemented. Regression and
Chromium workflow checks pass. See [collection semantics](collection-status.md).
**A.2 implementation complete locally:** Inventory and map contents share
conservative object matching, ambiguous clones are visible, and actual
relationship/pin sets are compared. Dump errors, acquisition completeness,
truncation, and decoded BTF values survive comparison. Regression tests and
Chromium capture workflows pass; see [comparison semantics](snapshot-diff.md).
**A.3 audit and fixes complete locally:** Four UML packet tests verify ordered
TCX ingress/egress and conditional legacy TC execution. Native bpftool TCX
attachment loss/reordering was not reproduced. Reproduced mechanism labeling,
alternate-input chain coverage, namespace scoping, and unsupported ordering
claims are fixed. Revision is unavailable in ordinary bpftool JSON; TCX
continuation prediction remains explicitly unmodeled. See the
[recorded audit and fixtures](tcx-audit.md).
Milestone A is complete locally; publication/CI of these local changes remains
separate from the implementation status.

**Acceptance delivered:** Collection failures carry explicit coverage and
freshness; same-count relationship and pin changes are detected; ambiguous or
incomplete comparisons are visible; the TCX audit has reproducible fixtures and
a recorded verdict. Regression tests and browser workflows cover these cases.

## Milestone B — one complete ecosystem workflow

Deliver one investigation from a real libxdp capture through ownership, ordered
components, and continuation explanations in both live and offline views.
The following subtasks replace the broad Track 1/0/2 descriptions. Each can be
reviewed independently; B.1 establishes the evidence needed for later work.

### B.1 — reproduce and capture a libxdp dispatcher

- Verify the available kernel, xdp-tools/libxdp, bpftool, and permissions. Use an
  isolated lab with explicit cleanup, following the A.3 audit approach.
- Load two or three distinguishable components with `xdp-loader`. Exercise
  priority/order changes, a continuation-policy change, and a component reload.
- Save raw programs, links, maps, pins, and relevant BTF/configuration evidence,
  plus tool versions and the loader's independent view of the chain. Record
  measured packet execution separately if the lab can observe it.
- Include a plain XDP negative case and a capture with missing dispatcher
  evidence. Document which facts ordinary snapshot collection can recover and
  which require additional collection.

**Done when:** A repeatable lab runner, checked-in fixtures, and an evidence
matrix establish where identity, component membership, order, priority, and
continuation policy come from. Unsupported or absent fields are explicit.
No detector implementation depends on guessed names or kernel ID ordering.

### B.2 — recover dispatcher relationships and preserve evidence

**Depends on B.1.** Verify the observed layout against the corresponding primary
libxdp sources. Implement fixture-driven detection and a shared model for the
dispatcher, component program references, slots/order, priorities, and configured
continuation actions. Keep evidence source and availability with each recovered
fact; conflicting or unsupported layouts remain unresolved.

Add only the collection needed by the fixture evidence, with explicit cost
limits and A.1 status semantics. Preserve the resulting metadata through SSE,
capture, export, and import, while accepting older inventory-only captures.
A general bytecode/map investigation bundle remains Milestone C work.

**Done when:** Real, reordered, reloaded, plain-XDP, and incomplete fixtures
recover only supported relationships; live and offline data retain the same
facts and uncertainties. Kernel IDs alone never establish component order.

### B.3 — attribute ownership using a small declarative registry

**Depends on B.1; uses B.2 relationships when available.** Begin with xdp-tools /
libxdp management evidence. Distinguish the dispatcher manager from the owner of
a component; a libxdp attachment does not establish who authored or deployed
that component. Add other owners only when actual captures justify their rules.

Define a versioned registry with a documented local override/loading mechanism
that works without rebuilding. Evaluate names, pin paths, process evidence, and
attachment shapes with explicit match reasons and confidence. Handle conflicting
matches and unknown ownership, and preserve the evidence required to reproduce
attribution offline. Add focused negative fixtures for generic names and paths.

**Done when:** Attribution has inspectable reasons, deterministic conflict
handling, validated user entries, and fixtures demonstrating both matches and
false-positive avoidance. A broad product catalog is not required.

### B.4 — present the chain as an investigation workflow

**Depends on B.2 and B.3.** Render the dispatcher and ordered components in the
existing Network/Kernel views, with program drill-down, ownership badges, and
owner filtering. Show priority, configured continuation, and unavailable fields
where the evidence supports them. Keep attachment mechanisms and namespace
scope explicit, reusing A.3's ordering evidence conventions.

Explain what configured continuation permits. Use existing bytecode analysis
only where its semantics are valid and the required code is available; distinguish
possible behavior from measured packet execution. Missing metadata and imported
captures must not inherit live-only claims or counters.

**Done when:** A real capture and matching demo answer who manages the chain,
which components run in what order, and which configured actions allow the next
component to run. Browser checks cover drill-down, filtering, uncertainty, and
capture/export/import parity.

### B.5 — validate compatibility and ship the workflow

**Depends on B.1–B.4.** Document tested kernel/tool/libxdp versions and the limits
of the detector. Add fixture coverage for any additional layout claimed as
supported; otherwise label it unverified. Exercise live collection and offline
import, component reload/order/policy changes, and partial collection through the
existing diff workflow. Record collection cost and keep unsupported comparisons
explicit rather than implying no change.

**Done when:** Fixtures, demo, documentation/screenshots, and browser workflows
agree; dependency audit, Node 22 checks, and the packaged Node 16 smoke test pass
in GitHub CI. Choose a release version from the completed scope.

### Track 2 follow-ups — separately scoped after A.3

A.3 already delivered mechanism labels, namespace-aware chains, evidence-based
ordering, and conditional legacy TC display. Ordinary bpftool JSON does not
provide TCX revisions, and TCX continuation remains unmodeled. Further investment
requires separate evidence and acceptance criteria:

- Add an optional production query collector for TCX order/revision, accounting
  for permissions, unsupported kernels, and changes during collection.
- Model TCX continuation from the measured PASS/NEXT cases before enabling
  packet-chain prediction for TCX.
- Reproduce netkit ordering and continuation before extending those claims.

These follow-ups do not block B's libxdp workflow. Schedule them when a concrete
investigation needs them; do not repeat the completed A.3 parser fixes.

**Milestone acceptance:** B.1–B.5 deliver one complete libxdp investigation with
visible evidence and uncertainty. Broad ownership catalogs, tail-call families,
general capture bundles, and speculative performance work remain outside B.

## Milestone C — portable investigations, families, and scale

**Portable captures.** Package inventory, optional bytecode/CFG data, map dumps,
and collection metadata into one importable investigation bundle. Define
versioning and compatibility behavior, preserve existing snapshot imports, and
record which sections are missing, stale, truncated, or collected at different
times. Inventory-only captures cannot validate bytecode analysis.

**Track 3: tail-call families.** Recover candidate targets from program-array
maps and build relationships from attached roots to known members. Start with
on-demand collection using the existing map-dump plumbing and expensive-query
protections. Measure cost before considering background polling.

Group related programs in Programs and OS Map, with member drill-down and
clearly defined aggregate statistics. In packet-chain explanations, show known
possible targets while retaining uncertainty about dynamic indices, failed tail
calls, missing dumps, and actual execution. Naming supports ownership; it does
not prove an execution edge. Handle shared members and cycles explicitly.

**Representative corpus and browser workflows.** Grow a reproducible fixture
set spanning the lab patterns, different kernel/bpftool output shapes, partial
captures, and representative production systems. Exercise capture → import →
inspect → diff, including reload/deep-link behavior and large programs.

**Measure scale.** Benchmark import time, interaction latency, memory use,
layout/CFG rendering, and collection cost on small and large captures. Record
hardware, browser, versions, and repeatable procedures. Establish budgets from
those measurements and optimize demonstrated bottlenecks. Validate the existing
CFG thresholds against full large-program captures.

**Acceptance:** One bundle supports a useful offline investigation and diff;
known tail-call relationships are navigable without claiming observed packet
fate; representative browser workflows pass; performance baselines and budgets
are documented. Begin corpus collection and baseline measurement in A/B where
fixtures are already available.

## Further ecosystem tracks — demand-led

**Track 4: sched_ext and broader struct_ops.** Generalize the existing TCP
congestion-control grouping using BTF. Research scheduler callbacks and state,
then show scheduler identity, enabled state, members, and aggregate activity.
Verify the actual lab kernel configuration and required tooling before
scheduling reproduction. Consider other struct_ops users as captures justify.

**Track 5: kprobe_multi / uprobe_multi breadth.** Parse target counts and lists
where available, show searchable targets in the detail panel, and attribute
uprobes to binaries when evidence permits. Verify kernel/tool support and
capture real output before detection work. This can be a small standalone
increment if user demand or available fixtures make it valuable sooner.

Schedule these tracks according to real captures and operator demand; they do
not block the collection, libxdp, or portable-investigation milestones.

## Delivery method and open decisions

- Research each kernel/ecosystem convention against primary project sources,
  kernel documentation, and selftests. Record identifying fields and minimum
  versions. Treat bpftool output as evidence of what was collected, with its
  coverage and limitations made explicit.
- Verify the lab environment instead of assuming the old WSL 6.18/bpftool 7.8
  setup or kernel configuration is still available. Reproduce the pattern and
  save a fixture before implementing its detector.
- Every feature includes fixture-driven parsing, relevant browser validation,
  demo data, and documentation/screenshots. Use the established CI/release gates.
- Decide capture format, matching rules, and collection budgets through small
  prototypes and representative data. Record unresolved semantics explicitly.
- Review ownership fingerprints as products change. Keep heuristic matches
  visibly distinct from stronger evidence.

**Immediate next task:** B.1 — capture a real libxdp dispatcher with two or
three components and establish the evidence matrix before implementing recovery
or ownership rules.
