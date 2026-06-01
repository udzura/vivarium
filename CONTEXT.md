# Vivarium Glossary

This file defines canonical terms used in Vivarium discussions and code.
When a term here conflicts with a term used in conversation or in code,
**this file wins** unless we explicitly update it. Refine the glossary as
the design evolves; do not drift the vocabulary.

Sections §1–§2 describe roles and events. Sections §3–§4 describe
**the original ArrayMap-based transport** and are now **superseded by
§5**, which has been implemented (as of 2026-05-27). §6 lists what
remains open. §7 captures the implementation outcome and the few
v1 deviations from §5.

---

## 1. Roles (today)

- **vivariumd** — The privileged background daemon that loads the BPF
  program and pins shared maps under `bpf_pin_dir`. One per host.
- **Observer** — A Ruby process that calls `Vivarium.observe` (or
  `Vivarium.top_observe`).
- **Target** — A process whose syscalls/LSM hooks vivariumd is currently
  emitting events for. Union of:
  - **Root target** — PID explicitly registered via `register_pid`
    (pinned map `config_root_targets`).
  - **Spawned target** — TID inserted by the `sched_process_fork`
    tracepoint whenever a target forks (pinned map
    `config_spawned_targets`).

> "PID" in `config_root_targets` is the userland `Process.pid` (kernel
> tgid); "TID" in `config_spawned_targets` is the kernel-level task id.
> Keep this distinction visible.

---

## 2. Events (today)

- **Event (`event_t`)** — A fixed 288-byte struct emitted by the BPF
  program: `{ u64 ktime_ns; u32 pid; char event_name[16]; char payload[256]; }`.
- **Event name** — Short string identifying the hook source (`path_open`,
  `proc_exec`, `dns_req`, `task_kill`, ...). See [README.md](README.md).
- **Severity** — `high` or `medium`, derived from event name.
- **Drain** — Reading all currently-pending events out of the shared
  transport and clearing it. Today this is `MapStore#drain_events`.

---

## 3. Transport (historical — superseded by §5, removed 2026-05-27)

- **Pinned maps** under bpffs (`/sys/fs/bpf/vivarium/`).
- **`event_invoked`** — 1024-slot `BPF_ARRAY` of `event_t`. **Wraps
  silently on overflow.**
- **`event_write_pos`** — 1-slot `BPF_ARRAY` of `u32`, atomically
  incremented BPF-side; reset to 0 on observer-side drain.

---

## 4. Correlation (historical — superseded by §5, removed 2026-05-27)

- **TracePoint correlation** — On every Ruby `:return` / `:c_return`,
  the observer drains the buffer and attributes everything currently
  sitting in it to the just-returned method. Positional, not identity-
  based. Known to break when (a) a method returns before its events are
  drained, (b) another thread emits events into the same buffer, or
  (c) the buffer wraps.

---

## 5. v1 architecture (implemented 2026-05-27)

The following terms and components describe the **implemented**
ringbuf + USDT + Correlator architecture. See §7 for the file/symbol
map and v1 deviations.

### 5.1 Vocabulary

- **Span** — One activation of a Ruby method on one thread. Identified
  by `(tid, method_id, start_ktime_ns)`. Delimited by:
  - **`span_start`** — emitted via `Vivarium::Usdt` `start_probe`.
  - **`span_stop`** — emitted via `stop_probe`. Fired on **both** normal
    and exceptional returns (Ruby's `:return` / `:c_return` TracePoint
    fires even when a method raises), so every Span is closed by exactly
    one `span_stop`.
  - **`span_raise`** — emitted via `raise_probe` on Ruby `:raise`. This
    is an **event within a Span**, not a Span terminator: it sets a
    `raised` flag on the innermost open Span on that tid and is also
    rendered as an `EXCP` event line under that Span (§7.1).
  Spans may nest within a single tid.

- **method_id** — 64-bit hash of `"#{defined_class}##{method_name}"`,
  produced by `Vivarium::Usdt.register_or_resolve_method`.

- **System event** — Any non-Span event captured by vivariumd's BPF
  program (LSM hooks, tracepoints, uprobes other than Span probes).

- **Span event** — `span_start` / `span_stop` / `span_raise`, captured
  by vivariumd attaching to the USDT probe sites in the observer's
  process. From vivariumd's point of view this is also "just" a uprobe.

- **Correlator** — The component that joins System events to Spans
  using `tid` and `ktime_ns ∈ [span.start, span.stop|raise]`, and
  renders the result as a Process Tree (see §5.4).

- **Process Tree** — The rendered output. A textual tree whose primary
  axis is process lineage (parent → child via execve/fork). Spans and
  events hang off process nodes. See §5.4 for the exact format.

### 5.2 Transport

- **Ringbuf** — `BPF_RINGBUF_OUTPUT` from BPF to userland, pinned on
  bpffs. Replaces today's `event_invoked` ArrayMap.
- **Single ringbuf for v1** — Span events and System events flow into
  the **same** ringbuf so they share a consistent ordering by
  `ktime_ns` and can be reordered in one consumer loop.
- **Single consumer for v1** — Exactly one Observer per host is
  supported in v1. Ringbuf is single-consumer by nature; multi-observer
  is deferred (§6).
- **Pin path is parameterizable** — The ringbuf pin path is exposed
  through the same `bpf_pin_dir` mechanism, so a future control
  protocol can introduce per-observer ringbufs without changing the
  consumer API.
- **Event schema (`event_t` v2)** — Field-reordered version of today's
  `event_t` (§2) that adds a `tid` field without changing the
  288-byte total size:

  ```c
  struct event_t {
    u64  ktime_ns;        //  0..7
    u32  pid;             //  8..11   tgid
    u32  tid;             // 12..15   task id (NEW)
    char event_name[16];  // 16..31
    char payload[256];    // 32..287
  };
  ```

  The added `tid` is consumed by the Correlator's join algorithm
  (§5.9).

### 5.3 Correlator placement

- **Lives in the Observer process** as a dedicated Ruby Thread (the
  **Correlator Thread**), separate from the **Main Thread** that runs
  user Ruby code and fires Span USDTs.
- **Must be extractable to a separate process in the future.** This
  constrains the in-process design: the Main Thread and Correlator
  Thread communicate only through a narrow message interface (§5.5),
  never by sharing mutable state directly. Replacing the in-process
  Queue with a Unix-socket transport must be a localized change.

### 5.4 Process Tree output format (Format A)

The canonical, human-and-machine readable rendering.

```
[PROC pid=100 comm=ruby]
└─ [SPAN tid=100 Net::HTTP#request  dur=12.3ms]
   ├─ LSM  socket_connect  →  tcp/192.168.1.1:443         @+0.4ms
   ├─ TP   execve          →  /bin/sh ["-c","id"]         @+8.0ms
   │  └─ [PROC pid=101 comm=sh  parent=100]
   │     └─ USDT ssl_write →  "POST /bad-endpoint"        @+9.2ms
   └─ [SPAN tid=100 SubCall#go  dur=0.5ms]
      └─ LSM file_open     →  /tmp/x                      @+10.0ms
```

**Line kinds:**

| Kind  | Form                                                    |
|-------|---------------------------------------------------------|
| PROC  | `[PROC pid=N comm=STR (parent=N)?]`                     |
| SPAN  | `[SPAN tid=N FQNAME  dur=Xms]` (closed form)            |
| EVENT | `KIND name  →  target  @+Xms`                           |

**Attribute conventions (load-bearing — keep stable):**

- Every attribute is `key=value` with no quoting unless the value
  contains spaces; in that case use double quotes (`"..."`).
- Numeric durations are `Xms` or `Xus`. Timestamps in events use the
  prefix `@+` and are relative to the **enclosing Span's start**.
- Bracketed `[...]` denotes a **container** (PROC or SPAN). Unbracketed
  lines are **events** (leaves).
- Event KIND is one of: `LSM`, `TP`, `USDT`.
- The arrow `→` (U+2192) separates the event from its target.
- Box-drawing characters (`├ └ │ ─`) are decoration only; structure
  must remain reconstructible from indentation depth alone, so AI/grep
  parsers may ignore them.

**Process Tree edges:**

- A child PROC appears nested under the EVENT (`TP execve` or
  `TP clone`/`TP fork`) that spawned it. The line above a nested PROC
  is the causal event; the PROC's `parent=` attribute is redundant but
  load-bearing for machine parsers that read PROC lines in isolation.

### 5.5 Main Thread ↔ Correlator Thread interface

For v1, the Main Thread publishes only **one** piece of context that
USDT cannot carry inline:

1. **method_id table** — when a new `method_id` is registered via
   `Vivarium::Usdt.register_or_resolve_method`, the Main Thread sends
   `(method_id, "Class#method")` to the Correlator.

All other Span data (`tid`, `ktime_ns`, exit status) arrives through
the ringbuf. This minimizes coupling and matches what a future
out-of-process Correlator will receive over IPC.

The transport used today is a `Thread::Queue`. Tomorrow it can become
a Unix socket without changing message semantics.

### 5.6 Stack trace handling

**Multi-frame stack traces are dropped in v1.** The pre-v1
`caller_locations(...)`-per-drain mechanism
(see [lib/vivarium/logger.rb](lib/vivarium/logger.rb)) is intentionally
not used; method context is preserved through Span nesting in the
Process Tree.

**Per-Span `file:lineno` is implemented** via the originally proposed
option **(b)**: the USDT probes carry a `(file_id, lineno)` argument
pair (24-byte payload for `span_start`/`span_stop`, 32-byte for
`span_raise` which adds `error_id`/`message_id`). `file_id` is
hash-resolved by `Vivarium::Usdt.register_or_resolve_file`, parallel
to `method_id`. Renderings:

- Span headers include `at=basename.rb:N` when the file is known
  (`TreeRenderer#span_file_info`).
- `EXCP` event lines include `error=Class message="..." at=basename.rb:N`
  (`TreeRenderer#render_raise_target`).

Option (a) (Queue-based delivery of file/line) was not adopted.

### 5.7 Threading scope (v1)

**v1 is single-Thread, single-Ractor on the Observer side.** This is
a deliberate PoC narrowing — we aim for a working end-to-end pipeline
before tackling concurrency.

Concretely:

- The Observer process has exactly two Ruby Threads: the **Main
  Thread** (user code + TracePoint + USDT firing) and the
  **Correlator Thread** (ringbuf consumer + tree renderer). No user
  Ractors are supported.
- The Main Thread's kernel task id is obtained by calling
  `gettid(2)` via Fiddle once at Observer start. This value is the
  canonical `tid` for **every** Span emitted in v1.
- The Correlator Thread has a different kernel tid, but it does not
  emit Spans. It is, however, part of the same tgid as the Main
  Thread, so its syscalls will be picked up by vivariumd's BPF
  program. For v1 we accept the minor self-noise this causes
  (a handful of `file_open` events at startup). A future iteration
  may add a BPF-side exclusion map keyed by tid.
- Thread/Ractor support is explicitly deferred. See §6 for the
  shape of the unanswered questions when we revisit it.

### 5.8 Span boundary mechanism (v1)

The Main Thread fires Span USDTs from inside a `TracePoint` callback.

- **TracePoint events listened:** `:call`, `:return`, `:c_call`,
  `:c_return`, `:raise`. Both Ruby- and C-implemented methods are
  eligible, so allowlist entries are not constrained by implementation
  language.
- **Per-method allowlist (call/return only):** for the call/return
  events, the callback fires USDT probes only when the method matches
  either:
  - `SPAN_ALLOWLIST` — exact `"#{tp.defined_class}##{tp.method_id}"`
    string match, or
  - `SPAN_ALLOWCLASSES` — `tp.defined_class` is one of the listed
    classes (or its singleton class, covering class-method calls).

  This is **mandatory** for call/return — no match means no Span.
- **v1 allowlist contents** (see [lib/vivarium.rb](lib/vivarium.rb)
  `SPAN_ALLOWCLASSES` / `SPAN_ALLOWLIST`):
  - Classes: `Socket`, `BasicSocket`, `IPSocket`, `TCPSocket`,
    `UDPSocket`, `UNIXSocket`, `File`, `Dir`, `Signal`, `Process`,
    `Process::UID`, `Process::GID`.
  - Methods: `Kernel#system`, `Kernel#require`,
    `Kernel#require_relative`, `Kernel#load`, `Kernel#eval`,
    `Object#instance_eval`, `Object#instance_exec`.
- **Mapping events → probes:**
  - `:call` / `:c_call` → `Vivarium::Usdt.start(defined_class, method_id, file:, lineno:)`
  - `:return` / `:c_return` → `Vivarium::Usdt.stop(defined_class, method_id, file:, lineno:)`
  - `:raise` → `Vivarium::Usdt.raise(exception.class, exception.message, file:, lineno:)`
- **`:raise` is unfiltered.** Unlike call/return, the `:raise` branch
  does **not** consult the allowlist — every Ruby-level raise inside
  the Observer process fires `raise_probe`. The probe is documented as
  exception-safe at the `vivarium_usdt` layer, so a misbehaving
  raise handler will not re-enter the TracePoint. Noise from third-
  party libraries (e.g. internal `rescue`d exceptions) is accepted
  for v1; filtering, if needed, will be added later.
- **`:raise` does not close the Span.** Ruby's TracePoint fires both
  `:raise` and the subsequent `:return` / `:c_return` for the raising
  frame, so the span is still closed by `span_stop`; `span_raise` only
  flags the Span with `raised=true` (rendered as `(raise)` suffix) and
  appears as an `EXCP` event line within it.
- **Allowlist configuration mechanism:** hardcoded constants in v1.
  A configuration API (`Vivarium.observe(methods: [...])`) is out of
  scope for v1.

### 5.9 Correlator join algorithm (fork/exec handling)

**New BPF event.** vivariumd must emit a `proc_fork` ringbuf event
whenever `sched_process_fork` fires for a target. Today this
tracepoint only updates `config_spawned_targets`
(see [vivarium.rb:695-718](lib/vivarium.rb#L695)); v1 keeps that
behavior and additionally submits:

- `event_name = "proc_fork"`
- `pid`, `tid` — the **parent** tgid and tid (the thread that called
  fork — this is also a member of the Spanning thread for the v1
  `Kernel#system` case).
- `payload = { u32 child_pid; u32 child_tid; }` (8 bytes; rest zero).

**Join rule.** For each event `E` (consumed in `ktime_ns` order),
locate the innermost open Span `S` such that
`S.start_ktime_ns ≤ E.ktime_ns ≤ S.stop_ktime_ns` AND either:

- **(i)** `E.tid == S.tid` — event from the Spanning thread, OR
- **(ii)** `E.pid ∈ S.descendant_pids` — event from a fork descendant.

`S.descendant_pids` is the closure under `proc_fork` events rooted
at `S.tid`'s process: when a `proc_fork` `F` is matched into `S`
via rule (i) or (ii), `F.payload.child_pid` is added to
`S.descendant_pids`.

**Rendering.**

- Events matched by rule (i) are placed directly under the `[SPAN]`
  line.
- Events matched by rule (ii) are placed under the `[PROC pid=X ...]`
  node that was materialized beneath the `proc_fork` event line
  that birthed `X`.

**`comm` in `[PROC ...]` headers** is rendered as the **most recently
observed comm** for that pid. Initialize from the
`sched_process_fork` event's `child_comm`; update on each subsequent
`sys_enter_execve` under that PROC using the exec'd program's
basename. So `Kernel#system "sh -c 'id'"` renders as
`[PROC pid=101 comm=sh parent=100]`, even though the process started
life as a `ruby` clone.

### 5.10 Process Tree root and output strategy

**Single shared root.** The Process Tree has exactly one root per
Observer session: the Observer's own `[PROC pid=N comm=ruby]`. All
Spans accumulate beneath it as siblings, in the order they closed:

```
[PROC pid=100 comm=ruby]
├─ [SPAN tid=100 Kernel#system  dur=2.3ms]
│  └─ ...
└─ [SPAN tid=100 Kernel#system  dur=5.1ms]
   └─ ...
```

**Output timing.** The Correlator emits the full tree **once** when
the Observer session ends:

- `Vivarium.observe { ... }` (scoped) — at block exit.
- `Vivarium.top_observe` — at `at_exit` / explicit `session.stop`.

v1 does not stream partial output mid-session. A future iteration
may add per-Span streaming output.

**State retention.** The Correlator holds all closed-Span subtrees
in memory until session end. Memory cost is proportional to the
total event count across the session. For PoC scope (a handful of
`Kernel#system` calls), this is negligible.

**Out-of-Span events: grouped into synthetic `<no-span>` Spans.**
Events whose `(pid, tid, ktime_ns)` match no real Span are collected
into per-gap synthetic Spans. The Correlator materializes one
synthetic Span per time gap:

- one for the interval `[session_start, firstRealSpan.start]`,
- one for each interval `[prevRealSpan.stop, nextRealSpan.start]`
  between consecutive real Spans,
- one for the interval `[lastRealSpan.stop, session_end]`.

A synthetic Span uses the literal sentinel name **`<no-span>`** in
its Format A header — the angle brackets distinguish it from real
method names — and otherwise renders identically to a real Span:

```
[SPAN tid=100 <no-span>  dur=10.0ms]
└─ LSM  file_open  →  /tmp/whatever                       @+3.0ms
```

The same join rule (§5.9) applies: events match a synthetic Span by
either `tid == MainThread.tid` or `pid ∈ descendant_pids` (forks
that happen outside any real Span are tracked the same way).

**Empty gaps are not rendered.** A synthetic Span with zero matched
events is skipped, so a stretch of pure idle does not pollute the
tree.

**Late-arriving child events.** For v1 the allowlist is
`Kernel#system`, which `wait(2)`s for its child. Therefore every
child process's events arrive within `[Span.start, Span.stop]` and
the join rule (§5.9) places them correctly. The case where a Span
spawns a long-lived background child (e.g. `Kernel#spawn` + no
wait) is out of v1 scope.

### 5.11 Time anchoring and header format

The Correlator captures a session anchor at startup and another at
shutdown:

- `session_start_iso` / `session_stop_iso` — wall clock at
  Correlator Thread start / stop (ISO 8601 with millisecond
  precision, UTC).
- `session_start_ktime` / `session_stop_ktime` —
  `bpf_ktime_get_ns()` values sampled at the same instants.

These are emitted at the top of the rendered output as a multi-line
comment header (lines beginning with `#`):

```
# vivarium session
#   started  iso=2026-05-27T19:00:00.000Z  ktime=12345678900
#   stopped  iso=2026-05-27T19:00:30.250Z  ktime=12375929150
#   duration 30.250s
[PROC pid=100 comm=ruby]
...
```

The `ktime` values are the absolute anchor for the entire session.
All Format A timestamps (§5.4) are `@+Xms` offsets relative to their
enclosing Span's `start_ktime`. Span `start_ktime` itself can be
recovered as `session_start_ktime + (span offset from session start)`
if needed, but is not exposed in the default rendering.

Comment lines (`#`-prefixed) are out of band; renderers may emit
additional `#` lines for warnings (§5.12).

### 5.12 method_id resolution and ordering

`method_id` registrations from the Main Thread arrive on the Queue
out of order relative to ringbuf events bearing the same
`method_id` (the ringbuf `span_start` may be observed before the
Queue registration is processed). v1 handles this **lazily**:

1. The Correlator updates its local `method_id → signature` table
   as Queue messages arrive, but never blocks on it.
2. Span name resolution is **deferred until rendering** (which
   happens once at session end per §5.10). By that point the Queue
   should be drained and the table should be complete.
3. Any `method_id` still unresolved at render time is rendered with
   the placeholder name **`<method_id=0x{hex}>`**, and a warning
   line is emitted immediately after the session header:

   ```
   # warning method_id=0xABCD1234EF567890 unresolved at render time
   ```

4. If unresolved warnings become frequent in practice, revisit the
   registration delivery (e.g., push registrations through the same
   ringbuf, or block the Main Thread until ack). v1 does not.

---

## 6. Decisions still open

1. **Backpressure.** What happens when `bpf_ringbuf_reserve` returns
   NULL? Need a drop counter (a separate small map) and the Correlator
   should render `[DROPPED n]` markers in-tree at the point of loss.

2. **`method_id` collisions.** Hash space is 64-bit; collisions are
   astronomically unlikely but not impossible. Proposal: ignore for
   v1, document.

3. **Long-lived background children.** §5.10 assumes the allowlisted
   method waits for its child (true for `Kernel#system`). With the
   broader v1 allowlist (Process spawn, etc.) a Span may close while
   its child is still alive, causing child events to land outside any
   real Span and be absorbed by a synthetic `<no-span>` gap. Acceptable
   for now; revisit if this becomes a usability issue.

4. **`:raise` noise filtering.** `:raise` is currently unfiltered
   (§5.8). If library-internal exceptions become a rendering nuisance
   beyond what the `vivarium_usdt` exception-safety guarantee buffers,
   reintroduce a defined-class denylist or an allowlist.

---

## 7. Implementation map (v1)

### 7.1 Where the §5 design lives in code

| §5 concept                          | Code location                                                                                                     |
|-------------------------------------|-------------------------------------------------------------------------------------------------------------------|
| `event_t` v2 (with `tid`)           | [lib/vivarium.rb](lib/vivarium.rb) — `EVENT_TID_OFFSET=12`, `EVENT_PAYLOAD_OFFSET=32` + BPF `struct event_t`      |
| `BPF_RINGBUF_OUTPUT(events, ...)`   | [lib/vivarium.rb](lib/vivarium.rb) — replaces former `event_invoked` / `event_write_pos` array maps               |
| Auto-`tid`/`ktime_ns` fill          | [lib/vivarium.rb](lib/vivarium.rb) — `submit_event()` BPF helper sets both from `bpf_get_current_pid_tgid`        |
| `proc_fork` ringbuf event           | [lib/vivarium.rb](lib/vivarium.rb) — `TRACEPOINT_PROBE(sched, sched_process_fork)` emits when target              |
| USDT uprobe handlers                | [lib/vivarium.rb](lib/vivarium.rb) — `on_span_start` / `on_span_stop` / `on_span_raise` (BPF C)                   |
| USDT attach via `.so` path          | [lib/vivarium.rb](lib/vivarium.rb) — `Daemon#run` calls `RbBCC::USDT.new(path: ...)`                              |
| `.so` path discovery                | [lib/vivarium.rb](lib/vivarium.rb) — `Vivarium.locate_vivarium_usdt_so`                                           |
| `MapStore` (slim, registration only)| [lib/vivarium.rb](lib/vivarium.rb) — `register_pid` / `unregister_pid` only                                       |
| Correlator Thread                   | [lib/vivarium/correlator.rb](lib/vivarium/correlator.rb)                                                          |
| Format A renderer                   | [lib/vivarium/tree_renderer.rb](lib/vivarium/tree_renderer.rb)                                                    |
| `gettid(2)` via Fiddle              | [lib/vivarium.rb](lib/vivarium.rb) — `Vivarium.gettid`                                                            |
| `method_id` Queue + lazy resolve    | `Thread::Queue` created in `top_observe` / `scoped_observe`, drained by Correlator, resolved at render            |
| Span allowlist (class + method)     | [lib/vivarium.rb](lib/vivarium.rb) — `SPAN_ALLOWCLASSES` (Socket/File/Dir/Signal/Process families) + `SPAN_ALLOWLIST` (Kernel#system/require/load/eval, Object#instance_eval/instance_exec) |
| TracePoint USDT firing              | [lib/vivarium.rb](lib/vivarium.rb) — `build_observe_tracepoint` (`:call`/`:c_call`/`:return`/`:c_return` gated by allowlist; `:raise` unfiltered → `raise_probe`) |
| `span_raise` payload + event render | [lib/vivarium.rb](lib/vivarium.rb) `decode_span_raise_payload` + [lib/vivarium/tree_renderer.rb](lib/vivarium/tree_renderer.rb) `render_raise_target` (EXCP kind, `(raise)` Span suffix) |
| Per-Span `file:lineno`              | USDT probe args (24B start/stop, 32B raise) resolved via `Vivarium::Usdt.register_or_resolve_file`; rendered by `TreeRenderer#span_file_info` |

### 7.2 v1 deviations and pragmatic choices

- **USDT attach is binary-path-based at daemon startup** (chosen over
  per-PID dynamic attach). vivariumd loads `vivarium_usdt` once,
  resolves its `.so` via `$LOADED_FEATURES`, and passes it as a single
  `usdt_contexts:` to `RbBCC::BCC.new`. Per-PID filtering still happens
  BPF-side via `target_enabled` (unchanged).
- **Logger (`lib/vivarium/logger.rb`) is orphaned but retained.** All
  Observer-side rendering goes through the Correlator / TreeRenderer.
  The kprint diagnostic thread in `Daemon` continues to use `puts` /
  `warn` directly, not Logger. The file is left intact to avoid
  collateral churn; it can be deleted in a follow-up.
- **`render_event_payload` is reused inside TreeRenderer** as the
  `target` text for event lines. This couples Format A target rendering
  to the existing decoder set; v1 accepts the coupling rather than
  duplicate the decoders.
- **`Process.clock_gettime(CLOCK_MONOTONIC, :nanosecond)`** is used as
  the userspace anchor for `session_start_ktime` / `session_stop_ktime`.
  This is treated as equivalent to BPF `bpf_ktime_get_ns()`; any small
  divergence (suspend handling on older kernels) is accepted for v1.
- **method_id resolution is fully lazy at render time** per §5.12,
  using `<method_id=0xHEX>` placeholder + `# warning ...` header line
  if unresolved. No back-fill, no Main-Thread blocking, no second
  registration channel.
- **Synthetic `<no-span>` gap rendering is emitted only when non-empty**
  (matches §5.10's "Empty gaps are not rendered" rule).
