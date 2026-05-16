# Vivarium

[![Gem Version](https://badge.fury.io/rb/vivarium.svg)](https://rubygems.org/gems/vivarium)

RubyGems: https://rubygems.org/gems/vivarium

Vivarium is an observation and sandbox helper for Ruby.

It combines:

- eBPF LSM monitoring via RbBCC (`vivariumd`)
- Ruby-side method boundary observation via `TracePoint` (`Vivarium.observe`)

The goal is to visualize which Ruby method context triggered low-level events.

## Current Scope

Implemented in this repository:

- BPF LSM hook on `file_open`
- Shared pinned maps on bpffs
	- `config_root_targets` (root PID -> 0/1)
	- `config_spawned_targets` (spawned TID -> 0/1)
	- `event_invoked` (array length 64 with `event_t` records)
	- `event_write_pos` (cursor for appending into `event_invoked`)
- Ruby API `Vivarium.observe do ... end`
	- Registers current PID to `config_root_targets`
	- eBPF tracks spawned descendants into `config_spawned_targets` via `sched_process_fork`
	- On each `:return` / `:c_return`, drains `event_invoked`
	- Prints stack trace + events
	- Clears event slots and cursor
	- Unregisters PID on block exit

`event_t` currently:

```c
struct event_t {
	u32 pid;
	char event_name[8];   // "path_open"
	char payload[64];     // opened path (truncated)
};
```

## Requirements

- Linux kernel/environment supporting BPF LSM
- `libbcc` installed
- `bpftool` installed (used to resolve `struct file::f_path` offset from BTF)
- root privileges for `vivariumd`
- bpffs mounted (typically `/sys/fs/bpf`)

## Installation

Add to Gemfile:

```ruby
gem "vivarium"
```

Then:

```bash
bundle install
```

## Usage

1) Start daemon (root):

```bash
sudo bundle exec vivariumd
```

2) Observe in Ruby process:

```ruby
require "vivarium"

Vivarium.observe do
  File.read("/etc/passwd")
end
```

You can also start top-level observation without a block (it keeps observing until process exit):

```ruby
require "vivarium"

observer = Vivarium.top_observe
# or: Vivarium.observe
# do anything ...
observer.stop
```

By default, Vivarium excludes its own internal frames from stack output. Set `VIVARIUM_FILTER_INTERNAL_FRAMES=0` to disable this filter.

You can override pin directory via `VIVARIUM_BPF_PIN_DIR` on both sides:

```bash
VIVARIUM_BPF_PIN_DIR=/sys/fs/bpf/vivarium bundle exec vivariumd
```

Use `Vivarium.bpf_pin_dir = "/sys/fs/bpf/..."` in Ruby code to set it programmatically.

```ruby
require "vivarium"
Vivarium.bpf_pin_dir = "/sys/fs/bpf/vivarium"
```

## Development

Run tests:

```bash
bundle exec rake test
```

Daemon entrypoint:

```bash
bundle exec vivariumd --pin-dir /sys/fs/bpf/vivarium
```

## Notes

- Thread/Ractor-awareness is not yet implemented.
- `event_invoked` uses fixed 64 slots and wraps around when full.
- Payload is truncated to 64 bytes in kernel space.
- Current output format is textual and intended for iteration.
- `vivariumd` resolves `struct file::f_path` offset from `/sys/kernel/btf/vmlinux` at startup.
- You can override offset manually with `VIVARIUM_FILE_F_PATH_OFFSET` if auto-detection fails.
- `vivariumd` also prints `bpf_trace_printk` lines (`vivarium: pid=... path=...`) to its own logs.

## Contributing

Issues and pull requests are welcome.
