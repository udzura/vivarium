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
- BPF LSM hooks on `inode_symlink`, `inode_link`, `inode_rename`, `path_chmod`
- BPF tracepoint on `sys_enter_getdents64`
- BPF tracepoint on `sys_enter_execve` (captures executable path and first few argv entries as `proc_exec`)
- BPF LSM hooks for suspicious behavior checks:
	- `ptrace_access_check` (emits `ptrace_check`)
	- `sb_mount` (emits `sb_mount`)
	- `kernel_read_file` (emits `kernel_read_file`)
	- `task_kill` (emits `task_kill`)
	- `task_fix_setuid` (emits `setid_change`)
	- `capable` for high-risk capabilities only (emits `capable_check`)
	- `bprm_creds_from_file` (emits `bprm_creds`)
- BPF LSM hook on `socket_create` (flags unusual socket creation as `odd_socket`)
- BPF LSM hook on `socket_connect` (captures destination family/address/port as `sock_connect`)
- BPF tracepoints on `sys_enter_sendmsg`, `sys_enter_sendto`, `sys_enter_sendmmsg` (capture UDP/53 DNS QNAME raw bytes as `dns_req`)
- Shared pinned maps on bpffs
	- `config_root_targets` (root PID -> 0/1)
	- `config_spawned_targets` (spawned TID -> 0/1)
	- `event_invoked` (array length 1024 with `event_t` records)
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
	u64 ktime_ns;
	u32 pid;
	char event_name[16];
	char payload[256];
};
```

## Requirements

- Linux kernel/environment supporting BPF LSM
- `libbcc` installed
- `bpftool` installed (used to resolve `struct file::f_path` and `struct dentry::d_name` offsets from BTF)
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

3) Network monitoring demo client:

```bash
bundle exec ruby examples/network_client_demo.rb
```

This demo intentionally triggers `sock_connect`, `dns_req`, and `odd_socket` events.

4) File operation demo client (only touches `/tmp`):

```bash
bundle exec ruby examples/file_operation_demo.rb
```

This demo intentionally triggers `path_open`, `file_symlink`, `file_hardlink`, `file_rename`, `file_chmod`, and `file_getdents` events under `/tmp`.

5) Execve demo client:

```bash
bundle exec ruby examples/execve_demo.rb
```

This demo intentionally triggers `proc_exec` with several argument patterns using direct `execve`-style process launches.

6) Signal demo client:

```bash
bundle exec ruby examples/signal_kill_demo.rb
```

This demo forks a child process and sends `TERM` with `Process.kill`, which is useful for triggering `task_kill`.

7) Privilege-related event demo client:

```bash
bundle exec ruby examples/privilege_event_demo.rb
```

This demo attempts setuid/setgid changes, sensitive file access, and `sudo` exec to trigger privilege-related events such as `setid_change`, `capable_check`, and `bprm_creds`.

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
- `event_invoked` uses fixed 1024 slots and wraps around when full.
- `payload` is 256 bytes in `event_t`; some event types intentionally use smaller structured slices inside that buffer.
- `proc_exec` currently stores the executable path plus up to 3 argv entries in 4 fixed 64-byte slots to keep the BPF verifier happy.
- Each event is tagged with severity metadata: `high` for `setid_change`, `capable_check`, `bprm_creds`, `task_kill`, `ptrace_check`, `sb_mount`, and `kernel_read_file`; others are `medium` by default.
- In `human` format output, `high` severity events are rendered in red.
- `capable_check` is intentionally filtered to high-risk capabilities to reduce noise from extremely frequent `capable` hook calls.
- Current output format is textual and intended for iteration.
- `vivariumd` resolves `struct file::f_path` offset from `/sys/kernel/btf/vmlinux` at startup.
- `vivariumd` also resolves `struct dentry::d_name` offset from `/sys/kernel/btf/vmlinux` at startup.
- You can override offsets manually with `VIVARIUM_FILE_F_PATH_OFFSET` and `VIVARIUM_DENTRY_D_NAME_OFFSET` if auto-detection fails.
- `vivariumd` also prints `bpf_trace_printk` lines (`vivarium: pid=... path=...`) to its own logs.

## Contributing

Issues and pull requests are welcome.
