# frozen_string_literal: true

require "fiddle"
require "fileutils"
require "net/http"
require "optparse"
require "pathname"
require "rbbcc"
require "socket"
require_relative "vivarium/version"
require_relative "vivarium/cli"

module Vivarium
  class Error < StandardError; end

  PIN_DIR = ENV.fetch("VIVARIUM_BPF_PIN_DIR", "/sys/fs/bpf/vivarium")
  CONFIG_ROOT_TARGETS_PIN = File.join(PIN_DIR, "config_root_targets")
  CONFIG_SPAWNED_TARGETS_PIN = File.join(PIN_DIR, "config_spawned_targets")
  CONFIG_TARGETS_PIN = CONFIG_ROOT_TARGETS_PIN
  EVENTS_PIN = File.join(PIN_DIR, "events")

  EVENT_NAME_SIZE = 16
  EVENT_PAYLOAD_SIZE = 256
  EVENT_TS_SIZE = 8
  PROC_EXEC_SLOT_SIZE = 64
  PROC_EXEC_SLOT_COUNT = 4
  EVENT_STRUCT_SIZE = 288
  EVENT_TS_OFFSET = 0
  EVENT_PID_OFFSET = 8
  EVENT_TID_OFFSET = 12
  EVENT_NAME_OFFSET = 16
  EVENT_PAYLOAD_OFFSET = 32
  EVENTS_RINGBUF_PAGES = 256

  SSL_WRITE_PAYLOAD_DATA_LEN_OFFSET = 0
  SSL_WRITE_PAYLOAD_CAP_LEN_OFFSET = 4
  SSL_WRITE_PAYLOAD_DATA_OFFSET = 8
  SSL_WRITE_PAYLOAD_DATA_MAX = EVENT_PAYLOAD_SIZE - SSL_WRITE_PAYLOAD_DATA_OFFSET

  LIBSSL_SEARCH_PATHS = [
    "/lib/x86_64-linux-gnu/libssl.so.3",
    "/lib/x86_64-linux-gnu/libssl.so.1.1",
    "/lib/aarch64-linux-gnu/libssl.so.3",
    "/lib/aarch64-linux-gnu/libssl.so.1.1",
    "/usr/lib/x86_64-linux-gnu/libssl.so.3",
    "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
    "/usr/lib/aarch64-linux-gnu/libssl.so.3",
    "/usr/lib/aarch64-linux-gnu/libssl.so.1.1",
    "/usr/lib64/libssl.so.3",
    "/usr/lib64/libssl.so.1.1",
    "/usr/lib/libssl.so.3",
    "/usr/lib/libssl.so.1.1"
  ].freeze

  SPAN_ALLOWCLASSES = [
    Socket,
    BasicSocket,
    IPSocket,
    TCPSocket,
    UDPSocket,
    UNIXSocket,
    File,
    Dir,
    Signal,
    Process,
    Process::UID,
    Process::GID,
    Net::HTTP,
  ]
  SPAN_ALLOWLIST = [
    "Kernel#system",
    "Kernel#require",
    "Kernel#require_relative",
    "Kernel#load",
    "Kernel#eval",
    "Object#instance_eval",
    "Object#instance_exec",
  ].freeze
  EVENT_SEVERITY_HIGH = %w[
    capable_check bprm_creds setid_change task_kill
    ptrace_check sb_mount kernel_read_file
  ].freeze

  CAPABILITY_NAMES = {
    0 => "CAP_CHOWN",
    1 => "CAP_DAC_OVERRIDE",
    2 => "CAP_DAC_READ_SEARCH",
    3 => "CAP_FOWNER",
    4 => "CAP_FSETID",
    5 => "CAP_KILL",
    6 => "CAP_SETGID",
    7 => "CAP_SETUID",
    8 => "CAP_SETPCAP",
    9 => "CAP_LINUX_IMMUTABLE",
    10 => "CAP_NET_BIND_SERVICE",
    12 => "CAP_NET_ADMIN",
    13 => "CAP_NET_RAW",
    16 => "CAP_SYS_MODULE",
    17 => "CAP_SYS_RAWIO",
    18 => "CAP_SYS_CHROOT",
    19 => "CAP_SYS_PTRACE",
    21 => "CAP_SYS_ADMIN",
    22 => "CAP_SYS_BOOT",
    23 => "CAP_SYS_NICE",
    24 => "CAP_SYS_RESOURCE",
    25 => "CAP_SYS_TIME",
    27 => "CAP_MKNOD",
    29 => "CAP_AUDIT_WRITE",
    37 => "CAP_AUDIT_READ",
    38 => "CAP_PERFMON",
    39 => "CAP_BPF",
    40 => "CAP_CHECKPOINT_RESTORE"
  }.freeze

  SETID_FLAG_NAMES = {
    0x01 => "LSM_SETID_ID",
    0x02 => "LSM_SETID_RE",
    0x04 => "LSM_SETID_RES",
    0x08 => "LSM_SETID_FS"
  }.freeze

  @bpf_pin_dir = PIN_DIR

  class << self
    attr_writer :bpf_pin_dir

    def bpf_pin_dir
      @bpf_pin_dir || PIN_DIR
    end
  end

  def self.c_string(bytes)
    str = bytes.to_s.b
    nul = str.index("\x00")
    return str if nul.nil?

    str[0, nul]
  end

  def self.event_severity(event_name)
    EVENT_SEVERITY_HIGH.include?(event_name.to_s) ? "high" : "medium"
  end

  def self.decode_dns_qname(raw_payload)
    bytes = raw_payload.to_s.b.bytes
    labels = []
    idx = 0

    while idx < bytes.length
      length = bytes[idx]
      break if length.nil? || length.zero?
      break if length > 63

      idx += 1
      break if (idx + length) > bytes.length

      label = bytes[idx, length].pack("C*")
      labels << label
      idx += length
    end

    return "" if labels.empty?

    labels.join(".")
  end

  def self.decode_sock_connect_payload(raw_payload)
    bytes = raw_payload.to_s.b
    return "" if bytes.bytesize < 20

    family = bytes[0, 2].unpack1("S<")
    port = bytes[2, 2].unpack1("n")
    addr = bytes[4, 16]

    case family
    when 2 # AF_INET
      ipv4 = addr[0, 4].bytes.join(".")
      "#{ipv4}:#{port} (#{socket_const_name("AF_", family)})"
    when 10 # AF_INET6
      words = addr.unpack("n8")
      ipv6 = words.map { |w| format("%x", w) }.join(":")
      "[#{ipv6}]:#{port} (#{socket_const_name("AF_", family)})"
    else
      "family=#{family}(#{socket_const_name("AF_", family)}) port=#{port}"
    end
  end

  def self.decode_odd_socket_payload(raw_payload)
    bytes = raw_payload.to_s.b
    return "" if bytes.bytesize < 6

    family = bytes[0, 2].unpack1("S<")
    type = bytes[2, 2].unpack1("S<")
    protocol = bytes[4, 2].unpack1("S<")
    family_name = socket_const_name("AF_", family)
    type_name = socket_const_name("SOCK_", type)
    protocol_name = socket_const_name("IPPROTO_", protocol)
    "family=#{family}(#{family_name}) type=#{type}(#{type_name}) protocol=#{protocol}(#{protocol_name})"
  end

  def self.socket_const_name(prefix, value)
    return "UNKNOWN" unless defined?(Socket)

    key = Socket.constants.find do |name|
      name.to_s.start_with?(prefix) && Socket.const_get(name) == value
    rescue NameError
      false
    end

    key ? key.to_s : "UNKNOWN"
  end

  def self.decode_bad_socket_payload(raw_payload)
    decode_odd_socket_payload(raw_payload)
  end

  def self.decode_file_symlink_payload(raw_payload)
    bytes = raw_payload.to_s.b
    target = c_string(bytes[0, 128])
    link_name = c_string(bytes[128, 128])
    "target=#{target.inspect} link_name=#{link_name.inspect}"
  end

  def self.decode_file_hardlink_payload(raw_payload)
    bytes = raw_payload.to_s.b
    old_path = c_string(bytes[0, 128])
    new_name = c_string(bytes[128, 128])
    "old_path=#{old_path.inspect} new_name=#{new_name.inspect}"
  end

  def self.decode_file_rename_payload(raw_payload)
    bytes = raw_payload.to_s.b
    old_name = c_string(bytes[0, 128])
    new_name = c_string(bytes[128, 128])
    "old_name=#{old_name.inspect} new_name=#{new_name.inspect}"
  end

  def self.decode_file_chmod_payload(raw_payload)
    bytes = raw_payload.to_s.b
    return "" if bytes.bytesize < 2

    mode = bytes[0, 2].unpack1("S<")
    path = c_string(bytes[2, 254])
    "mode=#{format('0o%o', mode)} path=#{path.inspect}"
  end

  def self.decode_file_getdents_payload(raw_payload)
    bytes = raw_payload.to_s.b
    return "" if bytes.bytesize < 8

    fd = bytes[0, 4].unpack1("L<")
    count = bytes[4, 4].unpack1("L<")
    "fd=#{fd} count=#{count}"
  end

  def self.decode_proc_exec_payload(raw_payload)
    bytes = raw_payload.to_s.b
    slots = PROC_EXEC_SLOT_COUNT.times.map do |index|
      offset = index * PROC_EXEC_SLOT_SIZE
      c_string(bytes[offset, PROC_EXEC_SLOT_SIZE])
    end
    slots.reject!(&:empty?)
    return "" if slots.empty?

    filename = slots.shift
    argv = slots
    "filename=#{filename.inspect} argv=[#{argv.map(&:inspect).join(', ')}]"
  end

  def self.decode_ptrace_check_payload(raw_payload)
    bytes = raw_payload.to_s.b
    return "" if bytes.bytesize < 4

    mode = bytes[0, 4].unpack1("L<")
    "mode=0x#{mode.to_s(16)}"
  end

  def self.decode_sb_mount_payload(raw_payload)
    bytes = raw_payload.to_s.b
    return "" if bytes.bytesize < 248

    flags = bytes[0, 8].unpack1("Q<")
    dev_name = c_string(bytes[8, 120])
    fs_type = c_string(bytes[128, 120])
    "flags=0x#{flags.to_s(16)} dev_name=#{dev_name.inspect} fs_type=#{fs_type.inspect}"
  end

  def self.decode_kernel_read_file_payload(raw_payload)
    bytes = raw_payload.to_s.b
    return "" if bytes.bytesize < 8

    id = bytes[0, 4].unpack1("L<")
    contents = bytes[4, 4].unpack1("L<")
    "id=#{id} contents=#{contents}"
  end

  def self.decode_task_kill_payload(raw_payload)
    bytes = raw_payload.to_s.b
    return "" if bytes.bytesize < 4

    sig = bytes[0, 4].unpack1("l<")
    signame = begin
      Signal.signame(sig)
    rescue ArgumentError
      nil
    end

    signame ? "sig=#{sig} signame=#{signame}" : "sig=#{sig}"
  end

  def self.decode_setid_change_payload(raw_payload)
    bytes = raw_payload.to_s.b
    return "" if bytes.bytesize < 4

    flags = bytes[0, 4].unpack1("L<")
    names = SETID_FLAG_NAMES.each_with_object([]) do |(bit, name), acc|
      acc << name if (flags & bit) != 0
    end
    names << "UNKNOWN" if names.empty?
    "flags=0x#{flags.to_s(16)} kinds=[#{names.join(', ')}]"
  end

  def self.decode_capable_check_payload(raw_payload)
    bytes = raw_payload.to_s.b
    return "" if bytes.bytesize < 8

    cap = bytes[0, 4].unpack1("L<")
    opts = bytes[4, 4].unpack1("L<")
    cap_name = CAPABILITY_NAMES.fetch(cap, "UNKNOWN")
    "cap=#{cap}(#{cap_name}) opts=0x#{opts.to_s(16)}"
  end

  def self.decode_bprm_creds_payload(raw_payload)
    bytes = raw_payload.to_s.b
    return "" if bytes.bytesize < 2

    has_file = bytes.getbyte(0).to_i
    path = c_string(bytes[1, EVENT_PAYLOAD_SIZE - 1])
    "has_file=#{has_file} file=#{path.inspect}"
  end

  def self.decode_proc_fork_payload(raw_payload)
    bytes = raw_payload.to_s.b
    return "" if bytes.bytesize < 8

    child_pid = bytes[0, 4].unpack1("L<")
    child_tid = bytes[4, 4].unpack1("L<")
    "child_pid=#{child_pid} child_tid=#{child_tid}"
  end

  def self.decode_span_payload(raw_payload)
    bytes = raw_payload.to_s.b
    return "" if bytes.bytesize < 8

    method_id = bytes[0, 8].unpack1("q<")
    result = format("method_id=0x%016X", method_id & 0xFFFF_FFFF_FFFF_FFFF)

    if bytes.bytesize >= 24
      file_id = bytes[8, 8].unpack1("q<")
      lineno = bytes[16, 8].unpack1("q<")
      result += format(" file_id=0x%016X", file_id & 0xFFFF_FFFF_FFFF_FFFF) if file_id != -1
      result += " lineno=#{lineno}" if lineno > 0
    end

    result
  end

  def self.decode_ssl_write_payload(raw_payload)
    bytes = raw_payload.to_s.b
    return { data_len: 0, cap_len: 0, data: "".b } if bytes.bytesize < SSL_WRITE_PAYLOAD_DATA_OFFSET

    data_len = bytes[SSL_WRITE_PAYLOAD_DATA_LEN_OFFSET, 4].unpack1("L<")
    cap_len = bytes[SSL_WRITE_PAYLOAD_CAP_LEN_OFFSET, 4].unpack1("L<")
    cap_len = SSL_WRITE_PAYLOAD_DATA_MAX if cap_len > SSL_WRITE_PAYLOAD_DATA_MAX
    data = bytes[SSL_WRITE_PAYLOAD_DATA_OFFSET, cap_len] || "".b
    { data_len: data_len, cap_len: cap_len, data: data }
  end

  def self.decode_span_raise_payload(raw_payload)
    bytes = raw_payload.to_s.b
    return "" if bytes.bytesize < 8

    error_id = bytes[0, 8].unpack1("q<")
    result = format("error_id=0x%016X", error_id & 0xFFFF_FFFF_FFFF_FFFF)

    if bytes.bytesize >= 16
      message_id = bytes[8, 8].unpack1("q<")
      result += format(" message_id=0x%016X", message_id & 0xFFFF_FFFF_FFFF_FFFF)
    end

    if bytes.bytesize >= 24
      file_id = bytes[16, 8].unpack1("q<")
      result += format(" file_id=0x%016X", file_id & 0xFFFF_FFFF_FFFF_FFFF) if file_id != -1
    end

    if bytes.bytesize >= 32
      lineno = bytes[24, 8].unpack1("q<")
      result += " lineno=#{lineno}" if lineno > 0
    end

    result
  end

  def self.render_event_payload(event)
    case event.event_name
    when "dns_req"
      decoded = decode_dns_qname(event.payload)
      decoded.empty? ? event.payload.inspect : decoded
    when "sock_connect"
      decoded = decode_sock_connect_payload(event.payload)
      decoded.empty? ? event.payload.inspect : decoded
    when "odd_socket"
      decoded = decode_odd_socket_payload(event.payload)
      decoded.empty? ? event.payload.inspect : decoded
    when "proc_exec"
      decoded = decode_proc_exec_payload(event.payload)
      decoded.empty? ? event.payload.inspect : decoded
    when "ptrace_check"
      decoded = decode_ptrace_check_payload(event.payload)
      decoded.empty? ? event.payload.inspect : decoded
    when "sb_mount"
      decoded = decode_sb_mount_payload(event.payload)
      decoded.empty? ? event.payload.inspect : decoded
    when "kernel_read_file"
      decoded = decode_kernel_read_file_payload(event.payload)
      decoded.empty? ? event.payload.inspect : decoded
    when "task_kill"
      decoded = decode_task_kill_payload(event.payload)
      decoded.empty? ? event.payload.inspect : decoded
    when "setid_change"
      decoded = decode_setid_change_payload(event.payload)
      decoded.empty? ? event.payload.inspect : decoded
    when "capable_check"
      decoded = decode_capable_check_payload(event.payload)
      decoded.empty? ? event.payload.inspect : decoded
    when "bprm_creds"
      decoded = decode_bprm_creds_payload(event.payload)
      decoded.empty? ? event.payload.inspect : decoded
    when "proc_fork"
      decoded = decode_proc_fork_payload(event.payload)
      decoded.empty? ? event.payload.inspect : decoded
    when "span_start", "span_stop"
      decoded = decode_span_payload(event.payload)
      decoded.empty? ? event.payload.inspect : decoded
    when "span_raise"
      decoded = decode_span_raise_payload(event.payload)
      decoded.empty? ? event.payload.inspect : decoded
    when "file_symlink"
      decoded = decode_file_symlink_payload(event.payload)
      decoded.empty? ? event.payload.inspect : decoded
    when "file_hardlink"
      decoded = decode_file_hardlink_payload(event.payload)
      decoded.empty? ? event.payload.inspect : decoded
    when "file_rename"
      decoded = decode_file_rename_payload(event.payload)
      decoded.empty? ? event.payload.inspect : decoded
    when "file_chmod"
      decoded = decode_file_chmod_payload(event.payload)
      decoded.empty? ? event.payload.inspect : decoded
    when "file_getdents"
      decoded = decode_file_getdents_payload(event.payload)
      decoded.empty? ? event.payload.inspect : decoded
    when "ssl_write"
      decoded = decode_ssl_write_payload(event.payload)
      "data_len=#{decoded[:data_len]} cap_len=#{decoded[:cap_len]}"
    else
      strip_to_first_null(event.payload).inspect
    end
  end

  def self.strip_to_first_null(bytes)
    nul = bytes.index("\x00")
    return bytes if nul.nil?

    bytes[0, nul]
  end

  class MapStore
    def initialize(pin_dir: Vivarium.bpf_pin_dir)
      @pin_dir = pin_dir
      @config_root_targets = RbBCC::HashTable.from_pin(
        File.join(@pin_dir, "config_root_targets"),
        "unsigned int",
        "unsigned char",
        keysize: 4,
        leafsize: 1
      )
      @config_spawned_targets = RbBCC::HashTable.from_pin(
        File.join(@pin_dir, "config_spawned_targets"),
        "unsigned int",
        "unsigned char",
        keysize: 4,
        leafsize: 1
      )
    rescue StandardError => e
      raise Error, "failed to open pinned maps under #{@pin_dir}: #{e.class}: #{e.message}"
    end

    def register_pid(pid)
      @config_root_targets[pid] = 1
    end

    def unregister_pid(pid)
      @config_root_targets.delete(pid)
      @config_spawned_targets.clear
    rescue KeyError
      nil
    end
  end

  class Daemon
    BPF_PROGRAM_TEMPLATE = <<~CLANG
      #include <linux/socket.h>
      #include <uapi/linux/in.h>
      #include <uapi/linux/in6.h>
      #include <uapi/linux/ip.h>
      #include <uapi/linux/udp.h>

      #ifndef SOCK_STREAM
      #define SOCK_STREAM 1
      #endif
      #ifndef SOCK_DGRAM
      #define SOCK_DGRAM 2
      #endif

      struct net;
      struct sock;
      struct sk_buff;
      struct task_struct;
      struct kernel_siginfo;
      struct cred;
      struct user_namespace;
      struct linux_binprm;

      struct path {
        void *mnt;
        void *dentry;
      };
      struct file {
        char __off[__VIVARIUM_F_PATH_OFFSET__];
        struct path f_path;
      };

      struct qstr {
        union {
          struct {
            u64 hash_len;
          };
          struct {
            u32 hash;
            u32 len;
          };
        };
        const unsigned char *name;
      };

      struct dentry_base {
        char __pad[__VIVARIUM_DENTRY_D_NAME_OFFSET__];
        struct qstr d_name;
      };

      struct sockaddr_t {
        u16 sa_family;
        unsigned char sa_data[14];
      };

      struct sockaddr_in_t {
        u16 sin_family;
        u16 sin_port;
        u32 sin_addr;
        unsigned char pad[8];
      };

      struct sockaddr_in6_t {
        u16 sin6_family;
        u16 sin6_port;
        u32 sin6_flowinfo;
        unsigned char sin6_addr[16];
        u32 sin6_scope_id;
      };

      struct sockaddr_port_t {
        u16 family;
        u16 port;
      };

      struct iovec_t {
        void *iov_base;
        unsigned long iov_len;
      };

      struct user_msghdr_t {
        void *msg_name;
        int msg_namelen;
        struct iovec_t *msg_iov;
        unsigned long msg_iovlen;
        void *msg_control;
        unsigned long msg_controllen;
        unsigned int msg_flags;
      };

      struct mmsghdr_t {
        struct user_msghdr_t msg_hdr;
        unsigned int msg_len;
      };

      struct sk_buff_t {
        unsigned char *head;
        unsigned char *data;
        u32 len;
        u16 mac_header;
        u16 network_header;
        u16 transport_header;
      };

      struct event_t {
        u64 ktime_ns;
        u32 pid;
        u32 tid;
        char event_name[16];
        char payload[#{EVENT_PAYLOAD_SIZE}];
      };

      BPF_HASH(config_root_targets, u32, u8, 1024);
      BPF_HASH(config_spawned_targets, u32, u8, 8192);
      BPF_HASH(dns_connected_tids, u32, u8, 8192);
      BPF_RINGBUF_OUTPUT(events, #{EVENTS_RINGBUF_PAGES});

      static __always_inline int target_enabled(u32 pid, u32 tid)
      {
        u8 *enabled_root = config_root_targets.lookup(&pid);
        if (enabled_root && *enabled_root == 1) {
          return 1;
        }

        u8 *enabled_spawned = config_spawned_targets.lookup(&tid);
        if (enabled_spawned && *enabled_spawned == 1) {
          return 1;
        }

        return 0;
      }

      static __always_inline int monitored_capability(int cap)
      {
        switch (cap) {
          case 1:  /* CAP_DAC_OVERRIDE */
          case 2:  /* CAP_DAC_READ_SEARCH */
          case 6:  /* CAP_SETGID */
          case 7:  /* CAP_SETUID */
          case 12: /* CAP_NET_ADMIN */
          case 16: /* CAP_SYS_MODULE */
          case 17: /* CAP_SYS_RAWIO */
          case 19: /* CAP_SYS_PTRACE */
          case 21: /* CAP_SYS_ADMIN */
          case 22: /* CAP_SYS_BOOT */
          case 25: /* CAP_SYS_TIME */
          case 38: /* CAP_PERFMON */
          case 39: /* CAP_BPF */
          case 40: /* CAP_CHECKPOINT_RESTORE */
            return 1;
          default:
            return 0;
        }
      }

      static __always_inline void submit_event(struct event_t *src)
      {
        struct event_t *ev = events.ringbuf_reserve(sizeof(struct event_t));
        if (!ev) {
          return;
        }

        __builtin_memcpy(ev, src, sizeof(*ev));
        ev->ktime_ns = bpf_ktime_get_ns();
        ev->tid = (u32)bpf_get_current_pid_tgid();

        events.ringbuf_submit(ev, 0);
      }

      static __always_inline int is_dns_destination(void *addr)
      {
        u16 family = 0;
        bpf_probe_read_user(&family, sizeof(family), addr);

        if (family == AF_INET) {
          struct sockaddr_in_t sin = {};
          bpf_probe_read_user(&sin, sizeof(sin), addr);
          return sin.sin_port == __constant_htons(53);
        }

        if (family == AF_INET6) {
          struct sockaddr_in6_t sin6 = {};
          bpf_probe_read_user(&sin6, sizeof(sin6), addr);
          return sin6.sin6_port == __constant_htons(53);
        }

        return 0;
      }

      static __always_inline void submit_dns_req(u32 pid, unsigned char *payload, unsigned int payload_len)
      {
        unsigned int copy_len = payload_len;

        if (copy_len <= 12) {
          return;
        }

        copy_len -= 12;
        if (copy_len > 64) {
          copy_len = 64;
        }

        struct event_t ev = {};
        ev.pid = pid;
        __builtin_memcpy(ev.event_name, "dns_req", 8);
        bpf_probe_read_user(&ev.payload[0], copy_len, payload + 12);
        submit_event(&ev);
      }

      static __always_inline int read_dentry_name(struct dentry *dentry, char *buffer, size_t max)
      {
        struct dentry_base d = {};
        struct qstr qname = {};

        if (!dentry || !buffer) {
          return -1;
        }

        bpf_probe_read_kernel(&d, sizeof(d), (void *)dentry);
        if (!d.d_name.name) {
          return -1;
        }

        unsigned int len = d.d_name.len;
        if (len > max) {
          len = max;
        }

        bpf_probe_read_kernel_str(buffer, len + 1, (void *)d.d_name.name);
        return len;
      }

      TRACEPOINT_PROBE(sched, sched_process_fork)
      {
        u32 parent = args->parent_pid;
        u32 child = args->child_pid;
        u8 one = 1;
        int is_target = 0;

        u8 *enabled_root = config_root_targets.lookup(&parent);
        if (enabled_root && *enabled_root == 1) {
          is_target = 1;
          config_spawned_targets.update(&child, &one);
        } else {
          u8 *enabled_spawned = config_spawned_targets.lookup(&parent);
          if (enabled_spawned && *enabled_spawned == 1) {
            is_target = 1;
            config_spawned_targets.update(&child, &one);
          }
        }

        if (is_target) {
          u64 pid_tgid = bpf_get_current_pid_tgid();
          struct event_t ev = {};
          ev.pid = pid_tgid >> 32;
          __builtin_memcpy(ev.event_name, "proc_fork", 10);
          __builtin_memcpy(&ev.payload[0], &child, sizeof(child));
          __builtin_memcpy(&ev.payload[4], &child, sizeof(child));
          submit_event(&ev);
        }

        return 0;
      }

      TRACEPOINT_PROBE(sched, sched_process_exit)
      {
        u32 tid = (u32)bpf_get_current_pid_tgid();
        config_spawned_targets.delete(&tid);
        dns_connected_tids.delete(&tid);
        return 0;
      }

      LSM_PROBE(file_open, struct file *file)
      {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;
        if (!target_enabled(pid, tid)) {
          return 0;
        }

        struct event_t ev = {};
        int path_ret;
        ev.pid = pid;
        __builtin_memcpy(ev.event_name, "path_open", 9);

        path_ret = bpf_d_path(&file->f_path, ev.payload, sizeof(ev.payload));
        if (path_ret < 0) {
          if (ev.payload[0] == 0) {
            __builtin_memcpy(ev.payload, "<path_error>", 13);
          }
        }

        submit_event(&ev);

        return 0;
      }

      LSM_PROBE(socket_create, int family, int type, int protocol, int kern)
      {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;

        if (!target_enabled(pid, tid)) {
          return 0;
        }

        if ((family == AF_INET || family == AF_INET6) && (type == SOCK_STREAM || type == SOCK_DGRAM)) {
          return 0;
        }

        struct event_t ev = {};
        u16 family16 = family;
        u16 type16 = type;
        u16 proto16 = protocol;

        ev.pid = pid;
        __builtin_memcpy(ev.event_name, "odd_socket", 11);
        __builtin_memcpy(&ev.payload[0], &family16, sizeof(family16));
        __builtin_memcpy(&ev.payload[2], &type16, sizeof(type16));
        __builtin_memcpy(&ev.payload[4], &proto16, sizeof(proto16));
        submit_event(&ev);

        return 0;
      }

      LSM_PROBE(socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
      {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;
        u16 family = 0;
        u8 one = 1;

        if (!target_enabled(pid, tid)) {
          return 0;
        }

        if (!address) {
          return 0;
        }

        bpf_probe_read_kernel(&family, sizeof(family), address);

        struct event_t ev = {};
        ev.pid = pid;
        __builtin_memcpy(ev.event_name, "sock_connect", 13);
        __builtin_memcpy(&ev.payload[0], &family, sizeof(family));

        if (family == AF_INET) {
          struct sockaddr_in_t sin = {};
          bpf_probe_read_kernel(&sin, sizeof(sin), address);
          __builtin_memcpy(&ev.payload[2], &sin.sin_port, sizeof(sin.sin_port));
          __builtin_memcpy(&ev.payload[4], &sin.sin_addr, sizeof(sin.sin_addr));
          if (sin.sin_port == __constant_htons(53)) {
            dns_connected_tids.update(&tid, &one);
          }
        } else if (family == AF_INET6) {
          struct sockaddr_in6_t sin6 = {};
          bpf_probe_read_kernel(&sin6, sizeof(sin6), address);
          __builtin_memcpy(&ev.payload[2], &sin6.sin6_port, sizeof(sin6.sin6_port));
          __builtin_memcpy(&ev.payload[4], &sin6.sin6_addr, sizeof(sin6.sin6_addr));
          if (sin6.sin6_port == __constant_htons(53)) {
            dns_connected_tids.update(&tid, &one);
          }
        }

        submit_event(&ev);

        return 0;
      }

      TRACEPOINT_PROBE(syscalls, sys_enter_sendmsg)
      {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;
        struct user_msghdr_t msg = {};
        struct iovec_t iov = {};

        if (!target_enabled(pid, tid)) {
          return 0;
        }

        if (!args->msg) {
          return 0;
        }

        bpf_probe_read_user(&msg, sizeof(msg), args->msg);
        if (!msg.msg_iov || msg.msg_iovlen == 0) {
          return 0;
        }

        if (msg.msg_name && !is_dns_destination(msg.msg_name)) {
          return 0;
        }

        bpf_probe_read_user(&iov, sizeof(iov), msg.msg_iov);
        if (!iov.iov_base) {
          return 0;
        }

        submit_dns_req(pid, (unsigned char *)iov.iov_base, (unsigned int)iov.iov_len);

        return 0;
      }

      TRACEPOINT_PROBE(syscalls, sys_enter_sendto)
      {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;
        unsigned char *buff = args->buff;
        int dns_match = 0;

        if (!target_enabled(pid, tid)) {
          return 0;
        }

        if (!buff) {
          return 0;
        }

        if (args->addr) {
          dns_match = is_dns_destination(args->addr);
        } else {
          u8 *connected = dns_connected_tids.lookup(&tid);
          dns_match = connected && *connected == 1;
        }

        if (!dns_match) {
          return 0;
        }

        submit_dns_req(pid, buff, args->len);
        dns_connected_tids.delete(&tid);

        return 0;
      }

      TRACEPOINT_PROBE(syscalls, sys_enter_sendmmsg)
      {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;
        struct mmsghdr_t mmsg = {};
        struct iovec_t iov = {};

        if (!target_enabled(pid, tid)) {
          return 0;
        }

        if (!args->mmsg) {
          return 0;
        }

        bpf_probe_read_user(&mmsg, sizeof(mmsg), args->mmsg);
        if (mmsg.msg_hdr.msg_name && !is_dns_destination(mmsg.msg_hdr.msg_name)) {
          return 0;
        }

        if (!mmsg.msg_hdr.msg_iov || mmsg.msg_hdr.msg_iovlen == 0) {
          return 0;
        }

        bpf_probe_read_user(&iov, sizeof(iov), mmsg.msg_hdr.msg_iov);
        if (!iov.iov_base) {
          return 0;
        }

        submit_dns_req(pid, (unsigned char *)iov.iov_base, (unsigned int)iov.iov_len);

        return 0;
      }

      TRACEPOINT_PROBE(syscalls, sys_enter_execve)
      {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;
        const char *argv0 = 0;
        const char *argv1 = 0;
        const char *argv2 = 0;

        if (!target_enabled(pid, tid)) {
          return 0;
        }

        if (!args->filename) {
          return 0;
        }

        struct event_t ev = {};
        ev.pid = pid;
        __builtin_memcpy(ev.event_name, "proc_exec", 10);
        bpf_probe_read_user_str(&ev.payload[0], #{PROC_EXEC_SLOT_SIZE}, args->filename);

        if (args->argv) {
          bpf_probe_read_user(&argv0, sizeof(argv0), &args->argv[0]);
          bpf_probe_read_user(&argv1, sizeof(argv1), &args->argv[1]);
          bpf_probe_read_user(&argv2, sizeof(argv2), &args->argv[2]);

          if (argv0) {
            bpf_probe_read_user_str(&ev.payload[#{PROC_EXEC_SLOT_SIZE}], #{PROC_EXEC_SLOT_SIZE}, argv0);
          }
          if (argv1) {
            bpf_probe_read_user_str(&ev.payload[#{PROC_EXEC_SLOT_SIZE * 2}], #{PROC_EXEC_SLOT_SIZE}, argv1);
          }
          if (argv2) {
            bpf_probe_read_user_str(&ev.payload[#{PROC_EXEC_SLOT_SIZE * 3}], #{PROC_EXEC_SLOT_SIZE}, argv2);
          }
        }

        submit_event(&ev);
        return 0;
      }

      LSM_PROBE(ptrace_access_check, struct task_struct *child, unsigned int mode)
      {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;

        if (!target_enabled(pid, tid)) {
          return 0;
        }

        struct event_t ev = {};
        u32 mode32 = mode;

        ev.pid = pid;
        __builtin_memcpy(ev.event_name, "ptrace_check", 13);
        __builtin_memcpy(&ev.payload[0], &mode32, sizeof(mode32));
        submit_event(&ev);

        return 0;
      }

      LSM_PROBE(sb_mount, const char *dev_name, const struct path *path, const char *type, unsigned long flags, void *data)
      {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;

        if (!target_enabled(pid, tid)) {
          return 0;
        }

        struct event_t ev = {};
        u64 flags64 = flags;

        ev.pid = pid;
        __builtin_memcpy(ev.event_name, "sb_mount", 9);
        __builtin_memcpy(&ev.payload[0], &flags64, sizeof(flags64));

        if (dev_name) {
          bpf_probe_read_kernel_str(&ev.payload[8], 120, dev_name);
        }
        if (type) {
          bpf_probe_read_kernel_str(&ev.payload[128], 120, type);
        }

        submit_event(&ev);

        return 0;
      }

      LSM_PROBE(kernel_read_file, struct file *file, int id, int contents)
      {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;

        if (!target_enabled(pid, tid)) {
          return 0;
        }

        struct event_t ev = {};
        u32 id32 = id;
        u32 contents32 = contents;

        ev.pid = pid;
        __builtin_memcpy(ev.event_name, "kernel_read_file", 16);
        __builtin_memcpy(&ev.payload[0], &id32, sizeof(id32));
        __builtin_memcpy(&ev.payload[4], &contents32, sizeof(contents32));
        submit_event(&ev);

        return 0;
      }

      LSM_PROBE(task_kill, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred)
      {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;

        if (!target_enabled(pid, tid)) {
          return 0;
        }

        struct event_t ev = {};

        ev.pid = pid;
        __builtin_memcpy(ev.event_name, "task_kill", 10);
        __builtin_memcpy(&ev.payload[0], &sig, sizeof(sig));
        submit_event(&ev);

        return 0;
      }

      LSM_PROBE(task_fix_setuid, struct cred *new, const struct cred *old, int flags)
      {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;

        if (!target_enabled(pid, tid)) {
          return 0;
        }

        struct event_t ev = {};
        u32 flags32 = flags;

        ev.pid = pid;
        __builtin_memcpy(ev.event_name, "setid_change", 13);
        __builtin_memcpy(&ev.payload[0], &flags32, sizeof(flags32));
        submit_event(&ev);

        return 0;
      }

      LSM_PROBE(capable, const struct cred *cred, struct user_namespace *targ_ns, int cap, unsigned int opts)
      {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;

        if (!target_enabled(pid, tid)) {
          return 0;
        }

        if (!monitored_capability(cap)) {
          return 0;
        }

        struct event_t ev = {};
        u32 cap32 = cap;
        u32 opts32 = opts;

        ev.pid = pid;
        __builtin_memcpy(ev.event_name, "capable_check", 14);
        __builtin_memcpy(&ev.payload[0], &cap32, sizeof(cap32));
        __builtin_memcpy(&ev.payload[4], &opts32, sizeof(opts32));
        submit_event(&ev);

        return 0;
      }

      LSM_PROBE(bprm_creds_from_file, struct linux_binprm *bprm, struct file *file)
      {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;

        if (!target_enabled(pid, tid)) {
          return 0;
        }

        struct event_t ev = {};
        u8 has_file = 0;

        ev.pid = pid;
        __builtin_memcpy(ev.event_name, "bprm_creds", 11);

        if (file) {
          has_file = 1;
          bpf_d_path(&file->f_path, &ev.payload[1], sizeof(ev.payload) - 1);
        }

        __builtin_memcpy(&ev.payload[0], &has_file, sizeof(has_file));
        submit_event(&ev);

        return 0;
      }

      LSM_PROBE(inode_symlink, struct inode *dir, struct dentry *dentry, const char *oldname)
      {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;

        if (!target_enabled(pid, tid)) {
          return 0;
        }

        struct event_t ev = {};
        ev.pid = pid;
        __builtin_memcpy(ev.event_name, "file_symlink", 13);

        if (oldname) {
          bpf_probe_read_user_str(&ev.payload[0], 128, oldname);
        }

        if (dentry) {
          read_dentry_name(dentry, &ev.payload[128], 128);
        }

        submit_event(&ev);
        return 0;
      }

      LSM_PROBE(inode_link, struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
      {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;

        if (!target_enabled(pid, tid)) {
          return 0;
        }

        struct event_t ev = {};
        ev.pid = pid;
        __builtin_memcpy(ev.event_name, "file_hardlink", 14);

        if (old_dentry) {
          read_dentry_name(old_dentry, &ev.payload[0], 128);
        }

        if (new_dentry) {
          read_dentry_name(new_dentry, &ev.payload[128], 128);
        }

        submit_event(&ev);
        return 0;
      }

      LSM_PROBE(inode_rename, struct inode *old_dir, struct dentry *old_dentry, 
                struct inode *new_dir, struct dentry *new_dentry, unsigned int flags)
      {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;

        if (!target_enabled(pid, tid)) {
          return 0;
        }

        struct event_t ev = {};
        ev.pid = pid;
        __builtin_memcpy(ev.event_name, "file_rename", 12);

        if (old_dentry) {
          read_dentry_name(old_dentry, &ev.payload[0], 128);
        }

        if (new_dentry) {
          read_dentry_name(new_dentry, &ev.payload[128], 128);
        }

        submit_event(&ev);
        return 0;
      }

      LSM_PROBE(path_chmod, struct path *path, umode_t mode)
      {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;

        if (!target_enabled(pid, tid)) {
          return 0;
        }

        if (!path) {
          return 0;
        }

        struct event_t ev = {};
        u16 mode_short = mode & 0xFFFF;
        ev.pid = pid;
        __builtin_memcpy(ev.event_name, "file_chmod", 11);
        __builtin_memcpy(&ev.payload[0], &mode_short, sizeof(mode_short));

        bpf_d_path(path, &ev.payload[2], sizeof(ev.payload) - 2);
        submit_event(&ev);
        return 0;
      }

      TRACEPOINT_PROBE(syscalls, sys_enter_getdents64)
      {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;

        if (!target_enabled(pid, tid)) {
          return 0;
        }

        struct event_t ev = {};
        u32 fd = args->fd;
        u32 count = args->count;

        ev.pid = pid;
        __builtin_memcpy(ev.event_name, "file_getdents", 14);
        __builtin_memcpy(&ev.payload[0], &fd, sizeof(fd));
        __builtin_memcpy(&ev.payload[4], &count, sizeof(count));

        submit_event(&ev);
        return 0;
      }

      int on_span_start(struct pt_regs *ctx)
      {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;

        if (!target_enabled(pid, tid)) {
          return 0;
        }

        u64 method_id = 0;
        u64 file_id = 0;
        u64 lineno = 0;
        bpf_usdt_readarg(1, ctx, &method_id);
        bpf_usdt_readarg(2, ctx, &file_id);
        bpf_usdt_readarg(3, ctx, &lineno);

        struct event_t ev = {};
        ev.pid = pid;
        __builtin_memcpy(ev.event_name, "span_start", 11);
        __builtin_memcpy(&ev.payload[0], &method_id, sizeof(method_id));
        __builtin_memcpy(&ev.payload[8], &file_id, sizeof(file_id));
        __builtin_memcpy(&ev.payload[16], &lineno, sizeof(lineno));
        submit_event(&ev);
        return 0;
      }

      int on_span_stop(struct pt_regs *ctx)
      {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;

        if (!target_enabled(pid, tid)) {
          return 0;
        }

        u64 method_id = 0;
        u64 file_id = 0;
        u64 lineno = 0;
        bpf_usdt_readarg(1, ctx, &method_id);
        bpf_usdt_readarg(2, ctx, &file_id);
        bpf_usdt_readarg(3, ctx, &lineno);

        struct event_t ev = {};
        ev.pid = pid;
        __builtin_memcpy(ev.event_name, "span_stop", 10);
        __builtin_memcpy(&ev.payload[0], &method_id, sizeof(method_id));
        __builtin_memcpy(&ev.payload[8], &file_id, sizeof(file_id));
        __builtin_memcpy(&ev.payload[16], &lineno, sizeof(lineno));
        submit_event(&ev);
        return 0;
      }

      int on_ssl_write(struct pt_regs *ctx)
      {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;

        if (!target_enabled(pid, tid)) {
          return 0;
        }

        const char *buf = (const char *)PT_REGS_PARM2(ctx);
        int num = (int)PT_REGS_PARM3(ctx);
        if (!buf || num <= 0) {
          return 0;
        }

        struct event_t ev = {};
        ev.pid = pid;
        __builtin_memcpy(ev.event_name, "ssl_write", 10);

        u32 data_len = (u32)num;
        u32 cap = data_len;
        if (cap > #{SSL_WRITE_PAYLOAD_DATA_MAX}) {
          cap = #{SSL_WRITE_PAYLOAD_DATA_MAX};
        }
        __builtin_memcpy(&ev.payload[#{SSL_WRITE_PAYLOAD_DATA_LEN_OFFSET}], &data_len, sizeof(data_len));
        __builtin_memcpy(&ev.payload[#{SSL_WRITE_PAYLOAD_CAP_LEN_OFFSET}], &cap, sizeof(cap));
        if (bpf_probe_read_user(&ev.payload[#{SSL_WRITE_PAYLOAD_DATA_OFFSET}], cap, buf) < 0) {
          u32 zero = 0;
          __builtin_memcpy(&ev.payload[#{SSL_WRITE_PAYLOAD_CAP_LEN_OFFSET}], &zero, sizeof(zero));
        }

        submit_event(&ev);
        return 0;
      }

      int on_span_raise(struct pt_regs *ctx)
      {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;

        if (!target_enabled(pid, tid)) {
          return 0;
        }

        u64 error_id = 0;
        u64 message_id = 0;
        u64 file_id = 0;
        u64 lineno = 0;
        bpf_usdt_readarg(1, ctx, &error_id);
        bpf_usdt_readarg(2, ctx, &message_id);
        bpf_usdt_readarg(3, ctx, &file_id);
        bpf_usdt_readarg(4, ctx, &lineno);

        struct event_t ev = {};
        ev.pid = pid;
        __builtin_memcpy(ev.event_name, "span_raise", 11);
        __builtin_memcpy(&ev.payload[0], &error_id, sizeof(error_id));
        __builtin_memcpy(&ev.payload[8], &message_id, sizeof(message_id));
        __builtin_memcpy(&ev.payload[16], &file_id, sizeof(file_id));
        __builtin_memcpy(&ev.payload[24], &lineno, sizeof(lineno));
        submit_event(&ev);
        return 0;
      }
    CLANG

    def initialize(pin_dir: Vivarium.bpf_pin_dir, ssl_trace: true, libssl_path: nil)
      @pin_dir = pin_dir
      @ssl_trace = ssl_trace
      @libssl_path = libssl_path
    end

    def run
      ensure_root!
      FileUtils.mkdir_p(@pin_dir)

      f_path_offset = detect_f_path_offset
      d_name_offset = detect_dentry_d_name_offset
      program = BPF_PROGRAM_TEMPLATE
        .gsub("__VIVARIUM_F_PATH_OFFSET__", f_path_offset.to_s)
        .gsub("__VIVARIUM_DENTRY_D_NAME_OFFSET__", d_name_offset.to_s)

      usdt_so_path = ENV.fetch("VIVARIUM_USDT_SO_PATH") { Vivarium.locate_vivarium_usdt_so }
      usdt = RbBCC::USDT.new(path: usdt_so_path)
      usdt.enable_probe(probe: "start_probe", fn_name: "on_span_start")
      usdt.enable_probe(probe: "stop_probe", fn_name: "on_span_stop")
      usdt.enable_probe(probe: "raise_probe", fn_name: "on_span_raise")

      bpf = RbBCC::BCC.new(text: program, usdt_contexts: [usdt])

      attach_ssl_write_uprobe(bpf) if @ssl_trace

      config_root_targets = bpf["config_root_targets"]
      config_spawned_targets = bpf["config_spawned_targets"]
      events_ringbuf = bpf["events"]

      config_spawned_targets.clear

      pin_map(config_root_targets, File.join(@pin_dir, "config_root_targets"))
      pin_map(config_spawned_targets, File.join(@pin_dir, "config_spawned_targets"))
      pin_map(events_ringbuf, File.join(@pin_dir, "events"))

      puts "[vivariumd] started"
      puts "[vivariumd] pinned maps in #{@pin_dir}"
      puts "[vivariumd] watching LSM file_open (f_path offset=#{f_path_offset})"
      puts "[vivariumd] USDT attached via #{usdt_so_path}"

      loop do
        sleep 1
      end
    rescue Interrupt
      puts "\n[vivariumd] stopping"
    end

    private

    def attach_ssl_write_uprobe(bpf)
      path = resolve_libssl_path
      unless path
        warn "[vivariumd] libssl not found; SSL_write uprobe disabled " \
             "(set --libssl PATH or VIVARIUM_LIBSSL_PATH to override)"
        return
      end

      bpf.attach_uprobe(name: path, sym: "SSL_write", fn_name: "on_ssl_write")
      puts "[vivariumd] SSL_write uprobe attached via #{path}"
    rescue StandardError => e
      warn "[vivariumd] SSL_write uprobe attach failed: #{e.class}: #{e.message}"
    end

    def resolve_libssl_path
      if @libssl_path
        return @libssl_path if File.exist?(@libssl_path)

        warn "[vivariumd] --libssl path does not exist: #{@libssl_path}"
        return nil
      end

      env_path = ENV["VIVARIUM_LIBSSL_PATH"]
      if env_path && !env_path.empty?
        return env_path if File.exist?(env_path)

        warn "[vivariumd] VIVARIUM_LIBSSL_PATH does not exist: #{env_path}"
        return nil
      end

      LIBSSL_SEARCH_PATHS.find { |p| File.exist?(p) }
    end

    def ensure_root!
      return if Process.uid.zero?

      raise Error, "vivariumd requires root privileges"
    end

    def pin_map(table, path)
      File.unlink(path) if File.exist?(path)
      RbBCC::BCC.pin!(table.map_fd, path)
    end

    def detect_f_path_offset
      env_offset = ENV["VIVARIUM_FILE_F_PATH_OFFSET"]
      return Integer(env_offset, 10) if env_offset

      raw = IO.popen(
        %w[bpftool btf dump file /sys/kernel/btf/vmlinux format raw],
        err: IO::NULL,
        &:read
      )

      in_file_struct = false
      f_path_bits_offset = nil
      anon_union_bits_offset = nil

      raw.each_line do |line|
        if line =~ /^\[\d+\] STRUCT 'file' /
          in_file_struct = true
          next
        end

        if in_file_struct && line.start_with?("[")
          break
        end

        next unless in_file_struct

        if (match = line.match(/'f_path'.*bits_offset=(\d+)/))
          f_path_bits_offset = Integer(match[1], 10)
          next
        end

        if (match = line.match(/'\(anon\)'.*bits_offset=(\d+)/))
          anon_union_bits_offset = Integer(match[1], 10)
        end
      end

      if f_path_bits_offset && anon_union_bits_offset && f_path_bits_offset != anon_union_bits_offset
        warn "[vivariumd] BTF offset mismatch: f_path=#{f_path_bits_offset / 8}, (anon)=#{anon_union_bits_offset / 8}; preferring (anon)"
      end

      bits_offset = anon_union_bits_offset || f_path_bits_offset
      if bits_offset
        if (bits_offset % 8).positive?
          raise Error, "unsupported f_path bits offset=#{bits_offset}"
        end

        if bits_offset >= 1024
          warn "[vivariumd] suspicious f_path offset=#{bits_offset / 8}, fallback to offset=64"
          return 64
        end

        return bits_offset / 8
      end

      warn "[vivariumd] could not find struct file::f_path in BTF, fallback to offset=64"
      64
    rescue Errno::ENOENT
      raise Error, "bpftool is required to resolve struct file::f_path offset"
    end

    def detect_dentry_d_name_offset
      env_offset = ENV["VIVARIUM_DENTRY_D_NAME_OFFSET"]
      return Integer(env_offset, 10) if env_offset

      raw = IO.popen(
        %w[bpftool btf dump file /sys/kernel/btf/vmlinux format raw],
        err: IO::NULL,
        &:read
      )

      in_dentry_struct = false
      d_name_bits_offset = nil

      raw.each_line do |line|
        if line =~ /^\[\d+\] STRUCT 'dentry' /
          in_dentry_struct = true
          next
        end

        if in_dentry_struct && line.start_with?("[")
          break
        end

        next unless in_dentry_struct

        if (match = line.match(/'d_name'.*bits_offset=(\d+)/))
          d_name_bits_offset = Integer(match[1], 10)
          break
        end
      end

      if d_name_bits_offset
        if (d_name_bits_offset % 8).positive?
          raise Error, "unsupported d_name bits offset=#{d_name_bits_offset}"
        end

        if d_name_bits_offset >= 1024
          warn "[vivariumd] suspicious d_name offset=#{d_name_bits_offset / 8}, fallback to offset=32"
          return 32
        end

        return d_name_bits_offset / 8
      end

      warn "[vivariumd] could not find struct dentry::d_name in BTF, fallback to offset=32"
      32
    rescue Errno::ENOENT
      raise Error, "bpftool is required to resolve struct dentry::d_name offset"
    end
  end

  class ObservationSession
    def initialize(store:, pid:, tracer:, correlator:)
      @store = store
      @pid = pid
      @tracer = tracer
      @correlator = correlator
      @stopped = false
    end

    def stop
      return if @stopped

      @stopped = true
      @tracer.disable
      @store.unregister_pid(@pid)
      @correlator.stop
    end
  end

  def self.observe(pin_dir: bpf_pin_dir, dest: $stdout, filter: nil, &block)
    return scoped_observe(pin_dir: pin_dir, dest: dest, filter: filter, &block) if block_given?

    top_observe(pin_dir: pin_dir, dest: dest, filter: filter)
  end

  def self.top_observe(pin_dir: bpf_pin_dir, dest: $stdout, filter: nil)
    require "vivarium_usdt"

    store = MapStore.new(pin_dir: pin_dir)
    pid = Process.pid
    store.register_pid(pid)

    method_id_queue = Thread::Queue.new
    main_tid = gettid

    correlator = Correlator.new(
      pin_dir: pin_dir,
      observer_pid: pid,
      main_tid: main_tid,
      method_id_queue: method_id_queue,
      filter: filter,
      dest: dest
    )
    correlator.start

    tracer = build_observe_tracepoint(method_id_queue)
    tracer.enable

    session = ObservationSession.new(
      store: store, pid: pid, tracer: tracer, correlator: correlator
    )
    at_exit { session.stop }
    session
  end

  def self.scoped_observe(pin_dir:, dest:, filter: nil)
    require "vivarium_usdt"

    store = MapStore.new(pin_dir: pin_dir)
    pid = Process.pid
    store.register_pid(pid)

    method_id_queue = Thread::Queue.new
    main_tid = gettid

    correlator = Correlator.new(
      pin_dir: pin_dir,
      observer_pid: pid,
      main_tid: main_tid,
      method_id_queue: method_id_queue,
      filter: filter,
      dest: dest
    )
    correlator.start

    tracer = build_observe_tracepoint(method_id_queue)
    tracer.enable

    yield
  ensure
    tracer&.disable
    store&.unregister_pid(pid)
    correlator&.stop
  end

  def self.build_observe_tracepoint(method_id_queue)
    allow_classes = SPAN_ALLOWCLASSES
    allowlist = SPAN_ALLOWLIST
    TracePoint.new(:call, :c_call, :return, :c_return, :raise) do |tp|
      if tp.event == :raise
        # FIXME: handle threaded events in the future
        if tp.raised_exception.kind_of?(ThreadError)
          next
        end

        Vivarium::Usdt.raise(
          tp.raised_exception.class.to_s,
          tp.raised_exception.message.to_s,
          file: tp.path,
          lineno: tp.lineno
        )
        next
      end

      signature = "#{tp.defined_class}##{tp.method_id}"
      is_target = allowlist.include?(signature) || \
        allow_classes.any? { |klass| tp.defined_class == klass } || \
        allow_classes.any? { |klass| tp.defined_class == klass.singleton_class }
      next unless is_target

      case tp.event
      when :call, :c_call
        method_id = Vivarium::Usdt.start(tp.defined_class.to_s, tp.method_id.to_s, file: tp.path, lineno: tp.lineno)
        method_id_queue << [method_id, signature]
      when :return, :c_return
        Vivarium::Usdt.stop(tp.defined_class.to_s, tp.method_id.to_s, file: tp.path, lineno: tp.lineno)
      end
    end
  end

  def self.gettid
    @gettid_func ||= begin
      libc = Fiddle.dlopen("libc.so.6")
      Fiddle::Function.new(libc["gettid"], [], Fiddle::TYPE_INT)
    rescue Fiddle::DLError
      libc = Fiddle.dlopen(nil)
      Fiddle::Function.new(libc["gettid"], [], Fiddle::TYPE_INT)
    end
    @gettid_func.call
  end

  def self.monotonic_ktime_ns
    Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
  end

  def self.locate_vivarium_usdt_so
    require "vivarium_usdt/vivarium_usdt"
    so = $LOADED_FEATURES.find { |p| p =~ %r{vivarium_usdt/vivarium_usdt\.(so|bundle|dylib)\z} }
    raise Error, "vivarium_usdt native extension not found in $LOADED_FEATURES" unless so

    File.realpath(so)
  rescue LoadError => e
    raise Error, "failed to load vivarium_usdt: #{e.message}"
  end

  def self.run_daemon!(argv = ARGV)
    options = { pin_dir: bpf_pin_dir, ssl_trace: true, libssl_path: nil }
    OptionParser.new do |opts|
      opts.banner = "Usage: vivariumd [--pin-dir PATH] [--no-ssl-trace] [--libssl PATH]"
      opts.on("--pin-dir PATH", "Pinned map directory") { |v| options[:pin_dir] = v }
      opts.on("--[no-]ssl-trace", "Attach OpenSSL SSL_write uprobe (default: enabled)") do |v|
        options[:ssl_trace] = v
      end
      opts.on("--libssl PATH", "Path to libssl.so to attach SSL_write to") do |v|
        options[:libssl_path] = v
      end
    end.parse!(argv)

    Daemon.new(
      pin_dir: options[:pin_dir],
      ssl_trace: options[:ssl_trace],
      libssl_path: options[:libssl_path]
    ).run
  end
end

require_relative "vivarium/correlator"
require_relative "vivarium/display_filter"
require_relative "vivarium/tree_renderer"
