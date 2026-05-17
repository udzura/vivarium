# frozen_string_literal: true

require "fiddle"
require "fileutils"
require "optparse"
require "pathname"
require "rbbcc"
require "socket"
require_relative "vivarium/version"
require_relative "vivarium/logger"

module Vivarium
  class Error < StandardError; end

  PIN_DIR = ENV.fetch("VIVARIUM_BPF_PIN_DIR", "/sys/fs/bpf/vivarium")
  CONFIG_ROOT_TARGETS_PIN = File.join(PIN_DIR, "config_root_targets")
  CONFIG_SPAWNED_TARGETS_PIN = File.join(PIN_DIR, "config_spawned_targets")
  CONFIG_TARGETS_PIN = CONFIG_ROOT_TARGETS_PIN
  EVENT_INVOKED_PIN = File.join(PIN_DIR, "event_invoked")
  EVENT_WRITE_POS_PIN = File.join(PIN_DIR, "event_write_pos")

  EVENT_NAME_SIZE = 16
  EVENT_PAYLOAD_SIZE = 256
  EVENT_TS_SIZE = 8
  EVENT_STRUCT_SIZE = 288
  EVENT_TS_OFFSET = 0
  EVENT_PID_OFFSET = 8
  EVENT_NAME_OFFSET = 12
  EVENT_PAYLOAD_OFFSET = 28
  EVENT_CAPACITY = 1024

  @bpf_pin_dir = PIN_DIR

  class << self
    attr_writer :bpf_pin_dir

    def bpf_pin_dir
      @bpf_pin_dir || PIN_DIR
    end
  end

  Event = Struct.new(:ktime_ns, :pid, :event_name, :payload, keyword_init: true) do
    def empty?
      ktime_ns.to_i.zero? && pid.to_i.zero? && event_name.to_s.empty? && payload.to_s.empty?
    end

    def self.from_binary(raw)
      bytes = raw.to_s.b
      bytes = bytes.ljust(EVENT_STRUCT_SIZE, "\x00")

      ktime_ns = bytes[EVENT_TS_OFFSET, EVENT_TS_SIZE].unpack1("Q<")
      pid = bytes[EVENT_PID_OFFSET, 4].unpack1("L<")
      event_name = c_string(bytes[EVENT_NAME_OFFSET, EVENT_NAME_SIZE])
      raw_payload = bytes[EVENT_PAYLOAD_OFFSET, EVENT_PAYLOAD_SIZE]
      payload = if %w[dns_req sock_connect odd_socket].include?(event_name)
                  raw_payload
                else
                  c_string(raw_payload)
                end

      new(ktime_ns: ktime_ns, pid: pid, event_name: event_name, payload: payload)
    end

    def self.c_string(bytes)
      str = bytes.to_s.b
      nul = str.index("\x00")
      return str if nul.nil?

      str[0, nul]
    end
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
    else
      event.payload.inspect
    end
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
      @event_invoked = RbBCC::ArrayTable.from_pin(
        File.join(@pin_dir, "event_invoked"),
        "unsigned int",
        "char[#{EVENT_STRUCT_SIZE}]",
        keysize: 4,
        leafsize: EVENT_STRUCT_SIZE
      )
      @event_write_pos = RbBCC::ArrayTable.from_pin(
        File.join(@pin_dir, "event_write_pos"),
        "unsigned int",
        "unsigned int",
        keysize: 4,
        leafsize: 4
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

    def drain_events
      events = []
      EVENT_CAPACITY.times do |idx|
        ptr = @event_invoked[idx]
        next unless ptr

        event = Event.from_binary(ptr[0, EVENT_STRUCT_SIZE])
        next if event.empty?

        events << event
        @event_invoked[idx] = zeroed_event_ptr
      end

      @event_write_pos[0] = 0
      events
    end

    private

    def zeroed_event_ptr
      ptr = Fiddle::Pointer.malloc(EVENT_STRUCT_SIZE)
      ptr[0, EVENT_STRUCT_SIZE] = "\x00" * EVENT_STRUCT_SIZE
      ptr
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

      struct path {
        void *mnt;
        void *dentry;
      };
      struct file {
        char __off[__VIVARIUM_F_PATH_OFFSET__];
        struct path f_path;
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
        char event_name[16];
        char payload[#{EVENT_PAYLOAD_SIZE}];
      };

      BPF_HASH(config_root_targets, u32, u8, 1024);
      BPF_HASH(config_spawned_targets, u32, u8, 8192);
      BPF_HASH(dns_connected_tids, u32, u8, 8192);
      BPF_ARRAY(event_invoked, struct event_t, #{EVENT_CAPACITY});
      BPF_ARRAY(event_write_pos, u32, 1);

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

      static __always_inline void submit_event(struct event_t *ev)
      {
        u32 zero = 0;
        u32 *write_pos = event_write_pos.lookup(&zero);
        if (!write_pos) {
          return;
        }

        ev->ktime_ns = bpf_ktime_get_ns();

        u32 idx = *write_pos % #{EVENT_CAPACITY};
        __sync_fetch_and_add(write_pos, 1);
        event_invoked.update(&idx, ev);
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

      TRACEPOINT_PROBE(sched, sched_process_fork)
      {
        u32 parent = args->parent_pid;
        u32 child = args->child_pid;
        u8 one = 1;

        u8 *enabled_root = config_root_targets.lookup(&parent);
        if (enabled_root && *enabled_root == 1) {
          config_spawned_targets.update(&child, &one);
          return 0;
        }

        u8 *enabled_spawned = config_spawned_targets.lookup(&parent);
        if (enabled_spawned && *enabled_spawned == 1) {
          config_spawned_targets.update(&child, &one);
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
        bpf_trace_printk("vivarium: invoked pid=%d\\n", pid);
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
            bpf_trace_printk("vivarium: failed to obtain full path. pid=%d path=%s\\n", pid, ev.payload);
          }
        }

        bpf_trace_printk("vivarium: pid=%d path=%s\\n", pid, ev.payload);
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
    CLANG

    def initialize(pin_dir: Vivarium.bpf_pin_dir)
      @pin_dir = pin_dir
    end

    def run
      ensure_root!
      FileUtils.mkdir_p(@pin_dir)

      f_path_offset = detect_f_path_offset
      program = BPF_PROGRAM_TEMPLATE.gsub("__VIVARIUM_F_PATH_OFFSET__", f_path_offset.to_s)

      bpf = RbBCC::BCC.new(text: program)
      kprint_thread = start_kprint_logger(bpf)

      config_root_targets = bpf["config_root_targets"]
      config_spawned_targets = bpf["config_spawned_targets"]
      event_invoked = bpf["event_invoked"]
      event_write_pos = bpf["event_write_pos"]

      clear_event_slots(event_invoked)
      event_write_pos[0] = 0
      config_spawned_targets.clear

      pin_map(config_root_targets, File.join(@pin_dir, "config_root_targets"))
      pin_map(config_spawned_targets, File.join(@pin_dir, "config_spawned_targets"))
      pin_map(event_invoked, File.join(@pin_dir, "event_invoked"))
      pin_map(event_write_pos, File.join(@pin_dir, "event_write_pos"))

      puts "[vivariumd] started"
      puts "[vivariumd] pinned maps in #{@pin_dir}"
      puts "[vivariumd] watching LSM file_open (f_path offset=#{f_path_offset})"
      puts "[vivariumd] kprint logger enabled"

      loop do
        sleep 1
      end
    rescue Interrupt
      puts "\n[vivariumd] stopping"
    ensure
      if kprint_thread
        kprint_thread.kill
        kprint_thread.join(0.2)
      end
    end

    private

    def ensure_root!
      return if Process.uid.zero?

      raise Error, "vivariumd requires root privileges"
    end

    def pin_map(table, path)
      File.unlink(path) if File.exist?(path)
      RbBCC::BCC.pin!(table.map_fd, path)
    end

    def clear_event_slots(table)
      ptr = Fiddle::Pointer.malloc(EVENT_STRUCT_SIZE)
      ptr[0, EVENT_STRUCT_SIZE] = "\x00" * EVENT_STRUCT_SIZE
      EVENT_CAPACITY.times do |idx|
        table[idx] = ptr
      end
    end

    def start_kprint_logger(bpf)
      Thread.new do
        begin
          bpf.trace_fields do |_task, pid, _cpu, _flags, ts, msg|
            line = msg.to_s.strip
            next unless line.start_with?("vivarium:")

            puts "[vivariumd:kprint #{ts} pid=#{pid}] #{line}"
          end
        rescue IOError, Errno::EINTR
          nil
        rescue StandardError => e
          warn "[vivariumd] kprint stream stopped: #{e.class}: #{e.message}"
        end
      end
    rescue StandardError => e
      warn "[vivariumd] failed to start kprint logger: #{e.class}: #{e.message}"
      nil
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
  end

  class ObservationSession
    def initialize(store:, pid:, tracer:)
      @store = store
      @pid = pid
      @tracer = tracer
      @stopped = false
    end

    def stop
      return if @stopped

      @tracer.disable
      @store.unregister_pid(@pid)
      @stopped = true
    end
  end

  def self.observe(pin_dir: bpf_pin_dir, logger: nil, dest: $stdout, format: :human)
    return scoped_observe(pin_dir: pin_dir, logger: logger, dest: dest, format: format) { yield } if block_given?

    top_observe(pin_dir: pin_dir, logger: logger, dest: dest, format: format)
  end

  def self.top_observe(pin_dir: bpf_pin_dir, logger: nil, dest: $stdout, format: :human)
    logger ||= Logger.new(dest: dest, format: format)
    store = MapStore.new(pin_dir: pin_dir)
    pid = Process.pid
    store.register_pid(pid)
    logger.info("top-level observing with pid=#{pid}")

    tracer = build_observe_tracepoint(store, logger)
    tracer.enable

    session = ObservationSession.new(store: store, pid: pid, tracer: tracer)
    at_exit { session.stop }
    session
  end

  def self.scoped_observe(pin_dir:, logger:, dest:, format:)
    logger ||= Logger.new(dest: dest, format: format)
    store = MapStore.new(pin_dir: pin_dir)
    pid = Process.pid
    store.register_pid(pid)
    logger.info("scoped observing with pid=#{pid}")

    tracer = build_observe_tracepoint(store, logger)
    tracer.enable

    yield
  ensure
    tracer&.disable
    store&.unregister_pid(pid)
  end

  def self.build_observe_tracepoint(store, logger)
    TracePoint.new(:return, :c_return) do |tp|
      events = store.drain_events
      next if events.empty?

      stack = caller_locations(2, 16)
      stack = stack.reject { |loc| loc.path.to_s.include?("vivarium") } if filter_internal_frames?
      logger.log(events, tp, stack)
    end
  end

  def self.filter_internal_frames?
    value = ENV["VIVARIUM_FILTER_INTERNAL_FRAMES"]
    return true if value.nil?

    !%w[0 false off no].include?(value.strip.downcase)
  end

  def self.run_daemon!(argv = ARGV)
    options = { pin_dir: bpf_pin_dir }
    OptionParser.new do |opts|
      opts.banner = "Usage: vivariumd [--pin-dir PATH]"
      opts.on("--pin-dir PATH", "Pinned map directory") { |v| options[:pin_dir] = v }
    end.parse!(argv)

    Daemon.new(pin_dir: options[:pin_dir]).run
  end
end
