# frozen_string_literal: true

require "fiddle"
require "fileutils"
require "optparse"
require "pathname"
require "rbbcc"
require_relative "vivarium/version"

module Vivarium
  class Error < StandardError; end

  PIN_DIR = ENV.fetch("VIVARIUM_BPF_PIN_DIR", "/sys/fs/bpf/vivarium")
  CONFIG_TARGETS_PIN = File.join(PIN_DIR, "config_targets")
  EVENT_INVOKED_PIN = File.join(PIN_DIR, "event_invoked")
  EVENT_WRITE_POS_PIN = File.join(PIN_DIR, "event_write_pos")

  EVENT_NAME_SIZE = 8
  EVENT_PAYLOAD_SIZE = 64
  EVENT_STRUCT_SIZE = 4 + EVENT_NAME_SIZE + EVENT_PAYLOAD_SIZE
  EVENT_CAPACITY = 64

  Event = Struct.new(:pid, :event_name, :payload, keyword_init: true) do
    def empty?
      pid.to_i.zero? && event_name.to_s.empty? && payload.to_s.empty?
    end

    def self.from_binary(raw)
      bytes = raw.to_s.b
      bytes = bytes.ljust(EVENT_STRUCT_SIZE, "\x00")

      pid = bytes[0, 4].unpack1("L<")
      event_name = bytes[4, EVENT_NAME_SIZE].delete("\x00")
      payload = bytes[4 + EVENT_NAME_SIZE, EVENT_PAYLOAD_SIZE].delete("\x00")

      new(pid: pid, event_name: event_name, payload: payload)
    end
  end

  class MapStore
    def initialize(pin_dir: PIN_DIR)
      @pin_dir = pin_dir
      @config_targets = RbBCC::HashTable.from_pin(
        File.join(@pin_dir, "config_targets"),
        "unsigned int",
        "unsigned char",
        keysize: 4,
        leafsize: 1
      )
      @event_invoked = RbBCC::ArrayTable.from_pin(
        File.join(@pin_dir, "event_invoked"),
        "unsigned int",
        "char[76]",
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
      @config_targets[pid] = 1
    end

    def unregister_pid(pid)
      @config_targets.delete(pid)
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
    BPF_PROGRAM = <<~CLANG
      #include <linux/fs.h>
      #include <linux/dcache.h>

      struct event_t {
        u32 pid;
        char event_name[8];
        char payload[64];
      };

      BPF_HASH(config_targets, u32, u8, 1024);
      BPF_ARRAY(event_invoked, struct event_t, 64);
      BPF_ARRAY(event_write_pos, u32, 1);

      static __always_inline int target_enabled(u32 pid)
      {
        u8 *enabled = config_targets.lookup(&pid);
        if (!enabled) {
          return 0;
        }
        return *enabled == 1;
      }

      LSM_PROBE(file_open, struct file *file)
      {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        if (!target_enabled(pid)) {
          return 0;
        }

        u32 zero = 0;
        u32 *write_pos = event_write_pos.lookup(&zero);
        if (!write_pos) {
          return 0;
        }

        u32 idx = __sync_fetch_and_add(write_pos, 1) & 63;
        struct event_t ev = {};
        ev.pid = pid;
        __builtin_memcpy(ev.event_name, "path_open", 8);
        bpf_d_path(&file->f_path, ev.payload, sizeof(ev.payload));
        event_invoked.update(&idx, &ev);

        return 0;
      }
    CLANG

    def initialize(pin_dir: PIN_DIR)
      @pin_dir = pin_dir
    end

    def run
      ensure_root!
      FileUtils.mkdir_p(@pin_dir)

      bpf = RbBCC::BCC.new(text: BPF_PROGRAM)
      bpf.attach_lsm(fn_name: "lsm__file_open")

      config_targets = bpf["config_targets"]
      event_invoked = bpf["event_invoked"]
      event_write_pos = bpf["event_write_pos"]

      clear_event_slots(event_invoked)
      event_write_pos[0] = 0

      pin_map(config_targets, File.join(@pin_dir, "config_targets"))
      pin_map(event_invoked, File.join(@pin_dir, "event_invoked"))
      pin_map(event_write_pos, File.join(@pin_dir, "event_write_pos"))

      puts "[vivariumd] started"
      puts "[vivariumd] pinned maps in #{@pin_dir}"
      puts "[vivariumd] watching LSM file_open"

      loop do
        sleep 1
      end
    rescue Interrupt
      puts "\n[vivariumd] stopping"
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
  end

  def self.observe(pin_dir: PIN_DIR, out: $stdout)
    raise ArgumentError, "block is required" unless block_given?

    store = MapStore.new(pin_dir: pin_dir)
    pid = Process.pid
    store.register_pid(pid)

    tracer = TracePoint.new(:return, :c_return) do |tp|
      events = store.drain_events
      next if events.empty?

      out.puts "[vivarium] #{events.size} event(s) at #{tp.defined_class}##{tp.method_id} (#{tp.event})"
      events.each do |event|
        out.puts "  pid=#{event.pid} #{event.event_name} payload=#{event.payload.inspect}"
      end
      out.puts "  stack:"
      caller_locations(0, 12).each do |loc|
        out.puts "    #{loc.path}:#{loc.lineno}:in #{loc.base_label}"
      end
    end

    tracer.enable
    yield
  ensure
    tracer&.disable
    store&.unregister_pid(pid)
  end

  def self.run_daemon!(argv = ARGV)
    options = { pin_dir: PIN_DIR }
    OptionParser.new do |opts|
      opts.banner = "Usage: vivariumd [--pin-dir PATH]"
      opts.on("--pin-dir PATH", "Pinned map directory") { |v| options[:pin_dir] = v }
    end.parse!(argv)

    Daemon.new(pin_dir: options[:pin_dir]).run
  end
end
