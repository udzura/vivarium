# frozen_string_literal: true

require "rbbcc"
require "time"

module Vivarium
  class Correlator
    RawEvent = Struct.new(
      :ktime_ns, :pid, :tid, :event_name, :payload,
      keyword_init: true
    )

    EVENT_C_TYPE = <<~C
      struct event_t {
        u64 ktime_ns;
        u32 pid;
        u32 tid;
        char event_name[16];
        char payload[256];
      };
    C

    POLL_TIMEOUT_MS = 200

    def initialize(pin_dir:, observer_pid:, main_tid:, method_id_queue:, filter: nil, dest: $stdout)
      @pin_dir = pin_dir
      @observer_pid = observer_pid
      @main_tid = main_tid
      @method_id_queue = method_id_queue
      @filter = filter
      @dest = dest

      @events = []
      @events_mutex = Mutex.new
      @method_table = {}
      @stop_flag = false
      @started = false

      @ringbuf = RbBCC::RingBuf.from_pin(
        File.join(@pin_dir, "events"),
        EVENT_C_TYPE,
        Vivarium::EVENTS_RINGBUF_PAGES
      )
      @ringbuf.open_ring_buffer do |_ctx, data, size|
        capture_event(data, size)
      end
    end

    def start
      return if @started

      @session_start_iso = Time.now.utc.iso8601(3)
      @session_start_ktime = Vivarium.monotonic_ktime_ns
      @thread = Thread.new { run }
      @started = true
    end

    def stop
      return unless @started
      return if @stopped

      @stop_flag = true
      @thread&.join(POLL_TIMEOUT_MS * 4 / 1000.0 + 1)
      @session_stop_iso = Time.now.utc.iso8601(3)
      @session_stop_ktime = Vivarium.monotonic_ktime_ns

      3.times { safe_poll(50) }
      drain_method_id_queue

      events_snapshot = @events_mutex.synchronize { @events.dup }
      method_table_snapshot = @method_table.dup
      @stopped = true

      TreeRenderer.new(
        events: events_snapshot,
        method_table: method_table_snapshot,
        observer_pid: @observer_pid,
        main_tid: @main_tid,
        session_start_iso: @session_start_iso,
        session_start_ktime: @session_start_ktime,
        session_stop_iso: @session_stop_iso,
        session_stop_ktime: @session_stop_ktime,
        filter: @filter,
        dest: @dest
      ).render
    end

    private

    def run
      until @stop_flag
        safe_poll(POLL_TIMEOUT_MS)
        drain_method_id_queue
      end
    end

    def safe_poll(timeout_ms)
      @ringbuf.ring_buffer_poll(timeout_ms)
    rescue StandardError => e
      warn "[vivarium correlator] poll error: #{e.class}: #{e.message}"
    end

    def capture_event(data, size)
      bytes = data[0, size].to_s.b
      bytes = bytes.ljust(Vivarium::EVENT_STRUCT_SIZE, "\x00") if bytes.bytesize < Vivarium::EVENT_STRUCT_SIZE

      ktime_ns = bytes[Vivarium::EVENT_TS_OFFSET, Vivarium::EVENT_TS_SIZE].unpack1("Q<")
      pid = bytes[Vivarium::EVENT_PID_OFFSET, 4].unpack1("L<")
      tid = bytes[Vivarium::EVENT_TID_OFFSET, 4].unpack1("L<")
      event_name = Vivarium.c_string(bytes[Vivarium::EVENT_NAME_OFFSET, Vivarium::EVENT_NAME_SIZE])
      payload = bytes[Vivarium::EVENT_PAYLOAD_OFFSET, Vivarium::EVENT_PAYLOAD_SIZE].to_s.b

      @events_mutex.synchronize do
        @events << RawEvent.new(
          ktime_ns: ktime_ns,
          pid: pid,
          tid: tid,
          event_name: event_name,
          payload: payload
        )
      end
    rescue StandardError => e
      warn "[vivarium correlator] capture error: #{e.class}: #{e.message}"
    end

    def drain_method_id_queue
      loop do
        msg = begin
          @method_id_queue.pop(true)
        rescue ThreadError
          return
        end

        method_id, signature = msg
        @method_table[method_id] = signature
      end
    end
  end
end
