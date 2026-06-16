# frozen_string_literal: true

require "time"

module Vivarium
  # Client-side consumer of the vivariumd event stream. Connects to the daemon's
  # Unix domain socket, reads chunked raw event_t records, accumulates them, and
  # renders a tree on stop. It never touches BPF maps or the ring buffer directly.
  class Correlator
    RawEvent = Struct.new(
      :ktime_ns, :pid, :tid, :event_name, :payload, :dropped_since_last,
      keyword_init: true
    )

    # Grace period after stop to let trailing events drain through the stream.
    DRAIN_SLEEP = 0.3

    def initialize(socket_path: Vivarium.socket_path, observer_pid:, main_tid:,
                   filter: nil, dest: $stdout)
      @socket_path = socket_path
      @observer_pid = observer_pid
      @main_tid = main_tid
      @filter = filter
      @dest = dest

      @client = DaemonClient.new(socket_path: socket_path)
      @events = []
      @events_mutex = Mutex.new
      @stop_flag = false
      @started = false
      @stopped = false
    end

    def start
      return if @started

      @session_start_iso = Time.now.utc.iso8601(3)
      @session_start_ktime = Vivarium.monotonic_ktime_ns
      @sock = @client.open_event_stream
      @thread = Thread.new { run }
      @started = true
    end

    def stop
      return unless @started
      return if @stopped

      sleep DRAIN_SLEEP
      @stop_flag = true
      @sock&.close
      @thread&.join(2)
      @session_stop_iso = Time.now.utc.iso8601(3)
      @session_stop_ktime = Vivarium.monotonic_ktime_ns

      events_snapshot = @events_mutex.synchronize { @events.dup }
      @stopped = true

      TreeRenderer.new(
        events: events_snapshot,
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
        size = read_chunk_size(@sock)
        break if size.nil? || size.zero?

        bytes = read_exactly(@sock, size)
        break if bytes.nil?

        @sock.read(2) # trailing CRLF after chunk data
        capture_event(bytes)
      end
    rescue IOError, Errno::EBADF, Errno::ECONNRESET
      # socket closed on stop
    rescue StandardError => e
      warn "[vivarium correlator] stream error: #{e.class}: #{e.message}"
    end

    def read_chunk_size(sock)
      line = sock.gets
      return nil if line.nil?

      Integer(line.strip, 16)
    rescue ArgumentError
      nil
    end

    def read_exactly(sock, size)
      buffer = +""
      while buffer.bytesize < size
        chunk = sock.read(size - buffer.bytesize)
        return nil if chunk.nil?

        buffer << chunk
      end
      buffer
    end

    def capture_event(bytes)
      bytes = bytes.to_s.b
      bytes = bytes.ljust(Vivarium::EVENT_STRUCT_SIZE, "\x00") if bytes.bytesize < Vivarium::EVENT_STRUCT_SIZE

      ktime_ns           = bytes[Vivarium::EVENT_TS_OFFSET,      Vivarium::EVENT_TS_SIZE].unpack1("Q<")
      pid                = bytes[Vivarium::EVENT_PID_OFFSET,     4].unpack1("L<")
      tid                = bytes[Vivarium::EVENT_TID_OFFSET,     4].unpack1("L<")
      event_name         = Vivarium.c_string(bytes[Vivarium::EVENT_NAME_OFFSET, Vivarium::EVENT_NAME_SIZE])
      payload            = bytes[Vivarium::EVENT_PAYLOAD_OFFSET, Vivarium::EVENT_PAYLOAD_SIZE].to_s.b
      dropped_since_last = bytes[Vivarium::EVENT_DROPPED_OFFSET, 8].unpack1("Q<")

      @events_mutex.synchronize do
        @events << RawEvent.new(
          ktime_ns: ktime_ns,
          pid: pid,
          tid: tid,
          event_name: event_name,
          payload: payload,
          dropped_since_last: dropped_since_last
        )
      end
    rescue StandardError => e
      warn "[vivarium correlator] capture error: #{e.class}: #{e.message}"
    end
  end
end
