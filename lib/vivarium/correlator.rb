# frozen_string_literal: true

require "time"

module Vivarium
  # Client-side consumer of the vivariumd event stream. Connects to the daemon's
  # Unix domain socket, reads chunked raw event_t records, accumulates them, and
  # renders a tree on stop. It never touches BPF maps or the ring buffer directly.
  class Correlator
    # Grace period after stop to let trailing events drain through the stream.
    DRAIN_SLEEP = 0.3

    # In save_raw mode, emit a progress line every this many captured events.
    SAVE_RAW_PROGRESS_INTERVAL = 1000

    def initialize(socket_path: Vivarium.socket_path, observer_pid:, main_tid:,
                   filter: nil, dest: $stdout, save_raw: nil, otel_out: nil, otel_endpoint: nil)
      @socket_path = socket_path
      @observer_pid = observer_pid
      @main_tid = main_tid
      @filter = filter
      @dest = dest
      @save_raw = save_raw
      @otel_out = otel_out
      @otel_endpoint = otel_endpoint

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
      start_stream_exporter if @otel_endpoint
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

      if @stream
        @stream.finalize(stop_ktime: @session_stop_ktime)
        @stream_exporter.shutdown
        warn "[vivarium] otel: streamed spans -> #{@otel_endpoint}"
        @stopped = true
        return
      end

      events_snapshot = @events_mutex.synchronize { @events.dup }
      @stopped = true

      meta = {
        observer_pid: @observer_pid,
        main_tid: @main_tid,
        session_start_iso: @session_start_iso,
        session_start_ktime: @session_start_ktime,
        session_stop_iso: @session_stop_iso,
        session_stop_ktime: @session_stop_ktime
      }

      if @save_raw
        File.open(@save_raw, "wb") do |io|
          Vivarium::RawStore.dump(io, events: events_snapshot, meta: meta)
        end
        warn "[vivarium] save_raw: saved #{events_snapshot.size} events -> #{@save_raw}"
        return
      end

      if @otel_out
        File.open(@otel_out, "w") do |io|
          Vivarium::OtelExporter.dump(io, events: events_snapshot, meta: meta)
        end
        warn "[vivarium] otel_out: wrote OTLP spans -> #{@otel_out}"
        return
      end

      TreeRenderer.new(events: events_snapshot, **meta, filter: @filter, dest: @dest).render
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

    def start_stream_exporter
      @stream_exporter = Vivarium::OtelHttpExporter.new(endpoint: @otel_endpoint).start
      @stream = Vivarium::OtelSpanStreamer.new(
        exporter: @stream_exporter,
        session_start_iso: @session_start_iso,
        session_start_ktime: @session_start_ktime
      )
    end

    def capture_event(bytes)
      ev = Vivarium::RawStore.unpack_record(bytes)

      # Streaming mode converts events to spans live and does not buffer them,
      # so a resident observation does not grow memory without bound.
      if @stream
        @stream.on_event(ev)
        return
      end

      count = @events_mutex.synchronize { @events << ev; @events.size }
      report_save_progress(count)
    rescue StandardError => e
      warn "[vivarium correlator] capture error: #{e.class}: #{e.message}"
    end

    def report_save_progress(count)
      return unless @save_raw
      return unless (count % SAVE_RAW_PROGRESS_INTERVAL).zero?

      warn "[vivarium] save_raw: captured #{count} events -> #{@save_raw}"
    end
  end
end
