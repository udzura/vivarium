# frozen_string_literal: true

require "fileutils"
require "fiddle"
require "securerandom"
require "socket"

module Vivarium
  # In-memory, sequence-numbered log of raw event_t records (#{Vivarium::EVENT_STRUCT_SIZE} bytes
  # each) fed by the daemon's ring buffer poller and consumed by /events streams.
  class EventLog
    def initialize(capacity: 50_000)
      @capacity = capacity
      @mutex = Mutex.new
      @cond = ConditionVariable.new
      @records = []
      @seq = 0
    end

    def append(bytes)
      @mutex.synchronize do
        @seq += 1
        @records << [@seq, bytes]
        overflow = @records.size - @capacity
        @records.shift(overflow) if overflow.positive?
        @cond.broadcast
      end
    end

    def tail_seq
      @mutex.synchronize { @seq }
    end

    # Returns records with seq > cursor. Blocks up to timeout seconds when nothing newer
    # is available so callers can long-poll.
    def read_after(cursor, timeout: 1.0)
      @mutex.synchronize do
        if @records.empty? || @records.last[0] <= cursor
          @cond.wait(@mutex, timeout)
        end
        @records.select { |seq, _| seq > cursor }
      end
    end
  end

  # Wraps the daemon's live BPF target maps so the API can (un)register PIDs.
  class Registry
    # struct otel_ctx_t { trace_id{u64 hi; u64 lo}; u64 span_id; u64 parent_span_id; }
    OTEL_CTX_PACK_FMT = "Q<Q<Q<Q<"

    def initialize(config_root_targets, config_spawned_targets, otel_ctx = nil)
      @config_root_targets = config_root_targets
      @config_spawned_targets = config_spawned_targets
      @otel_ctx = otel_ctx
    end

    # Registering a root target marks the start of a trace: issue a fresh
    # 128-bit trace_id and a root span_id (no parent) into the otel_ctx map,
    # keyed by the root pid (== the main thread's tid).
    def register(pid)
      @config_root_targets[pid] = 1
      return unless @otel_ctx

      hi = SecureRandom.random_number(1 << 64)
      lo = SecureRandom.random_number(1 << 64)
      span = SecureRandom.random_number(1 << 64)
      write_otel_ctx(pid, hi, lo, span, 0)
    end

    def unregister(pid)
      @config_root_targets.delete(pid)
      @config_spawned_targets.clear
      @otel_ctx&.clear
    rescue KeyError
      nil
    end

    private

    def write_otel_ctx(tid, trace_hi, trace_lo, span_id, parent_span_id)
      size = @otel_ctx.leafsize
      ptr = Fiddle::Pointer.malloc(size)
      ptr[0, size] = [trace_hi, trace_lo, span_id, parent_span_id].pack(OTEL_CTX_PACK_FMT)
      @otel_ctx[tid] = ptr
    end
  end

  # Minimal HTTP/1.1 server over a Unix domain socket exposing the daemon control API.
  class ApiServer
    STREAM_POLL_TIMEOUT = 1.0

    def initialize(socket_path:, event_log:, registry:, daemon_pid: Process.pid)
      @socket_path = socket_path
      @event_log = event_log
      @registry = registry
      @daemon_pid = daemon_pid
    end

    def start
      FileUtils.mkdir_p(File.dirname(@socket_path))
      File.unlink(@socket_path) if File.exist?(@socket_path)
      @server = UNIXServer.new(@socket_path)
      File.chmod(0o666, @socket_path)
      @thread = Thread.new { accept_loop }
      self
    end

    def stop
      @server&.close
    rescue StandardError
      nil
    ensure
      File.unlink(@socket_path) if @socket_path && File.exist?(@socket_path)
    end

    private

    def accept_loop
      loop do
        conn = @server.accept
        Thread.new(conn) { |c| handle(c) }
      end
    rescue IOError, Errno::EBADF
      # server closed during shutdown
    end

    def handle(conn)
      request_line = conn.gets
      return if request_line.nil?

      method, target, = request_line.split(" ")
      drain_headers(conn)

      path, query = target.to_s.split("?", 2)
      route(conn, method, path, query)
    rescue Errno::EPIPE, IOError
      nil
    rescue StandardError => e
      warn "[vivariumd api] #{e.class}: #{e.message}"
    ensure
      begin
        conn.close
      rescue StandardError
        nil
      end
    end

    def drain_headers(conn)
      while (line = conn.gets)
        break if line == "\r\n" || line == "\n"
      end
    end

    def route(conn, method, path, query)
      target_match = path.to_s.match(%r{\A/targets/(\d+)\z})

      if method == "GET" && path == "/healthz"
        respond_json(conn, 200, { status: "ok", pid: @daemon_pid })
      elsif method == "GET" && path == "/events"
        stream_events(conn, query)
      elsif method == "PUT" && target_match
        pid = Integer(target_match[1], 10)
        @registry.register(pid)
        respond_json(conn, 200, { status: "registered", pid: pid })
      elsif method == "DELETE" && target_match
        pid = Integer(target_match[1], 10)
        @registry.unregister(pid)
        respond_json(conn, 200, { status: "unregistered", pid: pid })
      else
        respond_json(conn, 404, { error: "not_found" })
      end
    end

    def stream_events(conn, query)
      since = parse_since(query)
      conn.write("HTTP/1.1 200 OK\r\n")
      conn.write("Content-Type: application/octet-stream\r\n")
      conn.write("Transfer-Encoding: chunked\r\n")
      conn.write("\r\n")

      cursor = since || @event_log.tail_seq
      loop do
        records = @event_log.read_after(cursor, timeout: STREAM_POLL_TIMEOUT)
        records.each do |seq, bytes|
          conn.write(format("%x\r\n", bytes.bytesize))
          conn.write(bytes)
          conn.write("\r\n")
          cursor = seq
        end
      end
    rescue Errno::EPIPE, Errno::ECONNRESET, IOError
      # client disconnected
    ensure
      begin
        conn.write("0\r\n\r\n")
      rescue StandardError
        nil
      end
    end

    def parse_since(query)
      return nil if query.nil? || query.empty?

      query.split("&").each do |pair|
        key, value = pair.split("=", 2)
        return Integer(value, 10) if key == "since" && value
      end
      nil
    rescue ArgumentError
      nil
    end

    def respond_json(conn, status, payload)
      body = json_encode(payload)
      conn.write("HTTP/1.1 #{status} #{status_text(status)}\r\n")
      conn.write("Content-Type: application/json\r\n")
      conn.write("Content-Length: #{body.bytesize}\r\n")
      conn.write("Connection: close\r\n")
      conn.write("\r\n")
      conn.write(body)
    end

    def status_text(status)
      case status
      when 200 then "OK"
      when 404 then "Not Found"
      else "Status"
      end
    end

    def json_encode(hash)
      pairs = hash.map do |key, value|
        encoded = value.is_a?(Integer) ? value.to_s : %("#{value}")
        %("#{key}":#{encoded})
      end
      "{#{pairs.join(',')}}"
    end
  end
end
