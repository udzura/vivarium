# frozen_string_literal: true

require "json"
require "net/http"
require "uri"

module Vivarium
  # Background OTLP/HTTP(JSON) sender. Completed spans are enqueued and flushed
  # in batches by a worker thread to {endpoint}/v1/traces. Send failures are
  # logged and the batch is dropped so a resident observation never stalls.
  class OtelHttpExporter
    def initialize(endpoint:, flush_interval: 2.0, max_batch: 256, max_queue: 10_000)
      @uri = build_uri(endpoint)
      @flush_interval = flush_interval
      @max_batch = max_batch
      @max_queue = max_queue

      @queue = []
      @mutex = Mutex.new
      @cond = ConditionVariable.new
      @stop = false
      @dropped = 0
      @thread = nil
    end

    def start
      return self if @thread

      @thread = Thread.new { worker }
      self
    end

    def enqueue(span)
      @mutex.synchronize do
        if @queue.size >= @max_queue
          @dropped += 1
        else
          @queue << span
          @cond.signal
        end
      end
    end

    def shutdown
      @mutex.synchronize do
        @stop = true
        @cond.signal
      end
      @thread&.join
      warn "[vivarium] otel: dropped #{@dropped} span(s) (queue overflow)" if @dropped.positive?
    end

    private

    def worker
      until stop_and_drained?
        batch = take_batch
        post_batch(batch) unless batch.empty?
      end
    rescue StandardError => e
      warn "[vivarium] otel worker error: #{e.class}: #{e.message}"
    end

    def stop_and_drained?
      @mutex.synchronize { @stop && @queue.empty? }
    end

    def take_batch
      @mutex.synchronize do
        @cond.wait(@mutex, @flush_interval) if @queue.empty? && !@stop
        @queue.shift(@max_batch)
      end
    end

    def post_batch(spans)
      body = JSON.generate(Vivarium::OtelExporter.wrap_document(spans))
      req = Net::HTTP::Post.new(@uri)
      req["Content-Type"] = "application/json"
      req.body = body

      http = Net::HTTP.new(@uri.host, @uri.port)
      http.use_ssl = (@uri.scheme == "https")
      http.open_timeout = 5
      http.read_timeout = 10
      res = http.request(req)
      return if res.code.to_s.start_with?("2")

      warn "[vivarium] otel: collector returned HTTP #{res.code} for #{spans.size} span(s)"
    rescue StandardError => e
      warn "[vivarium] otel: POST failed (#{e.class}: #{e.message}); dropped #{spans.size} span(s)"
    end

    def build_uri(endpoint)
      base = endpoint.to_s.strip.chomp("/")
      base += "/v1/traces" unless base.end_with?("/v1/traces")
      URI.parse(base)
    end
  end

  # Reconstructs method-call spans live from the event stream and enqueues each
  # completed span to an OtelHttpExporter. Top-level method spans start their own
  # OTel trace (process/thread identity lives in span attributes, not a span),
  # so traces stay bounded for resident processes. Events outside any method span
  # are emitted as standalone single-event spans. See plan: streaming model A.
  class OtelSpanStreamer
    def initialize(exporter:, session_start_iso:, session_start_ktime:)
      @exporter = exporter
      start_unix = Vivarium::OtelExporter.iso_to_unix_ns(session_start_iso)
      start_ktime = session_start_ktime.to_i
      @to_unix = ->(k) { (start_unix + (k.to_i - start_ktime)).to_s }
      @stacks = Hash.new { |h, k| h[k] = [] }
    end

    def on_event(ev)
      case ev.event_name
      when "span_start" then handle_start(ev)
      when "span_stop" then handle_stop(ev)
      else handle_event(ev)
      end
    end

    # Close any still-open spans (dangling) at end of observation.
    def finalize(stop_ktime:)
      @stacks.each_value do |stack|
        emit_method_span(stack.pop, stop_ktime) until stack.empty?
      end
    end

    private

    def handle_start(ev)
      stack = @stacks[ev.tid]
      if stack.empty?
        trace_hi, trace_lo = Vivarium.synth_trace_id(ev.trace_hi.to_i, ev.trace_lo.to_i, ev.tid, ev.ktime_ns)
        parent = 0
      else
        top = stack.last
        trace_hi = top[:trace_hi]
        trace_lo = top[:trace_lo]
        parent = top[:span_id]
      end

      name, file, lineno = Vivarium::OtelExporter.read_span_payload(ev.payload)
      stack.push(
        tid: ev.tid, pid: ev.pid, trace_hi: trace_hi, trace_lo: trace_lo,
        span_id: Vivarium.synth_span_id(ev.trace_hi.to_i, ev.trace_lo.to_i, ev.tid, ev.ktime_ns),
        parent: parent, name: (name.nil? || name.empty? ? "<anonymous>" : name),
        file: file, lineno: lineno, start_k: ev.ktime_ns, events: []
      )
    end

    def handle_stop(ev)
      rec = @stacks[ev.tid].pop
      emit_method_span(rec, ev.ktime_ns) if rec
    end

    def handle_event(ev)
      stack = @stacks[ev.tid]
      if stack.empty?
        emit_standalone(ev)
      else
        stack.last[:events] << Vivarium::OtelExporter.build_span_event(ev, @to_unix)
      end
    end

    def emit_method_span(rec, end_k)
      attrs = [
        Vivarium::OtelExporter.int_attr("thread.id", rec[:tid]),
        Vivarium::OtelExporter.int_attr("process.pid", rec[:pid])
      ]
      attrs << Vivarium::OtelExporter.str_attr("code.filepath", rec[:file]) if rec[:file] && !rec[:file].empty?
      attrs << Vivarium::OtelExporter.int_attr("code.lineno", rec[:lineno]) if rec[:lineno] && rec[:lineno] > 0

      @exporter.enqueue(
        Vivarium::OtelExporter.span_hash(
          trace_hi: rec[:trace_hi], trace_lo: rec[:trace_lo], span_id: rec[:span_id],
          parent: rec[:parent], name: rec[:name], start_k: rec[:start_k], stop_k: end_k,
          to_unix: @to_unix, attributes: attrs, events: rec[:events]
        )
      )
    end

    def emit_standalone(ev)
      trace_hi, trace_lo = Vivarium.synth_trace_id(ev.trace_hi.to_i, ev.trace_lo.to_i, ev.tid, ev.ktime_ns)
      span_id = Vivarium.synth_span_id(ev.trace_hi.to_i, ev.trace_lo.to_i, ev.tid, ev.ktime_ns)
      @exporter.enqueue(
        Vivarium::OtelExporter.span_hash(
          trace_hi: trace_hi, trace_lo: trace_lo, span_id: span_id, parent: 0,
          name: ev.event_name, start_k: ev.ktime_ns, stop_k: ev.ktime_ns,
          to_unix: @to_unix, attributes: Vivarium::OtelExporter.event_attributes(ev), events: []
        )
      )
    end
  end
end
