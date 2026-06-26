# frozen_string_literal: true

require "json"
require "time"

module Vivarium
  # Converts a captured event stream into an OTLP/JSON ResourceSpans document.
  #
  # Two span layers are emitted (see plan): a base thread/process span per tid
  # (identified by the BPF-issued span_id) and method-call spans reconstructed
  # from span_start/span_stop. Every other event becomes an OTel span event on
  # the innermost active span. Method span ids come from Vivarium.synth_span_id
  # so they match the report --dump-otel view.
  module OtelExporter
    SPAN_KIND_INTERNAL = 1
    SERVICE_NAME = "vivarium"
    INTERNAL_COMM_MATCH = [/otel_stream\.rb/].freeze

    module_function

    # io: a writable IO. Writes a single-line OTLP/JSON document.
    def dump(io, events:, meta:)
      io.write(JSON.generate(build_document(events: events, meta: meta)))
    end

    def build_document(events:, meta:)
      wrap_document(build_spans(events: events, meta: meta))
    end

    # Wraps a list of OTLP span hashes in the ResourceSpans envelope. Shared by
    # the batch file exporter and the streaming HTTP exporter so both emit the
    # same resource/scope.
    def wrap_document(spans)
      {
        resourceSpans: [
          {
            resource: { attributes: [str_attr("service.name", SERVICE_NAME)] },
            scopeSpans: [
              {
                scope: { name: SERVICE_NAME, version: Vivarium::VERSION },
                spans: spans
              }
            ]
          }
        ]
      }
    end

    # Returns an array of OTLP span hashes.
    def build_spans(events:, meta:)
      sorted = events.sort_by { |e| [e.ktime_ns, e.pid, e.tid] }
      start_ktime = meta[:session_start_ktime].to_i
      stop_ktime = meta[:session_stop_ktime].to_i
      start_unix = iso_to_unix_ns(meta[:session_start_iso])
      main_tid = meta[:main_tid]
      to_unix = ->(k) { (start_unix + (k.to_i - start_ktime)).to_s }

      thread_spans = {}        # tid => mutable span record
      method_spans = []        # all method span records
      stacks = Hash.new { |h, k| h[k] = [] } # tid => [method span record, ...]

      sorted.each do |ev|
        next if internal_comm?(ev.comm)

        ts = (thread_spans[ev.tid] ||= new_thread_span(ev, main_tid))
        ts[:comm] = ev.comm.to_s unless ev.comm.to_s.empty?
        ts[:min_k] = ev.ktime_ns if ev.ktime_ns < ts[:min_k]
        ts[:max_k] = ev.ktime_ns if ev.ktime_ns > ts[:max_k]
        stack = stacks[ev.tid]

        case ev.event_name
        when "span_start"
          name, file, lineno = read_span_payload(ev.payload)
          parent = stack.empty? ? ts[:span_id] : stack.last[:span_id]
          rec = {
            tid: ev.tid, pid: ev.pid,
            span_id: Vivarium.synth_span_id(ev.trace_hi.to_i, ev.trace_lo.to_i, ev.tid, ev.ktime_ns),
            trace_hi: ev.trace_hi.to_i, trace_lo: ev.trace_lo.to_i,
            parent: parent, name: (name.nil? || name.empty? ? "<anonymous>" : name),
            file: file, lineno: lineno, start_k: ev.ktime_ns, stop_k: nil, events: []
          }
          method_spans << rec
          stack.push(rec)
        when "span_stop"
          rec = stack.pop
          rec[:stop_k] = ev.ktime_ns if rec
        else
          host = stack.empty? ? ts : stack.last
          host[:events] << build_span_event(ev, to_unix)
        end
      end

      method_spans.each { |rec| rec[:stop_k] ||= stop_ktime }

      out = []
      thread_spans.each_value { |ts| out << thread_span_hash(ts, start_ktime, stop_ktime, to_unix) }
      method_spans.each { |rec| out << method_span_hash(rec, to_unix) }
      out
    end

    # --- span record construction -------------------------------------------

    def new_thread_span(ev, main_tid)
      span_id = ev.span_id.to_i
      span_id = Vivarium.synth_span_id(ev.trace_hi.to_i, ev.trace_lo.to_i, ev.tid, ev.ktime_ns) if span_id.zero?
      {
        tid: ev.tid, pid: ev.pid, span_id: span_id,
        trace_hi: ev.trace_hi.to_i, trace_lo: ev.trace_lo.to_i,
        parent: ev.parent_span_id.to_i, comm: ev.comm.to_s,
        root: ev.tid == main_tid,
        min_k: ev.ktime_ns, max_k: ev.ktime_ns, events: []
      }
    end

    def thread_span_hash(ts, start_ktime, stop_ktime, to_unix)
      start_k = ts[:root] ? start_ktime : ts[:min_k]
      stop_k = ts[:root] ? stop_ktime : ts[:max_k]
      name = ts[:comm].empty? ? "tid=#{ts[:tid]}" : ts[:comm]
      span_hash(
        trace_hi: ts[:trace_hi], trace_lo: ts[:trace_lo],
        span_id: ts[:span_id], parent: ts[:parent], name: name,
        start_k: start_k, stop_k: stop_k, to_unix: to_unix,
        attributes: [
          int_attr("thread.id", ts[:tid]),
          int_attr("process.pid", ts[:pid]),
          str_attr("process.command", ts[:comm])
        ],
        events: ts[:events] || []
      )
    end

    def method_span_hash(rec, to_unix)
      attrs = [int_attr("thread.id", rec[:tid]), int_attr("process.pid", rec[:pid])]
      attrs << str_attr("code.filepath", rec[:file]) if rec[:file] && !rec[:file].empty?
      attrs << int_attr("code.lineno", rec[:lineno]) if rec[:lineno] && rec[:lineno] > 0
      span_hash(
        trace_hi: rec[:trace_hi], trace_lo: rec[:trace_lo],
        span_id: rec[:span_id], parent: rec[:parent], name: rec[:name],
        start_k: rec[:start_k], stop_k: rec[:stop_k], to_unix: to_unix,
        attributes: attrs, events: rec[:events]
      )
    end

    def span_hash(trace_hi:, trace_lo:, span_id:, parent:, name:, start_k:, stop_k:, to_unix:, attributes:, events:)
      hash = {
        traceId: hex32(trace_hi, trace_lo),
        spanId: hex16(span_id),
        name: name,
        kind: SPAN_KIND_INTERNAL,
        startTimeUnixNano: to_unix.call(start_k),
        endTimeUnixNano: to_unix.call(stop_k),
        attributes: attributes
      }
      hash[:parentSpanId] = hex16(parent) unless parent.to_i.zero?
      hash[:events] = events unless events.empty?
      hash
    end

    def build_span_event(ev, to_unix)
      { timeUnixNano: to_unix.call(ev.ktime_ns), name: ev.event_name, attributes: event_attributes(ev) }
    end

    # OTLP attribute list describing an event (target/severity/uid/gid/comm/...).
    # Reused for both span events and standalone single-event spans (streaming).
    def event_attributes(ev)
      target =
        begin
          Vivarium.render_event_payload(ev).to_s.gsub(/\s+/, " ").strip
        rescue StandardError
          ""
        end
      attrs = [
        int_attr("thread.id", ev.tid),
        int_attr("process.pid", ev.pid),
        int_attr("user.id", ev.uid),
        int_attr("group.id", ev.gid),
        str_attr("severity", Vivarium.event_severity(ev.event_name))
      ]
      attrs << str_attr("process.command", ev.comm.to_s) unless ev.comm.to_s.empty?
      attrs << str_attr("target", target) unless target.empty?
      attrs
    end

    # --- helpers -------------------------------------------------------------

    def internal_comm?(comm)
      value = comm.to_s
      INTERNAL_COMM_MATCH.any? { |regex| value.match?(regex) }
    end

    def read_span_payload(payload)
      bytes = payload.to_s.b
      return [nil, nil, -1] if bytes.empty?

      name = Vivarium.c_string(bytes[0, Vivarium::SPAN_METHOD_SIZE])
      file = Vivarium.c_string(bytes[Vivarium::SPAN_METHOD_SIZE, Vivarium::SPAN_FILE_SIZE])
      lineno = bytes.bytesize > Vivarium::SPAN_LINENO_OFFSET ? bytes[Vivarium::SPAN_LINENO_OFFSET, 8].unpack1("q<") : -1
      [name, file, lineno]
    end

    def iso_to_unix_ns(iso)
      return 0 if iso.nil? || iso.to_s.empty?

      (Time.iso8601(iso).to_r * 1_000_000_000).to_i
    rescue ArgumentError
      0
    end

    def hex32(hi, lo)
      format("%016x%016x", hi.to_i & Vivarium::U64_MASK, lo.to_i & Vivarium::U64_MASK)
    end

    def hex16(value)
      format("%016x", value.to_i & Vivarium::U64_MASK)
    end

    def str_attr(key, value)
      { key: key, value: { stringValue: value.to_s } }
    end

    def int_attr(key, value)
      { key: key, value: { intValue: value.to_i.to_s } }
    end
  end
end
