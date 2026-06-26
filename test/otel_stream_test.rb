# frozen_string_literal: true

require "test_helper"
require "ostruct"

class VivariumOtelStreamTest < Test::Unit::TestCase
  SESSION_START_ISO = "2026-06-26T00:00:00.000Z"
  SESSION_START_KTIME = 1_000
  OBSERVER_PID = 123
  MAIN_TID = 456
  RUBY_SPAN_ID = 0x100
  SHELL_SPAN_ID = 0x200
  TRACE_HI = 11
  TRACE_LO = 22

  class CaptureExporter
    attr_reader :spans

    def initialize
      @spans = []
    end

    def enqueue(span)
      @spans << span
    end
  end

  test "streams spawned process span using BPF parent hierarchy" do
    exporter = CaptureExporter.new
    streamer = new_streamer(exporter)

    parent_attrs = ruby_event_attrs
    child_attrs = shell_event_attrs

    streamer.on_event(raw_event(parent_attrs.merge(
      event_name: "span_start",
      ktime_ns: 1_100,
      payload: span_payload("Kernel#system", "examples/network_client_demo_otel.rb", 23)
    )))
    streamer.on_event(raw_event(parent_attrs.merge(
      event_name: "proc_fork",
      ktime_ns: 1_120,
      payload: fork_payload(777)
    )))
    streamer.on_event(raw_event(child_attrs.merge(
      event_name: "proc_exec",
      ktime_ns: 1_130,
      payload: exec_payload("/bin/sh")
    )))

    assert_nil find_span(exporter, "sh"), "child process span should wait for proc_exit"

    streamer.on_event(raw_event(child_attrs.merge(
      event_name: "proc_exit",
      ktime_ns: 1_160,
      payload: ""
    )))

    shell_span = find_span(exporter, "sh")
    assert_not_nil shell_span
    assert_equal hex16(RUBY_SPAN_ID), shell_span[:parentSpanId]
    assert_equal ["proc_exec"], event_names(shell_span)
    assert_equal false, event_names(shell_span).include?("proc_exit")

    streamer.on_event(raw_event(parent_attrs.merge(
      event_name: "span_stop",
      ktime_ns: 1_200,
      payload: ""
    )))
    streamer.finalize(stop_ktime: 2_000)

    ruby_span = find_span(exporter, "ruby")
    method_span = find_span(exporter, "Kernel#system")
    session_span = find_span(exporter, "vivarium session")

    assert_not_nil ruby_span
    assert_not_nil method_span
    assert_not_nil session_span
    assert_equal nil, session_span[:parentSpanId]
    assert_equal session_span[:spanId], ruby_span[:parentSpanId]
    assert_equal hex16(RUBY_SPAN_ID), ruby_span[:spanId]
    assert_equal ruby_span[:spanId], method_span[:parentSpanId]
    assert_equal ruby_span[:spanId], shell_span[:parentSpanId]
    assert_equal 1, exporter.spans.count { |span| span[:name] == "sh" }
  end

  test "batch exporter drops proc_exit control events" do
    events = [
      raw_event(ruby_event_attrs.merge(event_name: "proc_exit", ktime_ns: 1_100, payload: "")),
      raw_event(ruby_event_attrs.merge(event_name: "path_open", ktime_ns: 1_200, payload: "/tmp/x"))
    ]
    meta = {
      session_start_ktime: SESSION_START_KTIME,
      session_stop_ktime: 2_000,
      session_start_iso: SESSION_START_ISO,
      main_tid: MAIN_TID
    }

    spans = Vivarium::OtelExporter.build_spans(events: events, meta: meta)
    all_event_names = spans.flat_map { |span| event_names(span) }

    assert_equal true, all_event_names.include?("path_open")
    assert_equal false, all_event_names.include?("proc_exit")
  end

  private

  def new_streamer(exporter)
    Vivarium::OtelSpanStreamer.new(
      exporter: exporter,
      session_start_iso: SESSION_START_ISO,
      session_start_ktime: SESSION_START_KTIME,
      observer_pid: OBSERVER_PID,
      main_tid: MAIN_TID
    )
  end

  def raw_event(attrs)
    OpenStruct.new({
      pid: OBSERVER_PID,
      tid: MAIN_TID,
      uid: 501,
      gid: 20,
      trace_hi: TRACE_HI,
      trace_lo: TRACE_LO,
      span_id: RUBY_SPAN_ID,
      parent_span_id: 0,
      comm: "ruby",
      dropped_since_last: 0,
      payload: ""
    }.merge(attrs))
  end

  def ruby_event_attrs
    {
      pid: OBSERVER_PID,
      tid: MAIN_TID,
      span_id: RUBY_SPAN_ID,
      parent_span_id: 0,
      comm: "ruby"
    }
  end

  def shell_event_attrs
    {
      pid: 777,
      tid: 777,
      span_id: SHELL_SPAN_ID,
      parent_span_id: RUBY_SPAN_ID,
      comm: "sh"
    }
  end

  def span_payload(name, file, lineno)
    name.b.ljust(Vivarium::SPAN_METHOD_SIZE, "\0") +
      file.b.ljust(Vivarium::SPAN_FILE_SIZE, "\0") +
      [lineno].pack("q<")
  end

  def fork_payload(child_pid)
    [child_pid].pack("L<")
  end

  def exec_payload(filename)
    filename.b.ljust(Vivarium::PROC_EXEC_SLOT_SIZE, "\0")
  end

  def find_span(exporter, name)
    exporter.spans.find { |span| span[:name] == name }
  end

  def event_names(span)
    (span[:events] || []).map { |event| event[:name] }
  end

  def hex16(value)
    format("%016x", value & Vivarium::U64_MASK)
  end
end