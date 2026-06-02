#!/usr/bin/env ruby
# frozen_string_literal: true

# Standalone demo: shows what DROP warning nodes look like in the TreeRenderer
# output. Does NOT require BPF or vivariumd — constructs RawEvent objects
# directly and feeds them to TreeRenderer.
#
# Usage:
#   ruby examples/drop_demo.rb

$LOAD_PATH.unshift File.join(__dir__, "..", "lib")

require "vivarium"
require "vivarium/correlator"
require "vivarium/tree_renderer"
require "vivarium/display_filter"
require "vivarium_usdt"

t0        = 1_000_000_000  # base ktime_ns
pid       = Process.pid
tid       = Process.pid
method_id = 0x0001_0001

# span_start payload: method_id (8B) + file_id (8B) + lineno (8B)
span_start_payload = [method_id, 0, 10].pack("q<q<q<")
                                        .ljust(Vivarium::EVENT_PAYLOAD_SIZE, "\x00")

events = [
  Vivarium::Correlator::RawEvent.new(
    ktime_ns: t0,
    pid: pid, tid: tid,
    event_name: "span_start",
    payload: span_start_payload,
    dropped_since_last: 0
  ),
  # This event carries drop info: 5 events were lost before it arrived
  Vivarium::Correlator::RawEvent.new(
    ktime_ns: t0 + 10_000_000,
    pid: pid, tid: tid,
    event_name: "path_open",
    payload: "/etc/passwd\x00".b.ljust(Vivarium::EVENT_PAYLOAD_SIZE, "\x00"),
    dropped_since_last: 5
  ),
  Vivarium::Correlator::RawEvent.new(
    ktime_ns: t0 + 20_000_000,
    pid: pid, tid: tid,
    event_name: "dns_req",
    payload: "\x06google\x03com\x00".b.ljust(Vivarium::EVENT_PAYLOAD_SIZE, "\x00"),
    dropped_since_last: 0
  ),
  # Another burst: 12 events dropped just before this sock_connect
  Vivarium::Correlator::RawEvent.new(
    ktime_ns: t0 + 25_000_000,
    pid: pid, tid: tid,
    event_name: "sock_connect",
    payload: [2, 443, 0x7f000001, 0].pack("S<nNN").ljust(Vivarium::EVENT_PAYLOAD_SIZE, "\x00"),
    dropped_since_last: 12
  ),
  Vivarium::Correlator::RawEvent.new(
    ktime_ns: t0 + 30_000_000,
    pid: pid, tid: tid,
    event_name: "span_stop",
    payload: "\x00" * Vivarium::EVENT_PAYLOAD_SIZE,
    dropped_since_last: 0
  ),
]

Vivarium::TreeRenderer.new(
  events: events,
  method_table: { method_id => "MyClass#my_method" },
  observer_pid: pid,
  main_tid: tid,
  session_start_iso: "2026-06-02T00:00:00.000Z",
  session_start_ktime: t0,
  session_stop_iso: "2026-06-02T00:00:00.030Z",
  session_stop_ktime: t0 + 30_000_000,
  dest: $stdout
).render
