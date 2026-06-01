# frozen_string_literal: true

require "test_helper"

class VivariumDisplayFilterTest < Test::Unit::TestCase
  test "compile with nil returns permissive filter" do
    filter = Vivarium::DisplayFilter.compile(nil)

    assert_equal false, filter.enabled?
    assert_equal true, filter.allow_span_name?("Kernel#system")
    assert_equal true, filter.allow_event?(
      event_name: "path_open",
      severity: "medium",
      span_name: "Kernel#system",
      payload: "path=/tmp/x",
      pid: 100,
      tid: 100
    )
  end

  test "filters by include and exclude event names" do
    filter = Vivarium::DisplayFilter.compile(
      include_events: ["path_open", "proc_exec"],
      exclude_events: ["proc_exec"]
    )

    assert_equal true, filter.allow_event?(
      event_name: "path_open",
      severity: "medium",
      span_name: "Kernel#system"
    )

    assert_equal false, filter.allow_event?(
      event_name: "proc_exec",
      severity: "medium",
      span_name: "Kernel#system"
    )

    assert_equal false, filter.allow_event?(
      event_name: "task_kill",
      severity: "high",
      span_name: "Kernel#system"
    )
  end

  test "filters by severity pid tid and payload" do
    filter = Vivarium::DisplayFilter.compile(
      severity: "high",
      pid: 101,
      tid: [202],
      payload: /sudo/
    )

    assert_equal true, filter.needs_payload?

    assert_equal true, filter.allow_event?(
      event_name: "bprm_creds",
      severity: "high",
      span_name: "Kernel#system",
      payload: "has_file=1 file=\"/usr/bin/sudo\"",
      pid: 101,
      tid: 202
    )

    assert_equal false, filter.allow_event?(
      event_name: "bprm_creds",
      severity: "high",
      span_name: "Kernel#system",
      payload: "has_file=1 file=\"/bin/sh\"",
      pid: 101,
      tid: 202
    )
  end

  test "filters by span name set and regex" do
    by_set = Vivarium::DisplayFilter.compile(include_span_names: ["Kernel#system"])
    assert_equal true, by_set.allow_span_name?("Kernel#system")
    assert_equal false, by_set.allow_span_name?("Net::HTTP#request")

    by_regex = Vivarium::DisplayFilter.compile(span: /Net::HTTP/)
    assert_equal true, by_regex.allow_span_name?("Net::HTTP#request")
    assert_equal false, by_regex.allow_span_name?("Kernel#system")
  end
end
