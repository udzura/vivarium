#!/usr/bin/env ruby
# frozen_string_literal: true

require "vivarium"

FILTER = {
  include_events: %w[task_kill]
}.freeze

OTEL_ENDPOINT = ENV.fetch("VIVARIUM_OTEL_ENDPOINT", "http://localhost:4318/v1/traces")

# Usage:
#   1) In another shell (root): sudo bundle exec vivariumd
#   2) Run this script: bundle exec ruby examples/signal_kill_demo_otel.rb
#      or: VIVARIUM_OTEL_ENDPOINT=http://collector:4318/v1/traces bundle exec ruby examples/signal_kill_demo_otel.rb

def try_step(title)
  puts "[signal-demo] #{title}"
  yield
rescue StandardError => e
  puts "[signal-demo] #{title} failed: #{e.class}: #{e.message}"
end

child_pid = nil

Vivarium.observe(filter: FILTER, otel_endpoint: OTEL_ENDPOINT) do
  try_step("fork child process") do
    child_pid = fork do
      trap("TERM") { exit!(0) }
      loop { sleep 1 }
    end
    puts "[signal-demo] child pid=#{child_pid}"
  end

  try_step("send TERM signal to child") do
    sleep 0.1
    Process.kill("TERM", child_pid)
  end

  try_step("wait child process") do
    Process.wait(child_pid)
  end
end

puts "[signal-demo] done"
