#!/usr/bin/env ruby
# frozen_string_literal: true

require "vivarium"

FILTER = {
  include_events: %w[setid_change capable_check bprm_creds]
}.freeze

OTEL_ENDPOINT = ENV.fetch("VIVARIUM_OTEL_ENDPOINT", "http://localhost:4318/v1/traces")

# Usage:
#   1) In another shell (root): sudo bundle exec vivariumd
#   2) Run this script: bundle exec ruby examples/privilege_event_demo_otel.rb
#      or: VIVARIUM_OTEL_ENDPOINT=http://collector:4318/v1/traces bundle exec ruby examples/privilege_event_demo_otel.rb

def try_step(title)
  puts "[priv-demo] #{title}"
  yield
rescue StandardError => e
  puts "[priv-demo] #{title} failed: #{e.class}: #{e.message}"
end

Vivarium.observe(filter: FILTER, otel_endpoint: OTEL_ENDPOINT) do
  try_step("attempt setuid(0)") do
    Process::UID.change_privilege(0)
  end

  try_step("attempt setgid(0)") do
    Process::GID.change_privilege(0)
  end

  try_step("attempt opening /etc/shadow") do
    File.read("/etc/shadow")
  end

  try_step("exec setuid-related binary") do
    pid = Process.spawn("/usr/bin/sudo", "-n", "true", out: File::NULL, err: File::NULL)
    Process.wait(pid)
  rescue Errno::ENOENT
    puts "[priv-demo] sudo not found; skipped"
  end
end

puts "[priv-demo] done"
