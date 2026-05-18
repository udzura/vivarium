#!/usr/bin/env ruby
# frozen_string_literal: true

require "vivarium"

# Usage:
#   1) In another shell (root): sudo bundle exec vivariumd
#   2) Run this script: bundle exec ruby examples/privilege_event_demo.rb

def try_step(title)
  puts "[priv-demo] #{title}"
  yield
rescue StandardError => e
  puts "[priv-demo] #{title} failed: #{e.class}: #{e.message}"
end

Vivarium.observe do
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
