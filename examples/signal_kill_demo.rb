#!/usr/bin/env ruby
# frozen_string_literal: true

require "vivarium"

# Usage:
#   1) In another shell (root): sudo bundle exec vivariumd
#   2) Run this script: bundle exec ruby examples/signal_kill_demo.rb

def try_step(title)
  puts "[signal-demo] #{title}"
  yield
rescue StandardError => e
  puts "[signal-demo] #{title} failed: #{e.class}: #{e.message}"
end

child_pid = nil

Vivarium.observe do
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
