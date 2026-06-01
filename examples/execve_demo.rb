#!/usr/bin/env ruby
# frozen_string_literal: true

require "tmpdir"
require "vivarium"

# Usage:
#   1) In another shell (root): sudo bundle exec vivariumd
#   2) Run this script: bundle exec ruby examples/execve_demo.rb

TMP_PREFIX = "vivarium-exec-demo"
FILTER = {
  include_events: %w[proc_exec]
}.freeze

def try_step(title)
  puts "[exec-demo] #{title}"
  yield
rescue StandardError => e
  puts "[exec-demo] #{title} failed: #{e.class}: #{e.message}"
end

Dir.mktmpdir(TMP_PREFIX, "/tmp") do |dir|
  output_path = File.join(dir, "execve-demo.out")

  Vivarium.observe(filter: FILTER) do
    try_step("system echo with multiple args") do
      system("/bin/echo", "hello", "from", "vivarium", out: File::NULL)
    end

    try_step("spawn env with explicit argv") do
      pid = Process.spawn(
        "/usr/bin/env",
        "env",
        "printf",
        "execve-demo\n",
        out: output_path,
        err: File::NULL
      )
      Process.wait(pid)
    end

    try_step("spawn sleep with flag") do
      pid = Process.spawn("/bin/sleep", "0")
      Process.wait(pid)
    end
  end

  puts "[exec-demo] output file: #{output_path}" if File.exist?(output_path)
end

puts "[exec-demo] done"
