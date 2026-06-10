#!/usr/bin/env ruby
# frozen_string_literal: true

require "vivarium"

# Usage:
#   1) In another shell (root): sudo bundle exec vivariumd
#   2) Run this script: bundle exec ruby examples/env_access_ruby_demo.rb
#
# This demo intentionally triggers Ruby-side ENV access methods so they are
# observed through TracePoint -> SPAN (USDT) path.

FILTER = {
  include_events: %w[span_start span_stop env_caccess]
}.freeze

def safe_fetch(key)
  ENV.fetch(key)
rescue KeyError
  nil
end

def demo_env_reads
  ENV["HOME"]
  safe_fetch("PATH")
  ENV.key?("SHELL")
end

def demo_env_writes
  ENV["VIVARIUM_ENV_DEMO_A"] = "1"
  ENV.store("VIVARIUM_ENV_DEMO_B", "2")
  ENV.delete("VIVARIUM_ENV_DEMO_A")
  ENV.replace(ENV.to_h.merge("VIVARIUM_ENV_DEMO_C" => "3"))
  ENV.delete("VIVARIUM_ENV_DEMO_B")
  ENV.delete("VIVARIUM_ENV_DEMO_C")
end

Vivarium.observe(filter: FILTER) do
  original_env = ENV.to_h

  puts "[env-ruby-demo] read methods"
  demo_env_reads

  puts "[env-ruby-demo] write methods"
  demo_env_writes

  puts "[env-ruby-demo] clear"
  ENV.clear
  ENV.replace(original_env)
end

puts "[env-ruby-demo] done"
