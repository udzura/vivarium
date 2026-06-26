#!/usr/bin/env ruby
# frozen_string_literal: true

require "fiddle"
require "vivarium"

FILTER = {
  include_events: %w[dlopen mmap_exec]
}.freeze

OTEL_ENDPOINT = ENV.fetch("VIVARIUM_OTEL_ENDPOINT", "http://localhost:4318/v1/traces")

# Usage:
#   1) In another shell (root): sudo bundle exec vivariumd
#      (dlopen uprobe is attached automatically when libc is found)
#   2) Run this script: bundle exec ruby examples/dlopen_demo_otel.rb
#      or: VIVARIUM_OTEL_ENDPOINT=http://collector:4318/v1/traces bundle exec ruby examples/dlopen_demo_otel.rb
#
# You can disable the dlopen uprobe with `sudo vivariumd --no-dlopen-trace`
# or point at a specific libc with `sudo vivariumd --libc /lib/x86_64-linux-gnu/libc.so.6`.

Vivarium.observe(filter: FILTER, otel_endpoint: OTEL_ENDPOINT) do
  begin
    libm = Fiddle.dlopen("libm.so.6")
    sin_fn = Fiddle::Function.new(libm["sin"], [Fiddle::TYPE_DOUBLE], Fiddle::TYPE_DOUBLE)
    puts "[dlopen_demo] sin(PI/4) = #{sin_fn.call(Math::PI / 4).round(6)}"
    libm.close
  rescue Fiddle::DLError => e
    warn "[dlopen_demo] libm: #{e.message}"
  end

  begin
    libsqlite3 = Fiddle.dlopen("libsqlite3.so.0")
    puts "[dlopen_demo] libsqlite3 loaded: version = #{Fiddle::Function.new(libsqlite3["sqlite3_libversion"], [], Fiddle::TYPE_VOIDP).call}"
    libsqlite3.close
  rescue Fiddle::DLError => e
    warn "[dlopen_demo] libsqlite3: #{e.message}"
  end

  Bundler.with_unbundled_env do
    system("ruby -e 'require \"fiddle\"; Fiddle.dlopen(\"libm.so.6\").close'")
  end
end

puts "[dlopen_demo] done"
