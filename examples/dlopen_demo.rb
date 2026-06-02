#!/usr/bin/env ruby
# frozen_string_literal: true

require "fiddle"
require "vivarium"

FILTER = {
  include_events: %w[dlopen mmap_exec]
}.freeze

# Usage:
#   1) In another shell (root): sudo bundle exec vivariumd
#      (dlopen uprobe is attached automatically when libc is found)
#   2) Run this script: bundle exec ruby examples/dlopen_demo.rb
#
# Expected output: "DL dlopen" and "DL mmap_exec" events for each
# library loaded via Fiddle.dlopen.
#
# You can disable the dlopen uprobe with `sudo vivariumd --no-dlopen-trace`
# or point at a specific libc with `sudo vivariumd --libc /lib/x86_64-linux-gnu/libc.so.6`.

Vivarium.observe(filter: FILTER) do
  # libm: math functions — almost universally available
  begin
    libm = Fiddle.dlopen("libm.so.6")
    sin_fn = Fiddle::Function.new(libm["sin"], [Fiddle::TYPE_DOUBLE], Fiddle::TYPE_DOUBLE)
    puts "[dlopen_demo] sin(PI/4) = #{sin_fn.call(Math::PI / 4).round(6)}"
    libm.close
  rescue Fiddle::DLError => e
    warn "[dlopen_demo] libm: #{e.message}"
  end

  # libz: zlib compression — common on most Linux systems
  begin
    libz = Fiddle.dlopen("libz.so.1")
    puts "[dlopen_demo] libz loaded: zlibVersion = #{Fiddle::Function.new(libz["zlibVersion"], [], Fiddle::TYPE_VOIDP).call}"
    libz.close
  rescue Fiddle::DLError => e
    warn "[dlopen_demo] libz: #{e.message}"
  end

  # Spawn a child process that also calls dlopen — its events should
  # appear under a PROC node in the tree (descendant PID tracking).
  system("ruby -e 'require \"fiddle\"; Fiddle.dlopen(\"libm.so.6\").close'")
end

puts "[dlopen_demo] done"
