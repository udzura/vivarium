#!/usr/bin/env ruby
# frozen_string_literal: true

require "rbconfig"
require "vivarium"

# Usage:
#   1) In another shell (root): sudo bundle exec vivariumd
#   2) Run this script: bundle exec ruby examples/env_access_external_demo.rb
#
# This demo launches an external Ruby process and forces direct libc calls to
# getenv/setenv/unsetenv/putenv/clearenv through Fiddle.
# These should appear as eBPF events with event_name=env_caccess.

FILTER = {
  include_events: %w[env_caccess proc_fork proc_exec]
}.freeze

CHILD_CODE = <<~RUBY
  require "fiddle"

  libc = begin
    Fiddle.dlopen("libc.so.6")
  rescue Fiddle::DLError
    Fiddle.dlopen(nil)
  end

  getenv = Fiddle::Function.new(libc["getenv"], [Fiddle::TYPE_VOIDP], Fiddle::TYPE_VOIDP)
  setenv = Fiddle::Function.new(libc["setenv"], [Fiddle::TYPE_VOIDP, Fiddle::TYPE_VOIDP, Fiddle::TYPE_INT], Fiddle::TYPE_INT)
  unsetenv = Fiddle::Function.new(libc["unsetenv"], [Fiddle::TYPE_VOIDP], Fiddle::TYPE_INT)
  putenv = Fiddle::Function.new(libc["putenv"], [Fiddle::TYPE_VOIDP], Fiddle::TYPE_INT)
  clearenv = Fiddle::Function.new(libc["clearenv"], [], Fiddle::TYPE_INT)

  key = "VIVARIUM_ENV_EXT_DEMO"
  putenv_buf = "VIVARIUM_ENV_EXT_PUT=from_putenv"

  getenv.call("HOME")
  setenv.call(key, "from_setenv", 1)
  getenv.call(key)
  putenv.call(putenv_buf)
  unsetenv.call(key)
  clearenv.call
RUBY

Vivarium.observe(filter: FILTER) do
  puts "[env-external-demo] spawning external child"
  pid = Process.spawn(RbConfig.ruby, "-e", CHILD_CODE)
  Process.wait(pid)
  puts "[env-external-demo] child exit status=#{Process.last_status.exitstatus}"
end

puts "[env-external-demo] done"
