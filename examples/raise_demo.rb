#!/usr/bin/env ruby
# frozen_string_literal: true

require "vivarium"

def try_step(title)
  puts "[priv-demo] #{title}"
  yield
rescue StandardError => e
  puts "[priv-demo] #{title} failed: #{e.class}: #{e.message}"
end

Vivarium.observe do
  try_step("raise in main") do
    raise "error in main"
  end

  try_step("raise in eval") do
    eval("raise 'error in eval'")
  end

  try_step("raise in method") do
    File.open("notfound")
  end
end
