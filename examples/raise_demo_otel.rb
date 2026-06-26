#!/usr/bin/env ruby
# frozen_string_literal: true

require "vivarium"

FILTER = {
  include_events: %w[span_raise]
}.freeze

OTEL_ENDPOINT = ENV.fetch("VIVARIUM_OTEL_ENDPOINT", "http://localhost:4318/v1/traces")

def try_step(title)
  puts "[priv-demo] #{title}"
  yield
rescue StandardError => e
  puts "[priv-demo] #{title} failed: #{e.class}: #{e.message}"
end

Vivarium.observe(filter: FILTER, otel_endpoint: OTEL_ENDPOINT) do
  try_step("raise in main") do
    raise "error in main"
  end

  try_step("raise in eval") do
    eval("raise 'error in eval'")
  end

  try_step("raise in nested eval") do
    eval(<<~RUBY)
      eval(<<~INNER_RUBY)
        begin
          eval(<<~INNER_INNER_RUBY)
            puts "Hi"
            raise "error in nested nested eval"
          INNER_INNER_RUBY
        rescue StandardError => _
          puts "Rescued in nested eval"
        end
        File.open("/etc/hosts")
      INNER_RUBY
    RUBY
  end

  try_step("raise in method") do
    File.open("notfound")
  end
end
