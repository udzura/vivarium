#!/usr/bin/env ruby
# frozen_string_literal: true

require "net/http"
require "uri"
require "vivarium"

OTEL_ENDPOINT = ENV.fetch("VIVARIUM_OTEL_ENDPOINT", "http://localhost:4318/v1/traces")

# Usage:
#   1) In another shell (root): sudo bundle exec vivariumd
#   2) Run this script: bundle exec ruby examples/save_raw_demo_otel.rb
#      or: VIVARIUM_OTEL_ENDPOINT=http://collector:4318/v1/traces bundle exec ruby examples/save_raw_demo_otel.rb
#
# Note: this is the OTLP streaming variant of save_raw_demo.rb, so no vivraw file is written.

Vivarium.observe(otel_endpoint: OTEL_ENDPOINT) do
  path = "/tmp/vivarium_save_raw_demo.txt"
  File.write(path, "hello from save_raw demo\n")
  File.chmod(0o600, path)
  File.delete(path)

  begin
    uri = URI("https://udzura.jp/")
    Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
      http.get(uri.request_uri)
    end
  rescue StandardError => e
    warn "[save_raw_demo] Net::HTTP failed: #{e.class}: #{e.message}"
  end

  system("true")
end

puts "[save_raw_demo] streamed OTLP events to #{OTEL_ENDPOINT}"
