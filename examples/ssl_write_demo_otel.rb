#!/usr/bin/env ruby
# frozen_string_literal: true

require "net/http"
require "uri"
require "vivarium"

FILTER = {
  include_events: %w[ssl_write]
}.freeze

OTEL_ENDPOINT = ENV.fetch("VIVARIUM_OTEL_ENDPOINT", "http://localhost:4318/v1/traces")

# Usage:
#   1) In another shell (root): sudo bundle exec vivariumd
#      (SSL_write uprobe is attached automatically when libssl is found)
#   2) Run this script: bundle exec ruby examples/ssl_write_demo_otel.rb
#      or: VIVARIUM_OTEL_ENDPOINT=http://collector:4318/v1/traces bundle exec ruby examples/ssl_write_demo_otel.rb
#
# You can disable the SSL_write uprobe with `sudo vivariumd --no-ssl-trace`
# or point at a specific library with `sudo vivariumd --libssl /path/to/libssl.so.3`.

Vivarium.observe(filter: FILTER, otel_endpoint: OTEL_ENDPOINT) do
  begin
    uri = URI("https://udzura.jp/")
    Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
      http.get(uri.request_uri)
    end
  rescue StandardError => e
    warn "[ssl_demo] Net::HTTP failed: #{e.class}: #{e.message}"
  end

  system("curl -sS --http2 -o /dev/null https://nghttp2.org/ 2>/dev/null")
end

puts "[ssl_demo] done"
