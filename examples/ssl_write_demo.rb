#!/usr/bin/env ruby
# frozen_string_literal: true

require "net/http"
require "uri"
require "vivarium"

# Usage:
#   1) In another shell (root): sudo bundle exec vivariumd
#      (SSL_write uprobe is attached automatically when libssl is found)
#   2) Run this script: bundle exec ruby examples/ssl_write_demo.rb
#
# You can disable the SSL_write uprobe with `sudo vivariumd --no-ssl-trace`
# or point at a specific library with `sudo vivariumd --libssl /path/to/libssl.so.3`.

Vivarium.observe do
  # Net::HTTP uses libssl's SSL_write under the hood. With HTTP/1.1 the
  # request line should appear verbatim in the SSL event payload.
  begin
    uri = URI("https://udzura.jp/")
    Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
      http.get(uri.request_uri)
    end
  rescue StandardError => e
    warn "[ssl_demo] Net::HTTP failed: #{e.class}: #{e.message}"
  end

  # `curl --http2` should produce HTTP/2 traffic; HEADERS frames will be
  # HPACK-decoded if the `http-2` gem is installed on the observer side.
  system("curl -sS --http2 -o /dev/null https://nghttp2.org/ 2>/dev/null")
end

puts "[ssl_demo] done"
