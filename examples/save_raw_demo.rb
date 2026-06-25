#!/usr/bin/env ruby
# frozen_string_literal: true

require "net/http"
require "uri"
require "vivarium"

# Where to write the raw capture. Override with VIVARIUM_RAW_PATH.
RAW_PATH = ENV.fetch("VIVARIUM_RAW_PATH", "/tmp/vivarium_save_raw_demo.vivraw")

# Usage:
#   1) In another shell (root): sudo bundle exec vivariumd
#   2) Run this script: bundle exec ruby examples/save_raw_demo.rb
#   3) Render the saved capture later (as many times as you like):
#        bundle exec vivarium report #{RAW_PATH}
#        bundle exec vivarium report --all #{RAW_PATH}   # ignore the default filter
#
# Note: when `save_raw:` is given, observation runs in *save-only* mode — no live
# tree is drawn. The full, unfiltered event stream is written to RAW_PATH, so you
# can re-report the same capture with different filters afterwards.

Vivarium.observe(save_raw: RAW_PATH) do
  # A few security-relevant actions to capture:

  # File write (LSM path_open + File span)
  path = "/tmp/vivarium_save_raw_demo.txt"
  File.write(path, "hello from save_raw demo\n")
  File.chmod(0o600, path)
  File.delete(path)

  # Outbound HTTPS (ssl_write + sock_connect + dns_req)
  begin
    uri = URI("https://udzura.jp/")
    Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
      http.get(uri.request_uri)
    end
  rescue StandardError => e
    warn "[save_raw_demo] Net::HTTP failed: #{e.class}: #{e.message}"
  end

  # Spawn a child process (proc_fork / proc_exec)
  system("true")
end

puts "[save_raw_demo] raw events saved to #{RAW_PATH}"
puts "[save_raw_demo] render it with: bundle exec vivarium report #{RAW_PATH}"
