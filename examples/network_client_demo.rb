#!/usr/bin/env ruby
# frozen_string_literal: true

require "socket"
require "vivarium"

# Usage:
#   1) In another shell (root): sudo bundle exec vivariumd
#   2) Run this script: bundle exec ruby examples/network_client_demo.rb

def try_step(title)
  puts "[client] #{title}"
  yield
rescue StandardError => e
  puts "[client] #{title} failed: #{e.class}: #{e.message}"
end

Vivarium.observe do
  # Likely emits sock_connect and dns_req via resolver traffic.
  try_step("system: DNS lookup") do
    system("getent hosts dns-lookup.example.com >/dev/null 2>&1 || true")
  end

  # Likely emits sock_connect through HTTPS connection attempts.
  try_step("system: curl") do
    system("curl -I https://curl.example.com >/dev/null 2>&1 || true")
  end

  # Explicit connect path.
  try_step("Ruby TCP connect") do
    sock = TCPSocket.new("tcp.example.com", 80)
    sock.close
  end

  # Raw DNS query payload, useful for dns_req decode testing.
  try_step("Ruby UDP DNS query") do
    dns_query = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" +
                "\x09udp-query\x07example\x03com\x00" +
                "\x00\x01\x00\x01"

    udp = UDPSocket.new
    begin
      udp.connect("127.0.0.53", 53)
    rescue StandardError
      udp.connect("8.8.8.8", 53)
    end
    udp.send(dns_query, 0)
    udp.close
  end

  # Explicit sendto path for DNS payload visibility.
  try_step("Ruby UDP sendto DNS query") do
    dns_query = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" +
                "\x06sendto\x07example\x03com\x00" +
                "\x00\x01\x00\x01"

    udp = UDPSocket.new
    udp.send(dns_query, 0, "127.0.0.53", 53)
    udp.close
  end

  # Intentionally unusual socket type to trigger odd_socket.
  try_step("Ruby odd socket attempt") do
    af_packet = Socket.const_defined?(:AF_PACKET) ? Socket::AF_PACKET : 17
    raw = Socket.new(af_packet, Socket::SOCK_RAW, 0)
    raw.close
  end
end

puts "[client] done"
