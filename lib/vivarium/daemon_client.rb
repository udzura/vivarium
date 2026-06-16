# frozen_string_literal: true

require "socket"

module Vivarium
  # HTTP-over-Unix-domain-socket client for talking to vivariumd. The client side
  # never touches BPF maps or the ring buffer directly; everything goes through here.
  class DaemonClient
    def initialize(socket_path: Vivarium.socket_path)
      @socket_path = socket_path
    end

    def healthy?
      status, = simple_request("GET", "/healthz")
      status == 200
    rescue Error
      false
    end

    def register(pid)
      simple_request("PUT", "/targets/#{pid}")
    end

    def unregister(pid)
      simple_request("DELETE", "/targets/#{pid}")
    end

    # Opens a dedicated streaming connection to GET /events, consumes the response
    # headers, and returns the still-open socket positioned at the start of the
    # chunked body. The caller is responsible for reading chunks and closing it.
    def open_event_stream(since: nil)
      sock = connect
      path = since ? "/events?since=#{since}" : "/events"
      sock.write("GET #{path} HTTP/1.1\r\n")
      sock.write("Host: vivarium\r\n")
      sock.write("Accept: application/octet-stream\r\n")
      sock.write("\r\n")
      read_response_headers(sock)
      sock
    end

    private

    def connect
      UNIXSocket.new(@socket_path)
    rescue Errno::ENOENT, Errno::ECONNREFUSED => e
      raise Error, "cannot connect to vivariumd at #{@socket_path}: #{e.message} " \
                   "(is vivariumd running?)"
    end

    def simple_request(method, path)
      sock = connect
      begin
        sock.write("#{method} #{path} HTTP/1.1\r\n")
        sock.write("Host: vivarium\r\n")
        sock.write("Connection: close\r\n")
        sock.write("\r\n")
        status = read_status(sock)
        body = sock.read
        [status, body]
      ensure
        sock.close
      end
    end

    def read_status(sock)
      status_line = sock.gets
      return nil if status_line.nil?

      status_line.split(" ")[1].to_i
    end

    def read_response_headers(sock)
      read_status(sock)
      while (line = sock.gets)
        break if line == "\r\n" || line == "\n"
      end
    end
  end
end
