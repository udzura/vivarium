# frozen_string_literal: true

module Vivarium
  # Decodes payloads captured from OpenSSL `SSL_write` into a human-readable
  # one-liner. Auto-detects HTTP/1.x request/response lines and HTTP/2 binary
  # frames; HPACK-decompresses HEADERS / CONTINUATION when the `http-2` gem
  # is available, otherwise reports frame types only.
  #
  # HPACK decompressor state is kept per pid. This is sufficient for the
  # common "one HTTPS connection per process" case; with multiple concurrent
  # TLS connections per pid the HPACK table can diverge and decoding may
  # fail — in that case the decompressor for that pid is reset on the next
  # decode error.
  class HttpDecoder
    HTTP1_METHODS = %w[GET POST PUT PATCH DELETE HEAD OPTIONS TRACE CONNECT].freeze
    HTTP2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".b
    H2_FRAME_HEADER_SIZE = 9
    H2_FLAG_END_HEADERS = 0x04
    H2_FLAG_PADDED = 0x08
    H2_FLAG_PRIORITY = 0x20
    FRAME_TYPE_NAMES = {
      0x0 => "DATA",
      0x1 => "HEADERS",
      0x2 => "PRIORITY",
      0x3 => "RST_STREAM",
      0x4 => "SETTINGS",
      0x5 => "PUSH_PROMISE",
      0x6 => "PING",
      0x7 => "GOAWAY",
      0x8 => "WINDOW_UPDATE",
      0x9 => "CONTINUATION"
    }.freeze

    def initialize
      @hpack_available = load_http2_gem
      @decompressors = {}
      @continuation = {}
    end

    def hpack_available?
      @hpack_available
    end

    def render(pid:, data:, data_len:)
      data = data.to_s.b
      data_len = data_len.to_i

      return "data_len=0" if data_len <= 0
      return "len=#{data_len} <no-capture>" if data.empty?

      if (summary = http1_summary(data))
        kind, line = summary
        return "http/1.x #{kind}: #{line}#{truncation_note(data, data_len)}"
      end

      rest = data
      preface_note = ""
      if rest.start_with?(HTTP2_PREFACE)
        preface_note = "preface "
        rest = rest.byteslice(HTTP2_PREFACE.bytesize..) || "".b
      end

      frames = parse_h2_frames(rest)
      if frames.empty?
        if !preface_note.empty?
          return "h2 preface only#{truncation_note(data, data_len)}"
        end
        return "binary len=#{data_len}#{truncation_note(data, data_len)}"
      end

      rendered = frames.map { |f| render_h2_frame(pid, f) }.join(" | ")
      "h2 #{preface_note}#{rendered}#{truncation_note(data, data_len)}"
    end

    private

    def truncation_note(data, data_len)
      return "" if data.bytesize >= data_len

      " (captured #{data.bytesize}/#{data_len}B)"
    end

    def load_http2_gem
      require "http/2"
      true
    rescue LoadError
      false
    end

    def http1_summary(data)
      head = data.byteslice(0, 512).to_s
      first_line = head.split("\r\n", 2).first
      return nil if first_line.nil? || first_line.empty?

      first_line = first_line.dup.force_encoding(Encoding::UTF_8)
      return nil unless first_line.valid_encoding?

      if HTTP1_METHODS.any? { |m| first_line.start_with?("#{m} ") }
        return ["request", first_line]
      end

      if first_line.start_with?("HTTP/1.1 ") || first_line.start_with?("HTTP/1.0 ")
        return ["response", first_line]
      end

      nil
    end

    # @return [Array<Array(Integer, Integer, Integer, String, Boolean)>]
    #   each entry: [frame_type, flags, stream_id, frame_payload, truncated?]
    def parse_h2_frames(payload)
      frames = []
      i = 0
      total = payload.bytesize

      while i + H2_FRAME_HEADER_SIZE <= total
        length = (payload.getbyte(i) << 16) |
                 (payload.getbyte(i + 1) << 8) |
                 payload.getbyte(i + 2)
        frame_type = payload.getbyte(i + 3)
        flags = payload.getbyte(i + 4)
        stream_id = payload.byteslice(i + 5, 4).unpack1("N") & 0x7fff_ffff
        i += H2_FRAME_HEADER_SIZE

        if i + length > total
          remaining = payload.byteslice(i, total - i) || "".b
          frames << [frame_type, flags, stream_id, remaining, true]
          break
        end

        frame_payload = payload.byteslice(i, length) || "".b
        i += length
        frames << [frame_type, flags, stream_id, frame_payload, false]
      end

      # Heuristic: if the very first "frame" doesn't look like a valid HTTP/2
      # frame, refuse the whole parse so we fall back to "binary".
      first_type = frames.first && frames.first[0]
      return [] if first_type && !FRAME_TYPE_NAMES.key?(first_type)

      frames
    end

    def render_h2_frame(pid, frame)
      frame_type, flags, stream_id, frame_payload, truncated = frame
      frame_name = FRAME_TYPE_NAMES.fetch(frame_type, "TYPE0x#{format('%02x', frame_type)}")
      header = "#{frame_name} stream=#{stream_id} flags=0x#{format('%02x', flags)} len=#{frame_payload.bytesize}#{truncated ? '*' : ''}"

      case frame_type
      when 0x1 # HEADERS
        fragment = headers_fragment(flags, frame_payload)
        return "#{header} <bad_payload>" if fragment.nil?

        if (flags & H2_FLAG_END_HEADERS) != 0
          pseudo = decode_hpack(pid, fragment)
          "#{header}#{format_pseudo(pseudo)}"
        else
          @continuation[[pid, stream_id]] = fragment.dup
          "#{header} <collecting>"
        end
      when 0x9 # CONTINUATION
        key = [pid, stream_id]
        unless @continuation.key?(key)
          return "#{header} <orphan>"
        end

        @continuation[key] << frame_payload
        if (flags & H2_FLAG_END_HEADERS) == 0
          "#{header} <collecting>"
        else
          buf = @continuation.delete(key)
          pseudo = decode_hpack(pid, buf)
          "#{header}#{format_pseudo(pseudo)}"
        end
      else
        header
      end
    end

    def headers_fragment(flags, frame_payload)
      start_idx = 0
      end_idx = frame_payload.bytesize

      if (flags & H2_FLAG_PADDED) != 0
        return nil if end_idx.zero?

        pad_len = frame_payload.getbyte(0)
        start_idx += 1
        end_idx = [start_idx, end_idx - pad_len].max
      end

      if (flags & H2_FLAG_PRIORITY) != 0
        return nil if start_idx + 5 > end_idx

        start_idx += 5
      end

      frame_payload.byteslice(start_idx, end_idx - start_idx) || "".b
    end

    def decompressor_for(pid)
      return nil unless @hpack_available

      @decompressors[pid] ||= HTTP2::Header::Decompressor.new
    end

    def decode_hpack(pid, header_block)
      dec = decompressor_for(pid)
      return { ":error" => "hpack-unavailable" } unless dec

      pairs = dec.decode(header_block.b)
      pairs.each_with_object({}) { |(k, v), h| h[k] = v }
    rescue StandardError => e
      @decompressors.delete(pid)
      { ":error" => "#{e.class}: #{e.message}" }
    end

    def format_pseudo(pseudo)
      return " <error: #{pseudo[':error']}>" if pseudo.key?(":error")

      parts = []
      parts << ":method=#{pseudo[':method']}" if pseudo[':method']
      parts << ":path=#{pseudo[':path']}" if pseudo[':path']
      parts << ":authority=#{pseudo[':authority']}" if pseudo[':authority']
      parts << ":status=#{pseudo[':status']}" if pseudo[':status']
      return "" if parts.empty?

      " #{parts.join(' ')}"
    end
  end
end
