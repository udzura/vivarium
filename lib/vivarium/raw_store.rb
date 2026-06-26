# frozen_string_literal: true

require "json"

module Vivarium
  RawEvent = Struct.new(
    :ktime_ns, :pid, :tid, :uid, :gid,
    :trace_hi, :trace_lo, :span_id, :parent_span_id, :comm,
    :event_name, :payload, :dropped_since_last,
    keyword_init: true
  )

  # Reads and writes the vivarium-raw file format: a single JSON metadata line
  # followed by fixed-size (EVENT_STRUCT_SIZE) event_t records. The record layout
  # mirrors the C struct event_t so it round-trips losslessly.
  module RawStore
    # Raised when a file is not a valid vivarium-raw capture.
    class FormatError < StandardError; end

    FORMAT = "vivarium-raw"
    VERSION = 2
    PACK_FMT = "Q<L<L<L<L<Q<Q<Q<Q<a16a16a256Q<" # struct event_t (352B)

    def self.pack_record(ev)
      [
        ev.ktime_ns, ev.pid, ev.tid, ev.uid.to_i, ev.gid.to_i,
        ev.trace_hi.to_i, ev.trace_lo.to_i, ev.span_id.to_i, ev.parent_span_id.to_i,
        ev.comm.to_s.b.ljust(EVENT_COMM_SIZE, "\x00")[0, EVENT_COMM_SIZE],
        ev.event_name.to_s.b.ljust(EVENT_NAME_SIZE, "\x00")[0, EVENT_NAME_SIZE],
        ev.payload.to_s.b.ljust(EVENT_PAYLOAD_SIZE, "\x00")[0, EVENT_PAYLOAD_SIZE],
        ev.dropped_since_last
      ].pack(PACK_FMT)
    end

    def self.unpack_record(bytes)
      bytes = bytes.to_s.b
      bytes = bytes.ljust(EVENT_STRUCT_SIZE, "\x00") if bytes.bytesize < EVENT_STRUCT_SIZE

      RawEvent.new(
        ktime_ns:           bytes[EVENT_TS_OFFSET,         EVENT_TS_SIZE].unpack1("Q<"),
        pid:                bytes[EVENT_PID_OFFSET,         4].unpack1("L<"),
        tid:                bytes[EVENT_TID_OFFSET,         4].unpack1("L<"),
        uid:                bytes[EVENT_UID_OFFSET,         4].unpack1("L<"),
        gid:                bytes[EVENT_GID_OFFSET,         4].unpack1("L<"),
        trace_hi:           bytes[EVENT_TRACE_HI_OFFSET,    8].unpack1("Q<"),
        trace_lo:           bytes[EVENT_TRACE_LO_OFFSET,    8].unpack1("Q<"),
        span_id:            bytes[EVENT_SPAN_OFFSET,        8].unpack1("Q<"),
        parent_span_id:     bytes[EVENT_PARENT_SPAN_OFFSET, 8].unpack1("Q<"),
        comm:               Vivarium.c_string(bytes[EVENT_COMM_OFFSET, EVENT_COMM_SIZE]),
        event_name:         Vivarium.c_string(bytes[EVENT_NAME_OFFSET, EVENT_NAME_SIZE]),
        payload:            bytes[EVENT_PAYLOAD_OFFSET,     EVENT_PAYLOAD_SIZE].to_s.b,
        dropped_since_last: bytes[EVENT_DROPPED_OFFSET,     8].unpack1("Q<")
      )
    end

    # io: a binary-writable IO. meta: session metadata Hash.
    def self.dump(io, events:, meta:)
      header = meta.merge(
        format: FORMAT, version: VERSION,
        event_struct_size: EVENT_STRUCT_SIZE, event_count: events.size
      )
      io.binmode
      io.write(JSON.generate(header))
      io.write("\n")
      events.each { |ev| io.write(pack_record(ev)) }
    end

    # Returns { meta: Hash(symbol keys), events: [RawEvent, ...] }.
    def self.load(io)
      io.binmode
      line = io.gets
      raise FormatError, "empty file" if line.nil?

      begin
        meta = JSON.parse(line, symbolize_names: true)
      rescue JSON::ParserError => e
        raise FormatError, "header is not valid JSON: #{e.message}"
      end
      raise FormatError, "missing JSON object header" unless meta.is_a?(Hash)
      unless meta[:format] == FORMAT
        raise FormatError, "format=#{meta[:format].inspect} (expected #{FORMAT.inspect})"
      end

      size = meta[:event_struct_size]
      if size && size != EVENT_STRUCT_SIZE
        raise FormatError,
              "event_struct_size=#{size} (expected #{EVENT_STRUCT_SIZE}); " \
              "incompatible capture (likely an older vivarium-raw v1 file)"
      end

      events = []
      while (rec = io.read(EVENT_STRUCT_SIZE))
        break if rec.bytesize < EVENT_STRUCT_SIZE

        events << unpack_record(rec)
      end
      { meta: meta, events: events }
    end
  end
end
