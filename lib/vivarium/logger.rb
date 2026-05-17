# frozen_string_literal: true

require "json"

module Vivarium
  class Logger
    FORMATS = %i[human json].freeze

    # dest: IO object or file path string
    # format: :human or :json
    # TODO: support flushing in bulk for performance
    def initialize(dest: $stdout, format: :human)
      @format = format.to_sym
      raise ArgumentError, "unknown format: #{@format}; choose from #{FORMATS.join(', ')}" unless FORMATS.include?(@format)

      if dest.is_a?(String)
        @io = File.open(dest, "a")
        @owned = true
      else
        @io = dest
        @owned = false
      end
    end

    def log(events, tp, stack)
      case @format
      when :human then log_human(events, tp, stack)
      when :json  then log_json(events, tp, stack)
      end
      @io.flush
    end

    def info(message)
      @io.puts("[vivarium] #{message}")
      @io.flush
    end

    def close
      @io.close if @owned
    end

    private

    def log_human(events, tp, stack)
      @io.puts "[vivarium] #{events.size} event(s) at #{tp.defined_class}##{tp.method_id} (#{tp.event})"
      @io.puts "  location: #{tp.path}:#{tp.lineno}"
      events.each do |event|
        @io.puts "  pid=#{event.pid} #{event.event_name} payload=#{Vivarium.render_event_payload(event)}"
      end
      @io.puts "  stack:"
      stack.each do |loc|
        @io.puts "    #{loc.path}:#{loc.lineno}:in #{loc.base_label}"
      end
    end

    def log_json(events, tp, stack)
      entry = {
        at:     "#{tp.defined_class}##{tp.method_id}",
        event:  tp.event.to_s,
        path:   tp.path,
        lineno: tp.lineno,
        events: events.map { |e| { pid: e.pid, event_name: e.event_name, payload: Vivarium.render_event_payload(e) } },
        stack:  stack.map { |loc| "#{loc.path}:#{loc.lineno}:in #{loc.base_label}" }
      }
      @io.puts JSON.generate(entry)
    end
  end
end
