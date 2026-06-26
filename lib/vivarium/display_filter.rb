# frozen_string_literal: true

require "set"

module Vivarium
  class DisplayFilter
    attr_reader :include_events, :exclude_events, :include_severities, :include_pids, :include_tids,
                :max_span_depth, :dedup_values

    def self.compile(raw)
      return new if raw.nil?
      return raw if raw.is_a?(self)

      unless raw.respond_to?(:to_h)
        raise ArgumentError, "filter must be a Hash-compatible object"
      end

      new(raw.to_h)
    end

    def initialize(raw = {})
      @raw = symbolize_keys(raw || {})

      @include_events = normalize_string_set(fetch_key(:include_events, :event_names, :events))
      @exclude_events = normalize_string_set(fetch_key(:exclude_events))
      @include_severities = normalize_string_set(fetch_key(:include_severities, :severities, :severity))
      @include_pids = normalize_integer_set(fetch_key(:include_pids, :pids, :pid))
      @include_tids = normalize_integer_set(fetch_key(:include_tids, :tids, :tid))

      @include_span_names = normalize_string_set(fetch_key(:include_span_names, :span_names))
      @span_pattern = normalize_pattern(fetch_key(:span, :span_pattern))
      @max_span_depth = normalize_integer(fetch_key(:max_span_depth, :max_depth))
      @dedup_values = normalize_bool(fetch_key(:dedup_values, :dedup))

      payload_value = fetch_key(:payload)
      @payload_pattern = normalize_pattern(fetch_key(:payload_pattern))
      @payload_patterns_by_event = {}
      if payload_value.is_a?(Hash)
        @payload_patterns_by_event = normalize_payload_map(payload_value)
      else
        @payload_pattern ||= normalize_pattern(payload_value)
      end
    end

    def enabled?
      !@raw.empty?
    end

    def needs_payload?
      !@payload_pattern.nil? || !@payload_patterns_by_event.empty? || @dedup_values
    end

    def allow_span_name?(span_name)
      return true if @include_span_names.empty? && @span_pattern.nil?

      name = span_name.to_s
      return true if @include_span_names.include?(name)
      return true if @span_pattern && @span_pattern.match?(name)

      false
    end

    def allow_event?(event_name:, severity:, span_name:, payload: nil, pid: nil, tid: nil)
      return false unless allow_span_name?(span_name)

      name = event_name.to_s
      sev = severity.to_s

      return false if @exclude_events.include?(name)
      return false if !@include_events.empty? && !@include_events.include?(name)
      return false if !@include_severities.empty? && !@include_severities.include?(sev)
      return false if !@include_pids.empty? && !@include_pids.include?(pid.to_i)
      return false if !@include_tids.empty? && !@include_tids.include?(tid.to_i)

      payload_pattern = @payload_patterns_by_event[name] || @payload_pattern
      if payload_pattern
        return false if payload.nil?
        return false unless payload_pattern.match?(payload.to_s)
      end

      true
    end

    private

    def fetch_key(*keys)
      keys.each do |key|
        return @raw[key] if @raw.key?(key)
      end
      nil
    end

    def symbolize_keys(hash)
      hash.each_with_object({}) do |(k, v), out|
        out[k.respond_to?(:to_sym) ? k.to_sym : k] = v
      end
    end

    def normalize_string_set(value)
      arr = case value
            when nil
              []
            when Array
              value
            else
              [value]
            end

      arr.each_with_object(Set.new) do |item, set|
        str = item.to_s.strip
        set << str unless str.empty?
      end
    end

    def normalize_integer_set(value)
      arr = case value
            when nil
              []
            when Array
              value
            else
              [value]
            end

      arr.each_with_object(Set.new) do |item, set|
        begin
          set << Integer(item)
        rescue ArgumentError, TypeError
          nil
        end
      end
    end

    def normalize_integer(value)
      return nil if value.nil?

      n = Integer(value)
      n.positive? ? n : nil
    rescue ArgumentError, TypeError
      nil
    end

    def normalize_bool(value)
      case value
      when true then true
      when false, nil then false
      when String then %w[1 true yes on].include?(value.strip.downcase)
      when Numeric then !value.zero?
      else true
      end
    end

    def normalize_pattern(value)
      case value
      when nil
        nil
      when Regexp
        value
      when String
        return nil if value.empty?

        Regexp.new(Regexp.escape(value))
      else
        nil
      end
    end

    def normalize_payload_map(raw_map)
      raw_map.each_with_object({}) do |(event_name, pattern), out|
        key = event_name.to_s.strip
        next if key.empty?

        normalized = normalize_pattern(pattern)
        next unless normalized

        out[key] = normalized
      end
    end
  end
end
