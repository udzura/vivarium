# frozen_string_literal: true

require "set"

module Vivarium
  # Box provides an isolated execution context where method calls are automatically traced
  # through Vivarium's observation system.
  #
  # Usage:
  #   box = Vivarium::Box.new
  #   box.eval('class MyClass; def foo; "result"; end; end')
  #   result = box::MyClass.new.foo  # automatically traced if Vivarium.observe is active
  #
  class Box < Module
    DEFAULT_FILTER = {
      include_events: %w[
        proc_fork proc_exec span_start span_stop
        sock_connect dns_req odd_socket
        ssl_write
        dlopen mmap_exec
        task_kill
        setid_change capable_check bprm_creds
      ]
    }

    def initialize(pin_dir: Vivarium.bpf_pin_dir, dest: $stdout, filter: DEFAULT_FILTER)
      super()
      @inner_box = Ruby::Box.new
      @pin_dir = pin_dir
      @dest = dest
      @filter = filter
      @session = nil

      @tracing_level = [0]
      # Set up TracePoint to automatically trace method calls within this box
      @tracer = TracePoint.new(:call, :return) do |tp|
        handle_trace_event(tp, @tracing_level, @inner_box)
      end
    end
    attr_reader :inner_box, :tracer

    # Evaluate code within the box context
    def eval(code)
      result = nil
      Vivarium.observe(filter: @filter) do
        result = @inner_box.eval(code)
      end
      result
    end

    # Require a file within the box context
    # Automatically traced if Vivarium.observe is active
    def require(path)
      result = nil
      Vivarium.observe(filter: @filter) do
        result = @inner_box.require(path)
      end
      result
    end

    # Require a file relative to the current file within the box context
    # Automatically traced if Vivarium.observe is active
    def require_relative(path)
      result = nil
      Vivarium.observe(filter: @filter) do
        result = @inner_box.require_relative(path)
      end
      result
    end

    # Load a file within the box context (executed every time, unlike require)
    # Automatically traced if Vivarium.observe is active
    def load(path, wrap = false)
      result = nil
      Vivarium.observe(filter: @filter) do
        result = @inner_box.load(path, wrap)
      end
      result
    end

    # Intercept constant access to resolve from the box's evaluated context
    def const_missing(name)
      @inner_box.const_get(name)
    rescue NameError => e
      raise NameError, "#{name} not found in box: #{e.message}"
    end

    def done_load!
      @tracer.enable
    end

    private

    def handle_trace_event(tp, tracing_level, target_box)
      begin
        if should_trace_call?(tp, target_box)
          case tp.event
          when :call
            if tracing_level[0].zero?
              start_vivarium_observation
            end
            tracing_level[0] += 1
            file_arg = Vivarium.tail_fit_string(tp.path, Vivarium::SPAN_FILE_ARG_MAX)
            root = Ruby::Box.root
            root::Vivarium::Usdt.start("#{tp.defined_class}", tp.method_id.to_s, file: file_arg, lineno: tp.lineno)
          when :return
            tracing_level[0] -= 1
            file_arg = Vivarium.tail_fit_string(tp.path, Vivarium::SPAN_FILE_ARG_MAX)
            root = Ruby::Box.root
            root::Vivarium::Usdt.stop("#{tp.defined_class}", tp.method_id.to_s, file: file_arg, lineno: tp.lineno)
            if tracing_level[0].zero?
              stop_vivarium_observation
            end
          end
        end
      rescue StandardError
        # Silently ignore tracing errors to avoid breaking user code
      end
    end

    def should_trace_call?(tp, target_box)
      tp.binding.eval("Ruby::Box.current") == target_box
    end

    def start_vivarium_observation
      puts "[debug] Starting Vivarium observation for Box method calls"
      @session = Vivarium.top_observe(pin_dir: @pin_dir, dest: @dest, filter: @filter)
    end

    def stop_vivarium_observation
      puts "[debug] Stopping Vivarium observation for Box method calls"
      @session&.stop
      @session = nil
    end
  end
end
