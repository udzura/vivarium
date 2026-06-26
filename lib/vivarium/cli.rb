# frozen_string_literal: true

require "optparse"
require "json"

module Vivarium
  module CLI
    def self.run!(argv = ARGV)
      options = { socket_path: Vivarium.socket_path, dest: $stdout }
      parser = OptionParser.new do |opts|
        opts.banner = "Usage: vivarium [options] <command> [args]"
        opts.separator ""
        opts.separator "Commands:"
        opts.separator "  load <script>       Load and observe a Ruby script"
        opts.separator "  report <raw-file>   Render a saved raw event file"
        opts.separator ""
        opts.separator "Options:"
        opts.on("--socket PATH", "vivariumd Unix domain socket path") { |v| options[:socket_path] = v }
        opts.on("-o", "--output PATH", "Log output file (default: stdout)") { |v| options[:dest] = File.open(v, "a") }
        opts.on("--save-raw PATH", "load: save raw events to PATH instead of rendering") { |v| options[:save_raw] = v }
        opts.on("-a", "--all", "report: show all events (ignore default filter)") { options[:show_all] = true }
        opts.on("--filter JSON", "report: filter as a JSON object (overrides --event/default)") { |v| options[:filter_json] = v }
        opts.on("-e", "--event NAMES", "report: comma-separated event names to include") do |v|
          options[:event_names] = v.split(",").map(&:strip).reject(&:empty?)
        end
        opts.on("-d", "--max-span-depth N", Integer, "report: collapse method spans deeper than N (events kept)") do |v|
          options[:max_span_depth] = v
        end
        opts.on("-u", "--dedup-values", "load/report: show repeated path_open/mmap_exec/dlopen/env_caccess values only once") do
          options[:dedup_values] = true
        end
        opts.on("--otel-debug", "report: [debug] dump per-event otel fields (trace/span/uid/gid/comm) instead of the tree") do
          options[:otel_debug] = true
        end
      end
      # order! stops at the first non-option (the subcommand), so parse once to
      # collect options before the command, then again to collect options placed
      # after it (e.g. `vivarium report --dedup-values FILE`).
      begin
        parser.order!(argv)
        command = argv.shift
        parser.order!(argv) if command
      rescue OptionParser::ParseError => e
        abort "#{e.message}\n\n#{parser.help}"
      end

      case command
      when "load"
        run_load!(argv, options)
      when "report"
        run_report!(argv, options)
      else
        abort parser.help
      end
    end

    def self.run_load!(argv, options)
      script = argv.shift
      abort "Usage: vivarium load <script>" unless script
      abort "File not found: #{script}" unless File.exist?(script)

      filter = Vivarium::DEFAULT_FILTER
      filter = filter.merge(dedup_values: true) if options[:dedup_values]

      Vivarium.observe(socket_path: options[:socket_path], dest: options[:dest],
                       filter: filter, save_raw: options[:save_raw]) do
        Kernel.load(File.expand_path(script))
      end
    end

    def self.run_report!(argv, options)
      raw = argv.shift
      abort "Usage: vivarium report <raw-file>" unless raw
      abort "File not found: #{raw}" unless File.exist?(raw)

      data =
        begin
          File.open(raw, "rb") { |io| Vivarium::RawStore.load(io) }
        rescue Vivarium::RawStore::FormatError => e
          abort "Invalid vivarium-raw file #{raw}: #{e.message}"
        end
      meta = data[:meta]

      if options[:otel_debug]
        dump_otel(data[:events], options[:dest])
        return
      end

      filter = resolve_report_filter(options)
      if options[:max_span_depth]
        filter = (filter || {}).merge(max_span_depth: options[:max_span_depth])
      end
      if options[:dedup_values]
        filter = (filter || {}).merge(dedup_values: true)
      end

      Vivarium::TreeRenderer.new(
        events: data[:events],
        observer_pid: meta[:observer_pid],
        main_tid: meta[:main_tid],
        session_start_iso: meta[:session_start_iso],
        session_start_ktime: meta[:session_start_ktime],
        session_stop_iso: meta[:session_stop_iso],
        session_stop_ktime: meta[:session_stop_ktime],
        filter: filter,
        dest: options[:dest]
      ).render
    end

    # [debug] Flat per-event dump of the OTel-oriented fields, sorted by ktime,
    # with method-call span nesting reconstructed in userspace (strategy B).
    # Temporary aid for verifying trace_id/span_id propagation; not the tree view.
    def self.dump_otel(events, dest)
      header = format("%-18s %-7s %-7s %-6s %-6s %-16s %-32s %-16s %-16s %-5s %s",
                      "ktime_ns", "pid", "tid", "uid", "gid", "comm",
                      "trace_id", "span_id", "parent_span", "depth", "event")
      dest.puts header
      compute_otel_rows(events).each do |e, span, parent, depth|
        trace = format("%016x%016x", e.trace_hi.to_i, e.trace_lo.to_i)
        dest.puts format("%-18d %-7d %-7d %-6d %-6d %-16s %-32s %016x %016x %-5d %s",
                         e.ktime_ns, e.pid, e.tid, e.uid.to_i, e.gid.to_i, e.comm.to_s,
                         trace, span, parent, depth, e.event_name)
      end
    end

    # [debug] Reconstruct method-call span nesting (strategy B) from span_start/
    # span_stop, layered on top of the BPF-provided thread/process span. Returns
    # [event, span_id, parent_span_id, depth] per event. Method spans receive a
    # 64-bit id hashed from (trace_id, tid, span-start ktime) to match what an
    # OTel exporter would emit (non-zero, unique within the trace, stable across
    # re-runs); when no method span is active the BPF thread span (and its
    # parent_span_id) is the base frame. The stack is per-tid so spawned children
    # nest independently.
    def self.compute_otel_rows(events)
      sorted = events.sort_by { |e| [e.ktime_ns, e.pid, e.tid] }
      stacks = Hash.new { |h, k| h[k] = [] } # tid => [method_span_id, ...]
      parent_of = {}                         # method_span_id => parent span_id

      sorted.map do |e|
        thread_span = e.span_id.to_i
        stack = stacks[e.tid]

        case e.event_name
        when "span_start"
          parent = stack.empty? ? thread_span : stack.last
          span = synth_span_id(e.trace_hi.to_i, e.trace_lo.to_i, e.tid, e.ktime_ns)
          parent_of[span] = parent
          stack.push(span)
          [e, span, parent, stack.size]
        when "span_stop"
          if stack.empty?
            [e, thread_span, e.parent_span_id.to_i, 0]
          else
            span = stack.pop
            [e, span, parent_of[span] || thread_span, stack.size + 1]
          end
        else
          if stack.empty?
            [e, thread_span, e.parent_span_id.to_i, 0]
          else
            span = stack.last
            [e, span, parent_of[span] || thread_span, stack.size]
          end
        end
      end
    end

    U64_MASK = 0xFFFFFFFFFFFFFFFF

    # Deterministic 64-bit span id for a method span, derived by folding the
    # trace id, tid, and span-start ktime through splitmix64. Non-zero.
    def self.synth_span_id(trace_hi, trace_lo, tid, start_ktime)
      seed = mix64(trace_hi)
      seed = mix64(seed ^ (trace_lo & U64_MASK))
      seed = mix64(seed ^ (tid.to_i & U64_MASK))
      seed = mix64(seed ^ (start_ktime.to_i & U64_MASK))
      seed.zero? ? 1 : seed
    end

    def self.mix64(value)
      x = (value.to_i + 0x9E3779B97F4A7C15) & U64_MASK
      x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & U64_MASK
      x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & U64_MASK
      (x ^ (x >> 31)) & U64_MASK
    end

    # Resolve the report display filter by precedence:
    #   --all  >  --filter JSON  >  --event NAMES  >  DEFAULT_FILTER
    def self.resolve_report_filter(options)
      return nil if options[:show_all]

      if options[:filter_json]
        begin
          return JSON.parse(options[:filter_json])
        rescue JSON::ParserError => e
          abort "Invalid --filter JSON: #{e.message}"
        end
      end

      names = options[:event_names]
      return { include_events: names } if names && !names.empty?

      Vivarium::DEFAULT_FILTER
    end
  end
end
