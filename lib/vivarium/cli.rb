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
        opts.on("--all", "report: show all events (ignore default filter)") { options[:show_all] = true }
        opts.on("--filter JSON", "report: filter as a JSON object (overrides --event/default)") { |v| options[:filter_json] = v }
        opts.on("--event NAMES", "report: comma-separated event names to include") do |v|
          options[:event_names] = v.split(",").map(&:strip).reject(&:empty?)
        end
        opts.on("--max-span-depth N", Integer, "report: collapse method spans deeper than N (events kept)") do |v|
          options[:max_span_depth] = v
        end
      end
      parser.order!(argv)

      command = argv.shift
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

      Vivarium.observe(socket_path: options[:socket_path], dest: options[:dest],
                       filter: Vivarium::DEFAULT_FILTER, save_raw: options[:save_raw]) do
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
      filter = resolve_report_filter(options)
      if options[:max_span_depth]
        filter = (filter || {}).merge(max_span_depth: options[:max_span_depth])
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
