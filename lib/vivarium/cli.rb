# frozen_string_literal: true

require "optparse"

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
      filter = options[:show_all] ? nil : Vivarium::DEFAULT_FILTER

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
  end
end
