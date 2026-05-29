# frozen_string_literal: true

require "set"

module Vivarium
  class TreeRenderer
    SPAN_EVENT_NAMES = %w[span_start span_stop span_raise].to_set.freeze
    FORK_EVENT_NAME = "proc_fork"
    EXEC_EVENT_NAME = "proc_exec"

    LSM_EVENT_NAMES = %w[
      path_open sock_connect odd_socket
      ptrace_check sb_mount kernel_read_file task_kill
      setid_change capable_check bprm_creds
      file_symlink file_hardlink file_rename file_chmod
    ].to_set.freeze

    TP_EVENT_NAMES = %w[
      dns_req proc_exec file_getdents proc_fork
    ].to_set.freeze

    SYNTHETIC_SPAN_NAME = "<no-span>"
    UNRESOLVED_METHOD_PREFIX = "<method_id="

    Span = Struct.new(
      :tid, :method_id, :start_ktime, :stop_ktime, :exit_kind,
      :events, :descendant_pids, :synthetic,
      keyword_init: true
    ) do
      def duration_ns
        return nil unless stop_ktime && start_ktime

        stop_ktime - start_ktime
      end
    end

    EventNode = Struct.new(:kind, :name, :target, :offset_ns, :child_proc, keyword_init: true)
    ProcNode = Struct.new(:pid, :comm, :parent_pid, :children, keyword_init: true)

    def initialize(events:, method_table:, observer_pid:, main_tid:,
                   session_start_iso:, session_start_ktime:,
                   session_stop_iso:, session_stop_ktime:, dest:)
      @events = events
      @method_table = method_table
      @observer_pid = observer_pid
      @main_tid = main_tid
      @session_start_iso = session_start_iso
      @session_start_ktime = session_start_ktime
      @session_stop_iso = session_stop_iso
      @session_stop_ktime = session_stop_ktime
      @dest = dest

      @pid_comm = { observer_pid => "ruby" }
      @pid_parent = {}
      @unresolved_method_ids = []
    end

    def render
      sorted = @events.sort_by { |e| [e.ktime_ns, e.pid, e.tid] }

      real_spans = build_real_spans(sorted)
      assign_descendants(real_spans, sorted)
      all_spans = interleave_synthetic_spans(real_spans)
      assign_events_to_spans(all_spans, sorted)

      print_header
      print_warnings
      print_observer_proc(all_spans)
    end

    private

    def build_real_spans(events)
      open_by_tid = Hash.new { |h, k| h[k] = [] }
      closed = []

      events.each do |ev|
        case ev.event_name
        when "span_start"
          mid = read_method_id(ev.payload)
          span = Span.new(
            tid: ev.tid,
            method_id: mid,
            start_ktime: ev.ktime_ns,
            stop_ktime: nil,
            exit_kind: nil,
            events: [],
            descendant_pids: Set.new,
            synthetic: false
          )
          open_by_tid[ev.tid].push(span)
        when "span_stop", "span_raise"
          stack = open_by_tid[ev.tid]
          next if stack.empty?

          span = stack.pop
          span.stop_ktime = ev.ktime_ns
          span.exit_kind = ev.event_name == "span_raise" ? :raised : :stopped
          closed << span
        end
      end

      open_by_tid.each_value do |stack|
        stack.each do |span|
          span.stop_ktime = @session_stop_ktime || (events.last&.ktime_ns)
          span.exit_kind = :dangling
          closed << span
        end
      end

      closed.sort_by!(&:start_ktime)
      closed
    end

    def assign_descendants(spans, events)
      sorted_spans = spans.reject(&:synthetic).sort_by(&:start_ktime)

      events.each do |ev|
        next unless ev.event_name == FORK_EVENT_NAME

        child_pid = read_proc_fork_child_pid(ev.payload)
        next if child_pid.zero?

        @pid_parent[child_pid] = ev.pid

        owning = innermost_span_for_event(sorted_spans, ev)
        owning&.descendant_pids&.add(child_pid)

        # Closure: if ev.pid is itself a descendant of some span, that span also gains child_pid
        sorted_spans.each do |span|
          next if span == owning
          next unless event_in_span?(ev, span)

          span.descendant_pids.add(child_pid) if span.descendant_pids.include?(ev.pid)
        end
      end
    end

    def interleave_synthetic_spans(real_spans)
      result = []
      cursor = @session_start_ktime || (real_spans.first&.start_ktime) || 0
      session_end = @session_stop_ktime ||
                    real_spans.map(&:stop_ktime).compact.max ||
                    cursor

      real_spans.each do |span|
        if span.start_ktime > cursor
          syn = synthetic_span(cursor, span.start_ktime)
          result << syn if syn
        end
        result << span
        cursor = [cursor, span.stop_ktime || span.start_ktime].max
      end

      if session_end > cursor
        syn = synthetic_span(cursor, session_end)
        result << syn if syn
      end

      result
    end

    def synthetic_span(start_ktime, stop_ktime)
      Span.new(
        tid: @main_tid,
        method_id: nil,
        start_ktime: start_ktime,
        stop_ktime: stop_ktime,
        exit_kind: :stopped,
        events: [],
        descendant_pids: Set.new,
        synthetic: true
      )
    end

    def assign_events_to_spans(spans, events)
      events.each do |ev|
        next if SPAN_EVENT_NAMES.include?(ev.event_name)

        if ev.event_name == "proc_exec"
          @pid_comm[ev.pid] = exec_basename(ev.payload) || @pid_comm[ev.pid] || "?"
        end

        host = find_host_span(spans, ev)
        next unless host

        host.events << ev
        if ev.event_name == FORK_EVENT_NAME
          child_pid = read_proc_fork_child_pid(ev.payload)
          @pid_comm[child_pid] ||= "?"
          host.descendant_pids.add(child_pid)
        end
      end
    end

    def find_host_span(spans, ev)
      candidates = spans.select { |s| event_in_span?(ev, s) }
      return nil if candidates.empty?

      direct = candidates.select { |s| s.tid == ev.tid }
      return direct.last unless direct.empty?

      desc = candidates.select { |s| s.descendant_pids.include?(ev.pid) }
      return desc.last unless desc.empty?

      candidates.find(&:synthetic) || candidates.last
    end

    def innermost_span_for_event(spans, ev)
      candidates = spans.select { |s| event_in_span?(ev, s) && s.tid == ev.tid }
      candidates.last
    end

    def event_in_span?(ev, span)
      return false unless span.start_ktime
      return false if span.stop_ktime && ev.ktime_ns > span.stop_ktime

      ev.ktime_ns >= span.start_ktime
    end

    def print_header
      duration_s = ((@session_stop_ktime || 0) - (@session_start_ktime || 0)) / 1_000_000_000.0
      @dest.puts "# vivarium session"
      @dest.puts "#   started  iso=#{@session_start_iso}  ktime=#{@session_start_ktime}"
      @dest.puts "#   stopped  iso=#{@session_stop_iso}  ktime=#{@session_stop_ktime}"
      @dest.puts "#   duration #{format('%.3fs', duration_s)}"
    end

    def print_warnings
      @unresolved_method_ids.uniq.each do |mid|
        @dest.puts format("# warning method_id=0x%016X unresolved at render time", mid & 0xFFFF_FFFF_FFFF_FFFF)
      end
    end

    def print_observer_proc(spans)
      @dest.puts "[PROC pid=#{@observer_pid} comm=#{@pid_comm[@observer_pid] || 'ruby'}]"
      children = spans.reject { |s| s.synthetic && s.events.empty? }
      children.each_with_index do |span, idx|
        print_span(span, prefix: "", is_last: idx == children.size - 1)
      end
    end

    def print_span(span, prefix:, is_last:)
      marker = is_last ? "└─ " : "├─ "
      @dest.puts "#{prefix}#{marker}#{render_span_header(span)}"
      child_prefix = prefix + (is_last ? "   " : "│  ")
      nodes = build_span_children(span)
      print_nodes(nodes, child_prefix)
    end

    def render_span_header(span)
      name = span_display_name(span)
      dur_text = format_duration(span.duration_ns)
      suffix = case span.exit_kind
               when :raised then "  (raise)"
               when :dangling then "  (open)"
               else ""
               end
      "[SPAN tid=#{span.tid} #{name}  dur=#{dur_text}#{suffix}]"
    end

    def span_display_name(span)
      return SYNTHETIC_SPAN_NAME if span.synthetic
      return SYNTHETIC_SPAN_NAME if span.method_id.nil?

      name = @method_table[span.method_id]
      name ||= Vivarium::Usdt.get_method_name(span.method_id)
      return name if name

      @unresolved_method_ids << span.method_id
      format("#{UNRESOLVED_METHOD_PREFIX}0x%016X>", span.method_id & 0xFFFF_FFFF_FFFF_FFFF)
    end

    def build_span_children(span)
      proc_node_by_pid = {}
      root_children = []

      span.events.each do |ev|
        if ev.event_name == FORK_EVENT_NAME
          child_pid = read_proc_fork_child_pid(ev.payload)
          child_node = ProcNode.new(
            pid: child_pid,
            comm: @pid_comm[child_pid] || "?",
            parent_pid: ev.pid,
            children: []
          )
          proc_node_by_pid[child_pid] = child_node

          ev_node = EventNode.new(
            kind: kind_for(ev),
            name: ev.event_name,
            target: render_target(ev),
            offset_ns: ev.ktime_ns - span.start_ktime,
            child_proc: child_node
          )

          parent_container = container_for_pid(ev.pid, span, proc_node_by_pid, root_children)
          append_event(parent_container, ev_node)
        else
          ev_node = EventNode.new(
            kind: kind_for(ev),
            name: ev.event_name,
            target: render_target(ev),
            offset_ns: ev.ktime_ns - span.start_ktime,
            child_proc: nil
          )

          if ev.pid == @observer_pid && ev.tid == span.tid
            append_event(root_children, ev_node)
          elsif (node = proc_node_by_pid[ev.pid])
            append_event(node.children, ev_node)
          else
            # event from a descendant pid we haven't materialized — synthesize a stub PROC node
            stub = ProcNode.new(
              pid: ev.pid,
              comm: @pid_comm[ev.pid] || "?",
              parent_pid: @pid_parent[ev.pid] || span.tid,
              children: []
            )
            proc_node_by_pid[ev.pid] = stub
            append_event(stub.children, ev_node)
            root_children << stub
          end

          if ev.event_name == EXEC_EVENT_NAME && (node = proc_node_by_pid[ev.pid])
            node.comm = @pid_comm[ev.pid] || node.comm
          end
        end
      end

      root_children
    end

    def container_for_pid(pid, span, proc_node_by_pid, root_children)
      return root_children if pid == @observer_pid

      node = proc_node_by_pid[pid]
      return node.children if node

      # Walk up parent chain to find a known node
      cur = pid
      while (parent = @pid_parent[cur])
        return root_children if parent == @observer_pid
        if (parent_node = proc_node_by_pid[parent])
          stub = ProcNode.new(pid: pid, comm: @pid_comm[pid] || "?", parent_pid: parent, children: [])
          proc_node_by_pid[pid] = stub
          parent_node.children << stub
          return stub.children
        end
        cur = parent
      end

      root_children
    end

    def append_event(container, ev_node)
      container << ev_node
    end

    def print_nodes(nodes, prefix)
      nodes.each_with_index do |node, idx|
        is_last = idx == nodes.size - 1
        case node
        when EventNode
          print_event_node(node, prefix: prefix, is_last: is_last)
        when ProcNode
          print_proc_node(node, prefix: prefix, is_last: is_last)
        end
      end
    end

    def print_event_node(node, prefix:, is_last:)
      marker = is_last && node.child_proc.nil? ? "└─ " : "├─ "
      marker = "└─ " if is_last && node.child_proc.nil?
      marker = "├─ " unless is_last
      marker = "└─ " if is_last
      offset_text = format_offset(node.offset_ns)
      line = format("%-4s %-15s →  %-30s @+%s", node.kind, node.name, node.target, offset_text)
      @dest.puts "#{prefix}#{marker}#{line}"

      if node.child_proc
        child_prefix = prefix + (is_last ? "   " : "│  ")
        print_proc_node(node.child_proc, prefix: child_prefix, is_last: true)
      end
    end

    def print_proc_node(node, prefix:, is_last:)
      marker = is_last ? "└─ " : "├─ "
      header = "[PROC pid=#{node.pid} comm=#{node.comm}"
      header += " parent=#{node.parent_pid}" if node.parent_pid
      header += "]"
      @dest.puts "#{prefix}#{marker}#{header}"
      child_prefix = prefix + (is_last ? "   " : "│  ")
      print_nodes(node.children, child_prefix)
    end

    def kind_for(ev)
      return "USDT" if SPAN_EVENT_NAMES.include?(ev.event_name)
      return "LSM" if LSM_EVENT_NAMES.include?(ev.event_name)
      return "TP" if TP_EVENT_NAMES.include?(ev.event_name)

      "EVT"
    end

    def render_target(ev)
      text = Vivarium.render_event_payload(ev).to_s
      text = text.gsub(/\s+/, " ").strip
      text.empty? ? "-" : text
    end

    def format_duration(ns)
      return "?" unless ns

      ms = ns / 1_000_000.0
      ms < 1.0 ? format("%.1fus", ns / 1_000.0) : format("%.1fms", ms)
    end

    def format_offset(ns)
      return "?" unless ns

      ms = ns / 1_000_000.0
      ms.abs < 1.0 ? format("%.1fus", ns / 1_000.0) : format("%.1fms", ms)
    end

    def read_method_id(payload)
      bytes = payload.to_s.b
      return 0 if bytes.bytesize < 8

      bytes[0, 8].unpack1("q<")
    end

    def read_proc_fork_child_pid(payload)
      bytes = payload.to_s.b
      return 0 if bytes.bytesize < 4

      bytes[0, 4].unpack1("L<")
    end

    def exec_basename(payload)
      slot_size = Vivarium::PROC_EXEC_SLOT_SIZE
      bytes = payload.to_s.b
      return nil if bytes.empty?

      filename = Vivarium.c_string(bytes[0, slot_size])
      return nil if filename.empty?

      File.basename(filename)
    end
  end
end
