# frozen_string_literal: true

require "set"
require_relative "http_decoder"

module Vivarium
  class TreeRenderer
    SPAN_EVENT_NAMES = %w[span_start span_stop].to_set.freeze
    FORK_EVENT_NAME = "proc_fork"
    EXEC_EVENT_NAME = "proc_exec"
    SSL_WRITE_EVENT_NAME = "ssl_write"

    LSM_EVENT_NAMES = %w[
      path_open sock_connect odd_socket
      ptrace_check sb_mount kernel_read_file task_kill
      setid_change capable_check bprm_creds
      file_symlink file_hardlink file_rename file_chmod
    ].to_set.freeze

    TP_EVENT_NAMES = %w[
      dns_req proc_exec file_getdents proc_fork
    ].to_set.freeze

    UPROBE_EVENT_NAMES = %w[ssl_write].to_set.freeze
    DL_EVENT_NAMES = %w[dlopen mmap_exec].to_set.freeze

    # Events whose traced value repeats heavily (same file/lib/env key opened over
    # and over). With dedup_values on, each (event_name, value) pair is rendered
    # only on its first occurrence in the session; later repeats are suppressed.
    DEDUP_EVENT_NAMES = %w[path_open mmap_exec dlopen env_caccess].to_set.freeze

    SYNTHETIC_SPAN_NAME = "<no-span>"
    UNRESOLVED_METHOD_PREFIX = "<method_id="

    Span = Struct.new(
      :tid, :method_name, :file_name, :lineno, :start_ktime, :stop_ktime, :exit_kind,
      :events, :descendant_pids, :synthetic, :raised,
      keyword_init: true
    ) do
      def duration_ns
        return nil unless stop_ktime && start_ktime

        stop_ktime - start_ktime
      end

      # Span is mutable (stop_ktime, events, descendant_pids are written after creation).
      # Use object identity for Hash/Set so keys remain stable across mutations.
      def hash
        object_id
      end

      def eql?(other)
        equal?(other)
      end
    end

    EventNode = Struct.new(:kind, :name, :target, :offset_ns, :child_proc, keyword_init: true)
    ProcNode = Struct.new(:pid, :comm, :parent_pid, :children, keyword_init: true)

    def initialize(events:, observer_pid:, main_tid:,
                   session_start_iso:, session_start_ktime:,
                   session_stop_iso:, session_stop_ktime:, filter: nil, dest:)
      @events = events
      @observer_pid = observer_pid
      @main_tid = main_tid
      @session_start_iso = session_start_iso
      @session_start_ktime = session_start_ktime
      @session_stop_iso = session_stop_iso
      @session_stop_ktime = session_stop_ktime
      @display_filter = Vivarium::DisplayFilter.compile(filter)
      @dest = dest

      @pid_comm = { observer_pid => "ruby" }
      @pid_parent = {}
      @dedup_seen = Set.new
    end

    def render
      sorted = @events.sort_by { |e| [e.ktime_ns, e.pid, e.tid] }

      real_spans, @children_map = build_real_spans(sorted)
      @child_span_set = @children_map.values.flatten.to_set

      assign_descendants(real_spans, sorted)

      root_real_spans = real_spans.reject { |s| @child_span_set.include?(s) }
      root_with_synthetics = interleave_synthetic_spans(root_real_spans)

      synthetic_spans = root_with_synthetics.select(&:synthetic)
      all_spans_for_assign = (synthetic_spans + real_spans).sort_by { |s| s.start_ktime || 0 }
      assign_events_to_spans(all_spans_for_assign, sorted)

      collapse_deep_spans(root_real_spans)

      print_header
      print_warnings
      print_observer_proc(root_with_synthetics)
    end

    private

    def build_real_spans(events)
      open_by_tid = Hash.new { |h, k| h[k] = [] }
      closed = []
      children_map = {}

      events.each do |ev|
        case ev.event_name
        when "span_start"
          method_name, file_name, lno = read_span_payload(ev.payload)
          span = Span.new(
            tid: ev.tid,
            method_name: method_name,
            file_name: file_name,
            lineno: lno,
            start_ktime: ev.ktime_ns,
            stop_ktime: nil,
            exit_kind: nil,
            events: [],
            descendant_pids: Set.new,
            synthetic: false,
            raised: false
          )
          parent = open_by_tid[ev.tid].last
          (children_map[parent] ||= []) << span if parent
          open_by_tid[ev.tid].push(span)
        when "span_stop"
          stack = open_by_tid[ev.tid]
          next if stack.empty?

          span = stack.pop
          span.stop_ktime = ev.ktime_ns
          span.exit_kind = :stopped
          closed << span
        when "span_raise"
          span = open_by_tid[ev.tid].last
          span.raised = true if span
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
      [closed, children_map]
    end

    # Trim method-call span nesting deeper than @display_filter.max_span_depth.
    # The deep span frames are dropped, but their events are promoted onto the
    # deepest still-visible ancestor span so no security-relevant event is lost.
    def collapse_deep_spans(root_real_spans)
      max = @display_filter.max_span_depth
      return unless max

      depth = {}
      stack = root_real_spans.map { |s| [s, 1] }
      until stack.empty?
        span, d = stack.pop
        depth[span] = d
        (@children_map[span] || []).each { |child| stack.push([child, d + 1]) }
      end

      depth.each do |span, d|
        next unless d == max

        descendants = collect_descendant_spans(span)
        next if descendants.empty?

        descendants.each do |desc|
          span.events.concat(desc.events)
          desc.events = []
        end
        span.events.sort_by!(&:ktime_ns)
        @children_map[span] = []
      end
    end

    def collect_descendant_spans(span)
      result = []
      stack = (@children_map[span] || []).dup
      until stack.empty?
        child = stack.pop
        result << child
        stack.concat(@children_map[child] || [])
      end
      result
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
        method_name: nil,
        file_name: nil,
        lineno: nil,
        start_ktime: start_ktime,
        stop_ktime: stop_ktime,
        exit_kind: :stopped,
        events: [],
        descendant_pids: Set.new,
        synthetic: true,
        raised: false
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
    end

    def print_observer_proc(spans)
      @dest.puts "[PROC pid=#{@observer_pid} comm=#{@pid_comm[@observer_pid] || 'ruby'}]"
      children = spans.reject { |s| s.synthetic && s.events.empty? }
                      .reject { |s| @child_span_set.include?(s) }
                      .select { |s| span_visible?(s) }
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
      file_info = span_file_info(span)
      suffix = if span.exit_kind == :dangling
                 "  (open)"
               elsif span.raised
                 "  (raise)"
               else
                 ""
               end
      "[SPAN tid=#{span.tid} #{name}#{file_info}  dur=#{dur_text}#{suffix}]"
    end

    def span_file_info(span)
      return "" if span.synthetic
      return "" if span.file_name.nil? || span.file_name.empty?

      lno = span.lineno && span.lineno > 0 ? ":#{span.lineno}" : ""
      "  at=#{File.basename(span.file_name)}#{lno}"
    end

    def span_display_name(span)
      return SYNTHETIC_SPAN_NAME if span.synthetic
      return SYNTHETIC_SPAN_NAME if span.method_name.nil? || span.method_name.empty?

      span.method_name
    end

    def build_span_children(span)
      proc_node_by_pid = {}
      root_children = []
      prev_event_ktime = span.start_ktime

      span.events.each do |ev|
        target_text = nil
        if @display_filter.needs_payload?
          target_text = render_target(ev)
          next unless event_visible?(ev, span, target_text)
        else
          next unless event_visible?(ev, span)
        end

        next if dedup_suppressed?(ev, target_text)

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
            target: target_text || render_target(ev),
            offset_ns: ev.ktime_ns - span.start_ktime,
            child_proc: child_node
          )

          parent_container = container_for_pid(ev.pid, span, proc_node_by_pid, root_children)
          maybe_inject_drop_node(parent_container, ev, span, prev_event_ktime)
          append_event(parent_container, ev_node)
        else
          ev_node = EventNode.new(
            kind: kind_for(ev),
            name: ev.event_name,
            target: target_text || render_target(ev),
            offset_ns: ev.ktime_ns - span.start_ktime,
            child_proc: nil
          )

          container = if ev.pid == @observer_pid && ev.tid == span.tid
            root_children
          elsif (node = proc_node_by_pid[ev.pid])
            node.children
          else
            stub = ProcNode.new(
              pid: ev.pid,
              comm: @pid_comm[ev.pid] || "?",
              parent_pid: @pid_parent[ev.pid] || span.tid,
              children: []
            )
            proc_node_by_pid[ev.pid] = stub
            root_children << stub
            stub.children
          end

          maybe_inject_drop_node(container, ev, span, prev_event_ktime)
          append_event(container, ev_node)

          if ev.event_name == EXEC_EVENT_NAME && (node = proc_node_by_pid[ev.pid])
            node.comm = @pid_comm[ev.pid] || node.comm
          end
        end

        prev_event_ktime = ev.ktime_ns
      end

      # Interleave child spans by start time among the event/proc nodes
      child_spans = (@children_map[span] || []).sort_by(&:start_ktime)
      child_spans.each do |child_span|
        child_offset = child_span.start_ktime - span.start_ktime
        insert_pos = root_children.size
        root_children.each_with_index do |node, i|
          if node.is_a?(EventNode) && node.offset_ns >= child_offset
            insert_pos = i
            break
          end
        end
        root_children.insert(insert_pos, child_span)
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

    def maybe_inject_drop_node(container, ev, span, prev_event_ktime = nil)
      n = ev.dropped_since_last.to_i
      return if n.zero?

      # Show the start of the drop window (= time of last good event).
      # The end is implicitly ev.ktime_ns (shown on the following event line).
      drop_start_ns = prev_event_ktime ? (prev_event_ktime - span.start_ktime) : nil

      container << EventNode.new(
        kind: "DROP",
        name: "dropped_events",
        target: "#{n} event(s) lost (ringbuf overflow)",
        offset_ns: drop_start_ns,
        child_proc: nil
      )
    end

    def print_nodes(nodes, prefix)
      visible_nodes = nodes.select do |node|
        !node.is_a?(Span) || span_visible?(node)
      end

      visible_nodes.each_with_index do |node, idx|
        is_last = idx == visible_nodes.size - 1
        case node
        when EventNode
          print_event_node(node, prefix: prefix, is_last: is_last)
        when ProcNode
          print_proc_node(node, prefix: prefix, is_last: is_last)
        when Span
          print_span(node, prefix: prefix, is_last: is_last)
        end
      end
    end

    def span_visible?(span)
      @display_filter.allow_span_name?(span_display_name(span))
    end

    # True when dedup_values is on and this (event_name, value) pair was already
    # rendered earlier in the session. Only visible events reach this point, so a
    # suppressed-by-filter event never consumes the "first occurrence" slot.
    def dedup_suppressed?(ev, target_text)
      return false unless @display_filter.dedup_values
      return false unless DEDUP_EVENT_NAMES.include?(ev.event_name)

      value = target_text || render_target(ev)
      !@dedup_seen.add?([ev.event_name, value])
    end

    def event_visible?(ev, span, target_text = nil)
      @display_filter.allow_event?(
        event_name: ev.event_name,
        severity: Vivarium.event_severity(ev.event_name),
        span_name: span_display_name(span),
        payload: target_text,
        pid: ev.pid,
        tid: ev.tid
      )
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
      return "EXCP" if ev.event_name == "span_raise"
      return "USDT" if SPAN_EVENT_NAMES.include?(ev.event_name)
      return "SSL" if ev.event_name == SSL_WRITE_EVENT_NAME
      return "DL" if DL_EVENT_NAMES.include?(ev.event_name)
      return "LSM" if LSM_EVENT_NAMES.include?(ev.event_name)
      return "TP" if TP_EVENT_NAMES.include?(ev.event_name)

      "EVT"
    end

    def render_target(ev)
      return render_raise_target(ev) if ev.event_name == "span_raise"
      return render_ssl_write_target(ev) if ev.event_name == SSL_WRITE_EVENT_NAME

      text = Vivarium.render_event_payload(ev).to_s
      text = text.gsub(/\s+/, " ").strip
      text.empty? ? "-" : text
    end

    def render_ssl_write_target(ev)
      decoded = Vivarium.decode_ssl_write_payload(ev.payload)
      http_decoder.render(
        pid: ev.pid,
        data: decoded[:data],
        data_len: decoded[:data_len]
      )
    rescue StandardError => e
      "ssl_write <decode-error: #{e.class}: #{e.message}>"
    end

    def http_decoder
      @http_decoder ||= Vivarium::HttpDecoder.new
    end

    def render_raise_target(ev)
      bytes = ev.payload.to_s.b
      return "-" if bytes.empty?

      slot = Vivarium::SPAN_RAISE_SLOT_SIZE
      error_name = Vivarium.c_string(bytes[0, slot])
      message    = Vivarium.c_string(bytes[slot, slot])
      file_name  = Vivarium.c_string(bytes[slot * 2, slot])
      lineno     = bytes.bytesize > Vivarium::SPAN_RAISE_LINENO_OFFSET ? bytes[Vivarium::SPAN_RAISE_LINENO_OFFSET, 8].unpack1("q<") : -1

      parts = ["error=#{error_name.empty? ? '?' : error_name}"]
      parts << "message=#{message.inspect}" unless message.empty?
      unless file_name.empty?
        lno = lineno > 0 ? ":#{lineno}" : ""
        parts << "at=#{File.basename(file_name)}#{lno}"
      end
      parts.join(" ")
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

    def read_span_payload(payload)
      bytes = payload.to_s.b
      return [nil, nil, -1] if bytes.empty?

      method_name = Vivarium.c_string(bytes[0, Vivarium::SPAN_METHOD_SIZE])
      file_name   = Vivarium.c_string(bytes[Vivarium::SPAN_METHOD_SIZE, Vivarium::SPAN_FILE_SIZE])
      lineno      = bytes.bytesize > Vivarium::SPAN_LINENO_OFFSET ? bytes[Vivarium::SPAN_LINENO_OFFSET, 8].unpack1("q<") : -1
      [method_name, file_name, lineno]
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
