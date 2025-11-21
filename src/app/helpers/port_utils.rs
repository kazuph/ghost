use nix::libc::{EPERM, kill};
use std::collections::{HashMap, HashSet, VecDeque};
use std::process::Command;

/// Utilities for extracting port information from running processes
/// Extract port number from process using lsof (including child processes)
///
/// Smart selection rules:
/// - Walk all descendants, not just direct children
/// - Collect all TCP LISTEN ports from lsof
/// - Exclude ports explicitly used by debuggers/inspectors (from process cmdline: --inspect*, --inspect-port)
/// - Prefer ports that respond to an HTTP GET on localhost
/// - If multiple HTTP candidates, prefer ones that look like HTML (contains <html or <!DOCTYPE)
/// - As a final tie-breaker, prefer commonly used dev ports (non-hardcoded single port)
pub fn extract_port_from_process(pid: u32) -> String {
    let pids_to_check = collect_descendant_pids(pid);

    let port_lookup = extract_ports_for_processes(&pids_to_check).unwrap_or_default();
    let mut inspector_cache: HashMap<u32, HashSet<u16>> = HashMap::new();

    // Gather candidate ports with their owning pid
    let mut candidates: Vec<(u16, u32)> = Vec::new();
    for &check_pid in &pids_to_check {
        let inspector_ports = inspector_cache
            .entry(check_pid)
            .or_insert_with(|| inspector_ports_from_cmdline(check_pid));

        if let Some(ports) = port_lookup.get(&check_pid) {
            for &port in ports {
                if inspector_ports.contains(&port) {
                    continue; // skip explicit inspector/debug ports
                }
                candidates.push((port, check_pid));
            }
        }
    }

    // Deduplicate by port, keeping first seen
    candidates.sort_by_key(|(p, _)| *p);
    candidates.dedup_by_key(|(p, _)| *p);

    // Score candidates and pick best
    if let Some(best) = select_best_http_candidate(&candidates) {
        return best.to_string();
    }

    // Fallback to first available port if any
    if let Some((port, _)) = candidates.first() {
        return port.to_string();
    }

    "-".to_string()
}

/// Extract web server info from process ID using lsof (returns :port format for TUI compatibility)
pub fn extract_web_server_info(pid: u32) -> Option<String> {
    let pids_to_check = collect_descendant_pids(pid);

    let port_lookup = extract_ports_for_processes(&pids_to_check).unwrap_or_default();
    let mut inspector_cache: HashMap<u32, HashSet<u16>> = HashMap::new();

    let mut candidates: Vec<(u16, u32)> = Vec::new();
    for &check_pid in &pids_to_check {
        let inspector_ports = inspector_cache
            .entry(check_pid)
            .or_insert_with(|| inspector_ports_from_cmdline(check_pid));

        if let Some(ports) = port_lookup.get(&check_pid) {
            for &port in ports {
                if inspector_ports.contains(&port) {
                    continue;
                }
                candidates.push((port, check_pid));
            }
        }
    }

    if let Some(best) = select_best_http_candidate(&candidates) {
        return Some(format!(":{best}"));
    }

    candidates.first().map(|(p, _)| format!(":{p}"))
}

/// Extract port number from lsof output line
fn extract_port_from_lsof_line(line: &str) -> Option<u16> {
    // Look for patterns like "*:3000", "localhost:3000", "[::1]:3000", "127.0.0.1:3000"
    let patterns = [
        r"\*:(\d+)",           // *:3000
        r"\blocalhost:(\d+)",  // localhost:3000
        r"\[::1\]:(\d+)",      // [::1]:3000 (IPv6 localhost)
        r"127\.0\.0\.1:(\d+)", // 127.0.0.1:3000
    ];

    for pattern in &patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            if let Some(captures) = re.captures(line) {
                if let Some(port_str) = captures.get(1) {
                    if let Ok(port) = port_str.as_str().parse::<u16>() {
                        return Some(port);
                    }
                }
            }
        }
    }
    None
}

/// Build a parent -> children process map using `ps`
fn build_process_children_map() -> HashMap<u32, Vec<u32>> {
    let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();

    if let Ok(output) = std::process::Command::new("ps")
        .args(["-o", "pid,ppid", "-A"]) // all processes
        .output()
    {
        if let Ok(stdout) = String::from_utf8(output.stdout) {
            for line in stdout.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let (Ok(pid), Ok(ppid)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>())
                    {
                        children_map.entry(ppid).or_default().push(pid);
                    }
                }
            }
        }
    }

    children_map
}

/// Build pid -> command map via ps
fn build_process_command_map() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    if let Ok(output) = Command::new("ps")
        .args(["-o", "pid,command", "-A"])
        .output()
    {
        if let Ok(stdout) = String::from_utf8(output.stdout) {
            for line in stdout.lines().skip(1) {
                let mut parts = line.split_whitespace();
                if let Some(pid_str) = parts.next() {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        let cmd = parts.collect::<Vec<_>>().join(" ");
                        map.insert(pid, cmd);
                    }
                }
            }
        }
    }
    map
}

#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub command: String,
}

/// Collect process tree (root + descendants) with commands
pub fn collect_process_tree(root: u32) -> Vec<ProcInfo> {
    let children_map = build_process_children_map();
    let parent_map: HashMap<u32, u32> = children_map
        .iter()
        .flat_map(|(ppid, kids)| kids.iter().map(move |k| (*k, *ppid)))
        .collect();
    let cmd_map = build_process_command_map();

    let descendants = collect_descendant_pids_with_map(root, &children_map);

    // order by BFS from root
    let mut order: Vec<u32> = Vec::new();
    let mut queue: VecDeque<u32> = VecDeque::new();
    queue.push_back(root);
    let desc_set: HashSet<u32> = descendants.iter().copied().collect();
    while let Some(pid) = queue.pop_front() {
        order.push(pid);
        if let Some(children) = children_map.get(&pid) {
            for &c in children {
                if desc_set.contains(&c) {
                    queue.push_back(c);
                }
            }
        }
    }

    order
        .into_iter()
        .filter(|pid| desc_set.contains(pid))
        .map(|pid| ProcInfo {
            pid,
            ppid: parent_map.get(&pid).copied().unwrap_or(0),
            command: cmd_map
                .get(&pid)
                .cloned()
                .unwrap_or_else(|| "<unknown>".to_string()),
        })
        .collect()
}

/// Collect all descendant PIDs (recursive), including the parent
pub fn collect_descendant_pids(root: u32) -> Vec<u32> {
    let children_map = build_process_children_map();
    collect_descendant_pids_with_map(root, &children_map)
}

pub fn collect_descendant_pids_with_map(
    root: u32,
    children_map: &HashMap<u32, Vec<u32>>,
) -> Vec<u32> {
    let mut visited: HashSet<u32> = HashSet::new();
    let mut queue = VecDeque::new();

    visited.insert(root);
    queue.push_back(root);

    while let Some(ppid) = queue.pop_front() {
        if let Some(children) = children_map.get(&ppid) {
            for &child in children {
                if visited.insert(child) {
                    queue.push_back(child);
                }
            }
        }
    }

    visited.into_iter().collect()
}

/// Extract all listening TCP ports for a set of processes using a single `lsof` call
fn extract_ports_for_processes(pids: &[u32]) -> Option<HashMap<u32, Vec<u16>>> {
    // Filter out PIDs that no longer exist to avoid lsof errors
    let existing_pids: Vec<u32> = pids
        .iter()
        .copied()
        .filter(|pid| pid_exists(*pid))
        .collect();

    if existing_pids.is_empty() {
        return Some(HashMap::new());
    }

    let pid_arg = existing_pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");

    // -a to intersect PID filter with TCP LISTEN filter (otherwise results are OR-ed on macOS)
    let output = std::process::Command::new("lsof")
        .args(["-a", "-p", &pid_arg, "-iTCP", "-sTCP:LISTEN", "-P", "-n"]) // only TCP LISTEN
        .output()
        .ok()?;

    // lsof may exit non-zero if some PIDs vanish mid-call; parse what we got
    let stdout = String::from_utf8(output.stdout).ok()?;
    if stdout.is_empty() {
        return Some(HashMap::new());
    }
    let mut map: HashMap<u32, Vec<u16>> = HashMap::new();
    for line in stdout.lines() {
        if line.starts_with("COMMAND") {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let pid = match parts[1].parse::<u32>() {
            Ok(pid) => pid,
            Err(_) => continue,
        };

        if let Some(port) = extract_port_from_lsof_line(line) {
            let entry = map.entry(pid).or_default();
            if !entry.contains(&port) {
                entry.push(port);
            }
        }
    }

    Some(map)
}

fn pid_exists(pid: u32) -> bool {
    // kill(pid, 0) returns 0 if process exists and we have permission,
    // -1 with EPERM if it exists but we lack permission.
    let res = unsafe { kill(pid as i32, 0) };
    if res == 0 {
        true
    } else {
        std::io::Error::last_os_error().raw_os_error() == Some(EPERM)
    }
}

/// Detect inspector/debugger ports from process cmdline
fn inspector_ports_from_cmdline(pid: u32) -> HashSet<u16> {
    let mut set = HashSet::new();

    if let Ok(output) = std::process::Command::new("ps")
        .args(["-o", "command=", "-p", &pid.to_string()])
        .output()
    {
        if let Ok(cmdline) = String::from_utf8(output.stdout) {
            let cmdline = cmdline.trim();
            // --inspect, --inspect=HOST:PORT, --inspect=PORT, --inspect-brk, --inspect-port PORT/PORT
            let re1 = regex::Regex::new(r"--inspect(?:-brk)?(?:=|\s+)(?:[^\s:]+:)?(\d+)").ok();
            let re2 = regex::Regex::new(r"--inspect-port(?:=|\s+)(\d+)").ok();
            if let Some(re) = re1.as_ref() {
                for cap in re.captures_iter(cmdline) {
                    if let Some(m) = cap.get(1) {
                        if let Ok(p) = m.as_str().parse::<u16>() {
                            set.insert(p);
                        }
                    }
                }
            }
            if let Some(re) = re2.as_ref() {
                for cap in re.captures_iter(cmdline) {
                    if let Some(m) = cap.get(1) {
                        if let Ok(p) = m.as_str().parse::<u16>() {
                            set.insert(p);
                        }
                    }
                }
            }
            // If --inspect/--inspect-brk present without port, default 9229
            if cmdline.contains("--inspect") && !set.iter().any(|_| true) {
                set.insert(9229);
            }
            // Heuristic: treat explicit "inspect" tools as debugger UIs (e.g., vite inspector plugins)
            // If command contains keywords and a single listening port later equals 9xxx it's likely inspector,
            // but we avoid hardcoding ranges; the explicit flags above handle most Node cases.
        }
    }

    set
}

/// Try to pick the best candidate port for HTTP dev server
fn select_best_http_candidate(candidates: &[(u16, u32)]) -> Option<u16> {
    // Add small preference weights for common dev ports without hardcoding a single value
    const COMMON_DEV_PORTS: &[u16] = &[5173, 3000, 8080, 5174, 4321, 1234, 4000, 8081, 4200, 8000];
    const INSPECT_LIKELY_RANGE_START: u16 = 9000;

    let mut best: Option<(i32, u16)> = None; // (score, port)

    for (port, _pid) in candidates {
        let probe = http_probe(*port, std::time::Duration::from_millis(250));

        let mut score = 0;
        match probe {
            HttpProbeResult::Html => score += 100,
            HttpProbeResult::Http => score += 80,
            HttpProbeResult::OpenButUnknown => score += 10,
            HttpProbeResult::Closed => score += 0,
        }

        if COMMON_DEV_PORTS.contains(port) {
            score += 5; // gentle nudge, not decisive
        }

        // Penalize typical inspector/high ports when not confidently HTTP
        if *port >= INSPECT_LIKELY_RANGE_START && score < 80 {
            score -= 20;
        }

        if let Some((best_score, best_port)) = best {
            if score > best_score || (score == best_score && *port < best_port) {
                best = Some((score, *port));
            }
        } else {
            best = Some((score, *port));
        }
    }

    best.map(|(_, p)| p)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum HttpProbeResult {
    Html,
    Http,
    OpenButUnknown,
    Closed,
}

/// Very lightweight HTTP probe: try GET / on both IPv4/IPv6 loopback and read a small prefix
fn http_probe(port: u16, timeout: std::time::Duration) -> HttpProbeResult {
    use std::net::{SocketAddr, TcpStream};

    fn score(result: &HttpProbeResult) -> u8 {
        match result {
            HttpProbeResult::Html => 3,
            HttpProbeResult::Http => 2,
            HttpProbeResult::OpenButUnknown => 1,
            HttpProbeResult::Closed => 0,
        }
    }

    fn probe_addr(addr: SocketAddr, timeout: std::time::Duration) -> HttpProbeResult {
        use std::io::{Read, Write};
        if let Ok(mut stream) = TcpStream::connect_timeout(&addr, timeout) {
            let _ = stream.set_read_timeout(Some(timeout));
            let _ = stream.set_write_timeout(Some(timeout));
            let req = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(req);
            let mut buf = [0u8; 1024];
            match stream.read(&mut buf) {
                Ok(n) if n > 0 => {
                    let text = String::from_utf8_lossy(&buf[..n]).to_lowercase();
                    if text.starts_with("http/1.") || text.starts_with("http/2") {
                        if text.contains("<html") || text.contains("<!doctype") {
                            HttpProbeResult::Html
                        } else {
                            HttpProbeResult::Http
                        }
                    } else {
                        HttpProbeResult::OpenButUnknown
                    }
                }
                _ => HttpProbeResult::OpenButUnknown,
            }
        } else {
            HttpProbeResult::Closed
        }
    }

    let mut best = HttpProbeResult::Closed;
    let mut best_score = 0u8;

    for addr in ["127.0.0.1", "::1"] {
        let sock_str = if addr.contains(':') {
            format!("[{addr}]:{port}")
        } else {
            format!("{addr}:{port}")
        };

        if let Ok(sock) = sock_str.parse::<SocketAddr>() {
            let result = probe_addr(sock, timeout);
            let s = score(&result);
            if s > best_score {
                best_score = s;
                best = result;
            }
            if matches!(result, HttpProbeResult::Html) {
                break; // best possible
            }
        }
    }

    best
}

// (Any live debug tests were removed to keep the helper lean.)
