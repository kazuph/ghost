use crate::app::error::{GhostError, Result};
use crate::app::helpers::port_utils::collect_descendant_pids;
use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct ListeningPort {
    pub protocol: String,
    pub local_addr: String,
    pub state: String,
}

/// システム全体のポート情報（プロセス詳細付き）
#[derive(Debug, Clone)]
pub struct SystemPort {
    pub port: u16,
    pub protocol: String,
    pub pid: u32,
    pub process_name: String,
    pub ppid: u32,
    pub parent_name: String,
    pub user: String,
    pub memory_kb: Option<u64>,
    pub cwd: Option<String>,
    pub local_addr: String,
}

// Cache the lsof availability check result
static LSOF_AVAILABLE: OnceLock<bool> = OnceLock::new();

/// Check if lsof command is available on the system (cached)
pub fn is_lsof_available() -> bool {
    *LSOF_AVAILABLE.get_or_init(|| {
        Command::new("which")
            .arg("lsof")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    })
}

/// Check if lsof command is available on the system
pub fn check_lsof_availability() -> Result<()> {
    if !is_lsof_available() {
        return Err(GhostError::CommandNotFound {
            command: "lsof".to_string(),
        });
    }
    Ok(())
}

/// Parse lsof machine-readable format (-F flag) output
fn parse_lsof_machine_format(output: &str) -> Vec<ListeningPort> {
    let mut ports = Vec::new();
    let mut current_protocol = String::new();
    let mut current_addr = String::new();
    let mut current_state = String::new();
    let mut in_network_fd = false;

    for line in output.lines() {
        if line.is_empty() {
            continue;
        }

        let tag = &line[0..1];
        let value = &line[1..];

        match tag {
            "f" => {
                // File descriptor - reset state for new FD
                in_network_fd = false;
                current_protocol.clear();
                current_addr.clear();
                current_state.clear();
            }
            "t" => {
                // Type - check if it's a network connection
                if value.starts_with("IPv4") || value.starts_with("IPv6") {
                    in_network_fd = true;
                }
            }
            "n" => {
                // Name - contains address information
                if in_network_fd {
                    current_addr = value.to_string();
                }
            }
            "P" => {
                // Protocol - TCP or UDP
                if in_network_fd {
                    current_protocol = value.to_lowercase();
                }
            }
            "T" => {
                // TCP/TPI info - contains state like LISTEN
                if in_network_fd && value.starts_with("ST=LISTEN") {
                    current_state = "LISTEN".to_string();

                    // We have all the information, add the port
                    if !current_protocol.is_empty() && !current_addr.is_empty() {
                        ports.push(ListeningPort {
                            protocol: current_protocol.clone(),
                            local_addr: current_addr.clone(),
                            state: current_state.clone(),
                        });
                    }
                }
            }
            _ => {}
        }
    }

    ports
}

/// Detect listening ports for a given process ID
pub fn detect_listening_ports(pid: u32) -> Result<Vec<ListeningPort>> {
    // Check if lsof is available
    check_lsof_availability()?;

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    return detect_ports_using_lsof(pid);

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    return Ok(Vec::new());
}

/// Detect listening ports for a process **and its descendants** (used in detail view)
pub fn detect_listening_ports_recursive(pid: u32) -> Result<Vec<ListeningPort>> {
    // Check if lsof is available
    check_lsof_availability()?;

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let pids = collect_descendant_pids(pid);
        return detect_ports_using_lsof_multi(&pids);
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Ok(Vec::new())
    }
}

/// Common implementation for macOS and Linux using lsof
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn detect_ports_using_lsof(pid: u32) -> Result<Vec<ListeningPort>> {
    let output = Command::new("lsof")
        .args(["-nP", "-i", "-a", "-p", &pid.to_string(), "-F"])
        .output()
        .map_err(|e| GhostError::ProcessOperation {
            message: format!("Failed to execute lsof: {e}"),
        })?;

    if !output.status.success() {
        // Process might not have any network connections
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_lsof_machine_format(&stdout))
}

/// Multi-pid variant to inspect parent+child processes in one lsof call
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn detect_ports_using_lsof_multi(pids: &[u32]) -> Result<Vec<ListeningPort>> {
    if pids.is_empty() {
        return Ok(Vec::new());
    }

    let pid_arg = pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");

    let output = Command::new("lsof")
        .args(["-nP", "-i", "-a", "-p", &pid_arg, "-F"])
        .output()
        .map_err(|e| GhostError::ProcessOperation {
            message: format!("Failed to execute lsof: {e}"),
        })?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_lsof_machine_format(&stdout))
}

/// システム全体のリスニングポートを取得（指定PIDを除外）
///
/// # Arguments
/// * `exclude_pids` - 除外するPIDのリスト（Ghost管理プロセスのPID）
///
/// # Returns
/// * `Vec<SystemPort>` - システム全体のリスニングポート情報
pub fn detect_all_listening_ports(exclude_pids: &[u32]) -> Result<Vec<SystemPort>> {
    check_lsof_availability()?;

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    return detect_all_system_ports(exclude_pids);

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = exclude_pids;
        Ok(Vec::new())
    }
}

/// macOS/Linux向けのシステム全体ポート検出
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn detect_all_system_ports(exclude_pids: &[u32]) -> Result<Vec<SystemPort>> {
    // lsof -i -P -n -sTCP:LISTEN でLISTEN状態のTCPポートを取得
    // -F pcnRP でPID、コマンド名、ネットワーク情報、親PID、プロトコルを出力
    let output = Command::new("lsof")
        .args(["-i", "-P", "-n", "-sTCP:LISTEN", "+c", "0", "-F", "pcnRP"])
        .output()
        .map_err(|e| GhostError::ProcessOperation {
            message: format!("Failed to execute lsof: {e}"),
        })?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let exclude_set: HashSet<u32> = exclude_pids.iter().copied().collect();

    // lsofの出力をパース
    let mut ports = Vec::new();
    let mut current_pid: u32 = 0;
    let mut current_ppid: u32 = 0;
    let mut current_command = String::new();
    let mut current_protocol = String::new();
    let mut current_addr = String::new();
    let mut in_network_fd = false;

    for line in stdout.lines() {
        if line.is_empty() {
            continue;
        }

        let tag = &line[0..1];
        let value = &line[1..];

        match tag {
            "p" => {
                // PID
                current_pid = value.parse().unwrap_or(0);
                in_network_fd = false;
            }
            "R" => {
                // Parent PID
                current_ppid = value.parse().unwrap_or(0);
            }
            "c" => {
                // Command name
                current_command = value.to_string();
            }
            "f" => {
                // File descriptor - reset network state
                in_network_fd = false;
                current_protocol.clear();
                current_addr.clear();
            }
            "P" => {
                // Protocol
                current_protocol = value.to_lowercase();
                in_network_fd = true;
            }
            "n" => {
                // Network address
                if in_network_fd && !exclude_set.contains(&current_pid) {
                    current_addr = value.to_string();

                    // Extract port number from address
                    if let Some(port) = extract_port_from_addr(&current_addr) {
                        ports.push(SystemPort {
                            port,
                            protocol: current_protocol.clone(),
                            pid: current_pid,
                            process_name: current_command.clone(),
                            ppid: current_ppid,
                            parent_name: String::new(), // Will be filled later
                            user: String::new(),        // Will be filled later
                            memory_kb: None,            // Will be filled later
                            cwd: None,                  // Will be filled later
                            local_addr: current_addr.clone(),
                        });
                    }
                }
            }
            _ => {}
        }
    }

    // 親プロセス名を取得
    let unique_ppids: HashSet<u32> = ports.iter().map(|p| p.ppid).collect();
    let parent_names = get_process_names(&unique_ppids.into_iter().collect::<Vec<_>>());

    // CWDを取得
    let unique_pids: Vec<u32> = ports.iter().map(|p| p.pid).collect::<HashSet<_>>().into_iter().collect();
    let cwds = get_process_cwds(&unique_pids);

    // ユーザー名とメモリ情報を取得
    let user_memory_info = get_process_user_memory(&unique_pids);

    // 現在のユーザー名を取得
    let current_user = std::env::var("USER").unwrap_or_default();

    // 情報を補完
    for port in &mut ports {
        if let Some(name) = parent_names.get(&port.ppid) {
            port.parent_name = name.clone();
        }
        if let Some(cwd) = cwds.get(&port.pid) {
            port.cwd = Some(cwd.clone());
        }
        if let Some((user, memory)) = user_memory_info.get(&port.pid) {
            port.user = user.clone();
            port.memory_kb = *memory;
        }
    }

    // 重複除去（同じポートで複数のFDがある場合）
    ports.dedup_by(|a, b| a.port == b.port && a.pid == b.pid);

    // ソート: 現在のユーザーのプロセスを上に、その後ポート番号順
    ports.sort_by(|a, b| {
        let a_is_current_user = a.user == current_user;
        let b_is_current_user = b.user == current_user;

        match (a_is_current_user, b_is_current_user) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.port.cmp(&b.port),
        }
    });

    Ok(ports)
}

/// アドレス文字列からポート番号を抽出
fn extract_port_from_addr(addr: &str) -> Option<u16> {
    // フォーマット例: "*:8080", "127.0.0.1:3000", "[::1]:5000", "[::]:8080"
    if let Some(pos) = addr.rfind(':') {
        let port_str = &addr[pos + 1..];
        // "->" が含まれている場合は接続先なのでスキップ
        if port_str.contains("->") {
            return None;
        }
        port_str.parse().ok()
    } else {
        None
    }
}

/// 複数のPIDのプロセス名を取得
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn get_process_names(pids: &[u32]) -> HashMap<u32, String> {
    let mut result = HashMap::new();
    if pids.is_empty() {
        return result;
    }

    // psコマンドで複数のプロセス名を一度に取得
    let pid_args = pids
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");

    if let Ok(output) = Command::new("ps")
        .args(["-p", &pid_args, "-o", "pid=,comm="])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(pid) = parts[0].parse::<u32>() {
                        result.insert(pid, parts[1..].join(" "));
                    }
                }
            }
        }
    }

    result
}

/// 複数のPIDのCWDを取得
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn get_process_cwds(pids: &[u32]) -> HashMap<u32, String> {
    let mut result = HashMap::new();
    if pids.is_empty() {
        return result;
    }

    // lsof -d cwd で複数プロセスのCWDを取得
    let pid_args = pids
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");

    if let Ok(output) = Command::new("lsof")
        .args(["-d", "cwd", "-p", &pid_args, "-F", "pn"])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut current_pid: u32 = 0;

            for line in stdout.lines() {
                if line.is_empty() {
                    continue;
                }
                let tag = &line[0..1];
                let value = &line[1..];

                match tag {
                    "p" => {
                        current_pid = value.parse().unwrap_or(0);
                    }
                    "n" => {
                        // Only accept values that look like directory paths (start with /)
                        // Filter out network addresses like "*:mdns", "localhost:5173->..."
                        if current_pid != 0
                            && !value.is_empty()
                            && value.starts_with('/')
                            && !result.contains_key(&current_pid)
                        {
                            result.insert(current_pid, value.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    result
}

/// 複数のPIDのユーザー名とメモリ使用量を取得
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn get_process_user_memory(pids: &[u32]) -> HashMap<u32, (String, Option<u64>)> {
    let mut result = HashMap::new();
    if pids.is_empty() {
        return result;
    }

    // psコマンドでユーザー名とRSS（メモリ使用量KB）を取得
    let pid_args = pids
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",");

    if let Ok(output) = Command::new("ps")
        .args(["-p", &pid_args, "-o", "pid=,user=,rss="])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(pid) = parts[0].parse::<u32>() {
                        let user = parts[1].to_string();
                        let memory = if parts.len() >= 3 {
                            parts[2].parse::<u64>().ok()
                        } else {
                            None
                        };
                        result.insert(pid, (user, memory));
                    }
                }
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_listening_ports() {
        // This test requires a running process with known ports
        // In a real test, we would start a test server
        let ports = detect_listening_ports(std::process::id());
        assert!(ports.is_ok());
    }

    #[test]
    fn test_check_lsof_availability() {
        // This test checks the lsof availability check function
        // The actual result depends on whether lsof is installed on the system
        let result = check_lsof_availability();

        // We can't guarantee it's installed, so we just check the function works
        assert!(result.is_ok() || result.is_err());

        // Test the cached version
        let is_available = is_lsof_available();
        // The cached result should match the check result
        assert_eq!(is_available, result.is_ok());
    }

    #[test]
    fn test_parse_lsof_machine_format() {
        // Test parsing of lsof -F format output
        let sample_output = "p1234\nfcwd\ntCWD\nn/home/user\n\
                           f6\ntREG\na r\ni123456\nn/usr/bin/app\n\
                           f10\ntIPv4\nPTCP\nn*:8080\nTST=LISTEN\n";

        let ports = parse_lsof_machine_format(sample_output);
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].protocol, "tcp");
        assert_eq!(ports[0].local_addr, "*:8080");
        assert_eq!(ports[0].state, "LISTEN");
    }

    #[test]
    fn test_parse_malformed_lsof_output() {
        // Test with completely empty output
        let empty_output = "";
        let ports = parse_lsof_machine_format(empty_output);
        assert_eq!(ports.len(), 0);

        // Test with malformed lines (missing tag characters)
        let malformed_output = "1234\nf10\nt\nn*:8080\n";
        let ports = parse_lsof_machine_format(malformed_output);
        assert_eq!(ports.len(), 0);

        // Test with truncated output (missing required fields)
        let truncated_output = "p1234\nf10\ntIPv4\n";
        let ports = parse_lsof_machine_format(truncated_output);
        assert_eq!(ports.len(), 0);

        // Test with wrong tag order
        let wrong_order_output = "TST=LISTEN\nPTCP\ntIPv4\nn*:8080\nf10\n";
        let ports = parse_lsof_machine_format(wrong_order_output);
        assert_eq!(ports.len(), 0);

        // Test with corrupted protocol field
        let corrupted_protocol = "f10\ntIPv4\nP\nn*:8080\nTST=LISTEN\n";
        let ports = parse_lsof_machine_format(corrupted_protocol);
        assert_eq!(ports.len(), 0);

        // Test with corrupted address field
        let corrupted_address = "f10\ntIPv4\nPTCP\nn\nTST=LISTEN\n";
        let ports = parse_lsof_machine_format(corrupted_address);
        assert_eq!(ports.len(), 0);

        // Test with non-LISTEN state
        let non_listen_output = "f10\ntIPv4\nPTCP\nn*:8080\nTST=ESTABLISHED\n";
        let ports = parse_lsof_machine_format(non_listen_output);
        assert_eq!(ports.len(), 0);

        // Test with mixed valid and invalid entries
        let mixed_output = "p1234\n\
                          f10\ntIPv4\nPTCP\nn*:8080\nTST=LISTEN\n\
                          f11\ntIPv4\n\nn*:9000\nTST=LISTEN\n\
                          f12\ntIPv4\nPUDP\nn*:7000\nTST=LISTEN\n";
        let ports = parse_lsof_machine_format(mixed_output);
        assert_eq!(ports.len(), 2); // Should only get the valid TCP and UDP entries
        assert!(
            ports
                .iter()
                .any(|p| p.local_addr == "*:8080" && p.protocol == "tcp")
        );
        assert!(
            ports
                .iter()
                .any(|p| p.local_addr == "*:7000" && p.protocol == "udp")
        );
    }

    #[test]
    fn test_parse_partial_lsof_output() {
        // Test with incomplete network file descriptor information
        let partial_fd_output = "f10\ntIPv4\nPTCP\n"; // Missing address and state
        let ports = parse_lsof_machine_format(partial_fd_output);
        assert_eq!(ports.len(), 0);

        // Test with missing protocol
        let missing_protocol_output = "f10\ntIPv4\nn*:8080\nTST=LISTEN\n";
        let ports = parse_lsof_machine_format(missing_protocol_output);
        assert_eq!(ports.len(), 0);

        // Test with incomplete state information
        let incomplete_state_output = "f10\ntIPv4\nPTCP\nn*:8080\nT\n";
        let ports = parse_lsof_machine_format(incomplete_state_output);
        assert_eq!(ports.len(), 0);

        // Test with IPv6 addresses
        let ipv6_output = "f10\ntIPv6\nPTCP\nn[::1]:8080\nTST=LISTEN\n";
        let ports = parse_lsof_machine_format(ipv6_output);
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].local_addr, "[::1]:8080");
        assert_eq!(ports[0].protocol, "tcp");

        // Test with multiple protocols
        let multi_protocol_output = "p1234\n\
                                   f10\ntIPv4\nPTCP\nn*:8080\nTST=LISTEN\n\
                                   f11\ntIPv4\nPUDP\nn*:9000\nTST=LISTEN\n\
                                   f12\ntIPv6\nPTCP\nn[::1]:7000\nTST=LISTEN\n";
        let ports = parse_lsof_machine_format(multi_protocol_output);
        assert_eq!(ports.len(), 3);

        let tcp_v4 = ports.iter().find(|p| p.local_addr == "*:8080").unwrap();
        assert_eq!(tcp_v4.protocol, "tcp");

        let udp_v4 = ports.iter().find(|p| p.local_addr == "*:9000").unwrap();
        assert_eq!(udp_v4.protocol, "udp");

        let tcp_v6 = ports.iter().find(|p| p.local_addr == "[::1]:7000").unwrap();
        assert_eq!(tcp_v6.protocol, "tcp");
    }

    #[test]
    fn test_detect_ports_error_scenarios() {
        // Test with invalid PID (should return empty result, not error)
        let result = detect_listening_ports(999999);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);

        // Test with PID 0 (system process)
        let result = detect_listening_ports(0);
        assert!(result.is_ok()); // Should not crash, may or may not have ports

        // Test with current process PID (should work)
        let current_pid = std::process::id();
        let result = detect_listening_ports(current_pid);
        assert!(result.is_ok()); // Should not error even if no ports
    }

    #[cfg(unix)]
    #[test]
    fn test_lsof_permission_scenarios() {
        // Test that we handle lsof permission errors gracefully
        // This tests the error handling path when lsof exits with non-zero status

        // Try to get ports for a process that likely doesn't exist or we can't access
        let result = detect_listening_ports(1); // init process, often not accessible

        // The function should not panic and should return a valid result
        assert!(result.is_ok());
        // The result might be empty (no ports) or contain ports if we have permission
    }

    #[test]
    fn test_edge_case_addresses() {
        // Test with various address formats
        let edge_case_output = "p1234\n\
                              f10\ntIPv4\nPTCP\nn127.0.0.1:8080\nTST=LISTEN\n\
                              f11\ntIPv4\nPTCP\nn0.0.0.0:9000\nTST=LISTEN\n\
                              f12\ntIPv6\nPTCP\nn[::]:7000\nTST=LISTEN\n\
                              f13\ntIPv4\nPUDP\nn*:5353\nTST=LISTEN\n";

        let ports = parse_lsof_machine_format(edge_case_output);
        assert_eq!(ports.len(), 4);

        // Verify all addresses are preserved correctly
        let addresses: Vec<&str> = ports.iter().map(|p| p.local_addr.as_str()).collect();
        assert!(addresses.contains(&"127.0.0.1:8080"));
        assert!(addresses.contains(&"0.0.0.0:9000"));
        assert!(addresses.contains(&"[::]:7000"));
        assert!(addresses.contains(&"*:5353"));
    }

    #[test]
    fn test_protocol_case_handling() {
        // Test that protocol names are properly normalized to lowercase
        let mixed_case_output = "f10\ntIPv4\nPTCP\nn*:8080\nTST=LISTEN\n\
                               f11\ntIPv4\nPUDP\nn*:9000\nTST=LISTEN\n";

        let ports = parse_lsof_machine_format(mixed_case_output);
        assert_eq!(ports.len(), 2);

        for port in &ports {
            // All protocols should be lowercase
            assert!(port.protocol.chars().all(|c| c.is_lowercase()));
        }
    }
}
