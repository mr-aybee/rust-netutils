//! Socket snapshots, filtering and change detection.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};

#[cfg(not(target_os = "linux"))]
use netstat2::get_sockets_info;
use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState};
use serde::Serialize;

/// Transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

impl std::fmt::Display for Proto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        })
    }
}

/// One socket. `remote` and `state` are absent for UDP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Sock {
    /// Transport protocol.
    pub proto: Proto,
    /// Local address and port.
    pub local: SocketAddr,
    /// Remote address and port (TCP only; `0.0.0.0:0` for listeners).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<SocketAddr>,
    /// TCP state name, e.g. `LISTEN` (TCP only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// Owning process IDs (empty when the OS does not reveal them to this user).
    pub pids: Vec<u32>,
    /// Name of the first owning process, where available (Linux).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
}

/// Identity of a socket across snapshots. Sockets bound to the same address on
/// different interfaces (SO_BINDTODEVICE) share a key; `--watch` treats them as one.
pub type Key = (Proto, SocketAddr, Option<SocketAddr>);

impl Sock {
    /// Identity used to match this socket across snapshots.
    pub fn key(&self) -> Key {
        (self.proto, self.local, self.remote)
    }
}

fn state_name(s: TcpState) -> String {
    s.to_string()
}

/// Process name for a PID, where the platform allows it without extra privileges.
#[cfg(target_os = "linux")]
fn process_name(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim_end().to_string())
}

#[cfg(not(target_os = "linux"))]
fn process_name(_pid: u32) -> Option<String> {
    None
}

/// Which address families and protocols to read.
#[derive(Debug, Clone, Copy)]
pub struct Scope {
    /// Include TCP sockets.
    pub tcp: bool,
    /// Include UDP sockets.
    pub udp: bool,
    /// Include IPv4 sockets.
    pub ipv4: bool,
    /// Include IPv6 sockets.
    pub ipv6: bool,
}

fn flags(scope: Scope) -> (AddressFamilyFlags, ProtocolFlags) {
    let mut af = AddressFamilyFlags::empty();

    if scope.ipv4 {
        af |= AddressFamilyFlags::IPV4;
    }

    if scope.ipv6 {
        af |= AddressFamilyFlags::IPV6;
    }

    let mut pf = ProtocolFlags::empty();

    if scope.tcp {
        pf |= ProtocolFlags::TCP;
    }

    if scope.udp {
        pf |= ProtocolFlags::UDP;
    }

    (af, pf)
}

fn to_sock(
    info: ProtocolSocketInfo,
    pids: Vec<u32>,
    names: &mut HashMap<u32, Option<String>>,
) -> Sock {
    let process = pids
        .first()
        .and_then(|p| names.entry(*p).or_insert_with(|| process_name(*p)).clone());

    match info {
        ProtocolSocketInfo::Tcp(t) => Sock {
            proto: Proto::Tcp,
            local: SocketAddr::new(t.local_addr, t.local_port),
            remote: Some(SocketAddr::new(t.remote_addr, t.remote_port)),
            state: Some(state_name(t.state)),
            pids,
            process,
        },
        ProtocolSocketInfo::Udp(u) => Sock {
            proto: Proto::Udp,
            local: SocketAddr::new(u.local_addr, u.local_port),
            remote: None,
            state: None,
            pids,
            process,
        },
    }
}

fn sort(out: &mut [Sock]) {
    out.sort_by(|a, b| {
        (a.proto, a.local.port(), a.local.ip(), a.remote).cmp(&(
            b.proto,
            b.local.port(),
            b.local.ip(),
            b.remote,
        ))
    });
}

/// Takes snapshots, reusing owner information between calls.
///
/// On Linux, mapping sockets to processes requires scanning every `/proc/<pid>/fd`,
/// which dominates the cost of a snapshot. The owner of each socket inode is cached,
/// and the scan runs only when an inode not seen before appears, so an idle `--watch`
/// costs one netlink dump per interval.
#[derive(Default)]
pub struct Snapshotter {
    #[cfg(target_os = "linux")]
    owners: HashMap<u32, Vec<u32>>,
    names: HashMap<u32, Option<String>>,
    /// Number of `/proc` scans performed (for tests and diagnostics).
    pub proc_scans: u64,
}

impl Snapshotter {
    /// Take a snapshot, sorted by protocol, local port, local address and remote.
    #[cfg(target_os = "linux")]
    pub fn take(&mut self, scope: Scope) -> Result<Vec<Sock>, String> {
        let (af, pf) = flags(scope);
        let raw: Vec<netstat2::SocketInfo> = netstat2::iterate_sockets_info_without_pids(af, pf)
            .map_err(|e| format!("cannot read socket table: {e}"))?
            .collect::<Result<_, _>>()
            .map_err(|e| format!("cannot read socket table: {e}"))?;

        // Inode 0 means no owning file (e.g. TIME_WAIT); nothing to resolve.
        let live: std::collections::HashSet<u32> =
            raw.iter().map(|s| s.inode).filter(|i| *i != 0).collect();
        let missing: std::collections::HashSet<u32> = live
            .iter()
            .copied()
            .filter(|i| !self.owners.contains_key(i))
            .collect();

        if !missing.is_empty() {
            self.proc_scans += 1;
            let found = scan_proc_for_inodes(&missing);

            for inode in missing {
                // Remember unresolvable inodes too, so they don't trigger a rescan every poll.
                self.owners
                    .insert(inode, found.get(&inode).cloned().unwrap_or_default());
            }
        }

        self.owners.retain(|i, _| live.contains(i));
        let mut out: Vec<Sock> = raw
            .into_iter()
            .map(|s| {
                let pids = self.owners.get(&s.inode).cloned().unwrap_or_default();
                to_sock(s.protocol_socket_info, pids, &mut self.names)
            })
            .collect();
        sort(&mut out);
        Ok(out)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn take(&mut self, scope: Scope) -> Result<Vec<Sock>, String> {
        let (af, pf) = flags(scope);
        let raw = get_sockets_info(af, pf).map_err(|e| format!("cannot read socket table: {e}"))?;
        let mut out: Vec<Sock> = raw
            .into_iter()
            .map(|s| {
                let mut pids = s.associated_pids;
                pids.sort_unstable();
                pids.dedup();
                to_sock(s.protocol_socket_info, pids, &mut self.names)
            })
            .collect();
        sort(&mut out);
        Ok(out)
    }
}

/// Map socket inodes to owning PIDs by reading `/proc/<pid>/fd/*` links (`socket:[inode]`).
/// Processes whose fd directory is not readable (other users, without privileges) are skipped.
#[cfg(target_os = "linux")]
fn scan_proc_for_inodes(wanted: &std::collections::HashSet<u32>) -> HashMap<u32, Vec<u32>> {
    let mut map: HashMap<u32, Vec<u32>> = HashMap::new();

    let Ok(procs) = std::fs::read_dir("/proc") else {
        return map;
    };

    for p in procs.flatten() {
        let Some(pid) = p.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };

        let Ok(fds) = std::fs::read_dir(p.path().join("fd")) else {
            continue;
        };

        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };

            let Some(inode) = target
                .to_str()
                .and_then(|t| t.strip_prefix("socket:["))
                .and_then(|t| t.strip_suffix(']'))
                .and_then(|t| t.parse::<u32>().ok())
            else {
                continue;
            };

            if wanted.contains(&inode) {
                let e = map.entry(inode).or_default();
                if !e.contains(&pid) {
                    e.push(pid);
                }
            }
        }
    }

    for v in map.values_mut() {
        v.sort_unstable();
    }

    map
}

/// One-off snapshot.
pub fn snapshot(scope: Scope) -> Result<Vec<Sock>, String> {
    Snapshotter::default().take(scope)
}

/// Filters combine with AND; within `ports`/`pids`/`states`, any match suffices.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// Match the local or remote port.
    pub ports: Vec<u16>,
    /// Match the local port only.
    pub local_ports: Vec<u16>,
    /// Match sockets owned by any of these PIDs.
    pub pids: Vec<u32>,
    /// Upper-case TCP state names, e.g. LISTEN, ESTABLISHED.
    pub states: Vec<String>,
    /// Only listening TCP sockets and bound UDP sockets.
    pub listening: bool,
    /// Match process names containing this text (case-insensitive).
    pub process: Option<String>,
    /// Match this local or remote IP address.
    pub address: Option<IpAddr>,
}

impl Filter {
    /// Whether `s` passes every configured filter.
    pub fn matches(&self, s: &Sock) -> bool {
        let remote_port = s.remote.map(|r| r.port());

        if !self.ports.is_empty()
            && !self
                .ports
                .iter()
                .any(|p| *p == s.local.port() || Some(*p) == remote_port)
        {
            return false;
        }

        if !self.local_ports.is_empty() && !self.local_ports.contains(&s.local.port()) {
            return false;
        }

        if !self.pids.is_empty() && !s.pids.iter().any(|p| self.pids.contains(p)) {
            return false;
        }

        if !self.states.is_empty()
            && !s
                .state
                .as_ref()
                .is_some_and(|st| self.states.iter().any(|f| f == st))
        {
            return false;
        }

        if self.listening && !(s.proto == Proto::Udp || s.state.as_deref() == Some("LISTEN")) {
            return false;
        }

        if let Some(name) = &self.process
            && !s
                .process
                .as_ref()
                .is_some_and(|p| p.to_ascii_lowercase().contains(&name.to_ascii_lowercase()))
        {
            return false;
        }

        if let Some(ip) = self.address
            && s.local.ip() != ip
            && s.remote.map(|r| r.ip()) != Some(ip)
        {
            return false;
        }

        true
    }
}

/// A difference between two snapshots.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "lowercase")]
pub enum Change {
    /// A socket appeared.
    Opened {
        /// The new socket.
        socket: Sock,
    },
    /// A socket disappeared.
    Closed {
        /// The socket as last seen.
        socket: Sock,
    },
    /// A TCP socket changed state.
    State {
        /// The socket in its new state.
        socket: Sock,
        /// The previous TCP state name.
        previous: String,
    },
}

/// Events turning `old` into `new` (both already filtered), in deterministic order.
pub fn diff(old: &[Sock], new: &[Sock]) -> Vec<Change> {
    let o: BTreeMap<Key, &Sock> = old.iter().map(|s| (s.key(), s)).collect();
    let n: BTreeMap<Key, &Sock> = new.iter().map(|s| (s.key(), s)).collect();
    let mut out = Vec::new();

    for (k, s) in &o {
        if !n.contains_key(k) {
            out.push(Change::Closed {
                socket: (*s).clone(),
            });
        }
    }

    for (k, s) in &n {
        match o.get(k) {
            None => out.push(Change::Opened {
                socket: (*s).clone(),
            }),
            Some(prev) if prev.state != s.state => out.push(Change::State {
                socket: (*s).clone(),
                previous: prev.state.clone().unwrap_or_default(),
            }),
            Some(_) => {}
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(local: u16, remote: u16, state: &str, pid: u32) -> Sock {
        Sock {
            proto: Proto::Tcp,
            local: format!("127.0.0.1:{local}").parse().unwrap(),
            remote: Some(format!("127.0.0.1:{remote}").parse().unwrap()),
            state: Some(state.into()),
            pids: vec![pid],
            process: Some("server".into()),
        }
    }

    #[test]
    fn filters() {
        let s = tcp(8080, 0, "LISTEN", 42);
        assert!(
            Filter {
                ports: vec![8080],
                ..Default::default()
            }
            .matches(&s)
        );
        assert!(
            !Filter {
                ports: vec![80],
                ..Default::default()
            }
            .matches(&s)
        );
        assert!(
            Filter {
                listening: true,
                ..Default::default()
            }
            .matches(&s)
        );
        assert!(
            !Filter {
                listening: true,
                ..Default::default()
            }
            .matches(&tcp(5000, 8080, "ESTABLISHED", 1))
        );
        assert!(
            Filter {
                ports: vec![8080],
                ..Default::default()
            }
            .matches(&tcp(5000, 8080, "ESTABLISHED", 1)),
            "remote port matches --port"
        );
        assert!(
            !Filter {
                local_ports: vec![8080],
                ..Default::default()
            }
            .matches(&tcp(5000, 8080, "ESTABLISHED", 1))
        );
        assert!(
            Filter {
                pids: vec![42],
                ..Default::default()
            }
            .matches(&s)
        );
        assert!(
            Filter {
                process: Some("SERV".into()),
                ..Default::default()
            }
            .matches(&s)
        );
        assert!(
            !Filter {
                states: vec!["ESTABLISHED".into()],
                ..Default::default()
            }
            .matches(&s)
        );
    }

    #[test]
    fn diffs() {
        let a = tcp(8080, 0, "LISTEN", 1);
        let b = tcp(5000, 8080, "ESTABLISHED", 2);
        let b2 = tcp(5000, 8080, "TIME_WAIT", 2);
        let c = tcp(6000, 8080, "ESTABLISHED", 3);
        let events = diff(&[a.clone(), b], &[b2, c]);
        assert_eq!(events.len(), 3);
        assert!(matches!(&events[0], Change::Closed { socket } if socket.local.port() == 8080));
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Change::State { previous, .. } if previous == "ESTABLISHED"))
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Change::Opened { socket } if socket.local.port() == 6000))
        );
        assert!(diff(std::slice::from_ref(&a), std::slice::from_ref(&a)).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_scan_only_for_new_inodes() {
        let scope = Scope {
            tcp: true,
            udp: false,
            ipv4: true,
            ipv6: false,
        };
        let mut snap = Snapshotter::default();
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let first = snap.take(scope).unwrap();
        assert!(
            first
                .iter()
                .any(|s| s.local.port() == port && s.pids.contains(&std::process::id()))
        );
        assert!(snap.proc_scans >= 1);

        // The listener's owner is now cached: later snapshots still report it,
        // and each scan only happens because some *other* new socket appeared.
        for _ in 0..3 {
            let again = snap.take(scope).unwrap();
            assert!(
                again
                    .iter()
                    .any(|s| s.local.port() == port && s.pids.contains(&std::process::id()))
            );
        }
    }

    #[test]
    fn real_snapshot_contains_our_listener() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let snap = snapshot(Scope {
            tcp: true,
            udp: false,
            ipv4: true,
            ipv6: false,
        })
        .unwrap();
        let ours = snap
            .iter()
            .find(|s| s.local.port() == port)
            .expect("listener visible");
        assert_eq!(ours.state.as_deref(), Some("LISTEN"));
        assert!(
            ours.pids.contains(&std::process::id()),
            "own PID is always visible"
        );
    }
}
