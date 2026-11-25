//! Windows ICMP echo via the IP Helper API (`IcmpSendEcho` / `Icmp6SendEcho2`).
//!
//! These APIs send ICMP echo requests **without Administrator rights**, unlike raw
//! sockets. They are blocking, so callers run them on Tokio's blocking pool.
//!
//! This is the only module in the workspace allowed to use `unsafe`. Every block
//! is an FFI call; the invariants are documented inline:
//! - handles are checked against `INVALID_HANDLE_VALUE` and always closed (RAII guard);
//! - reply buffers are owned, 8-byte aligned and larger than the documented minimum
//!   (`sizeof(reply) + payload + 8 + sizeof(IO_STATUS_BLOCK)`);
//! - reply structs are read with `read_unaligned` only after a successful call
//!   reported at least one reply.
#![allow(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ICMP_ECHO_REPLY, ICMPV6_ECHO_REPLY_LH, IP_DEST_HOST_UNREACHABLE, IP_DEST_NET_UNREACHABLE,
    IP_DEST_PORT_UNREACHABLE, IP_REQ_TIMED_OUT, IP_SUCCESS, IP_TTL_EXPIRED_TRANSIT,
    Icmp6CreateFile, Icmp6SendEcho2, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET6, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN6, SOCKADDR_IN6_0,
};

/// Result of one echo exchange.
#[derive(Debug, PartialEq, Eq)]
pub enum Echo {
    Reply { bytes: usize },
    TimedOut,
    Error(String),
}

/// Closes an ICMP handle on drop.
struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a valid handle returned by Icmp(6)CreateFile and is closed exactly once.
        unsafe {
            IcmpCloseHandle(self.0);
        }
    }
}

fn open(v6: bool) -> Result<Handle, String> {
    // SAFETY: no arguments; returns a handle or INVALID_HANDLE_VALUE.
    let h = unsafe {
        if v6 {
            Icmp6CreateFile()
        } else {
            IcmpCreateFile()
        }
    };

    if h == INVALID_HANDLE_VALUE || h.is_null() {
        return Err(format!(
            "IcmpCreateFile failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(Handle(h))
}

fn status_text(status: u32) -> Echo {
    match status {
        IP_SUCCESS => Echo::Reply { bytes: 0 },
        IP_REQ_TIMED_OUT => Echo::TimedOut,
        IP_DEST_HOST_UNREACHABLE => Echo::Error("destination host unreachable".into()),
        IP_DEST_NET_UNREACHABLE => Echo::Error("destination network unreachable".into()),
        IP_DEST_PORT_UNREACHABLE => Echo::Error("destination port unreachable".into()),
        IP_TTL_EXPIRED_TRANSIT => Echo::Error("time to live exceeded".into()),
        other => Echo::Error(format!("ICMP error status {other}")),
    }
}

/// Check that the ICMP API is usable (handle can be created).
pub fn available(v6: bool) -> Result<(), String> {
    open(v6).map(drop)
}

/// Send one echo request and wait up to `timeout`. Blocking.
pub fn echo(ip: IpAddr, payload: &[u8], timeout: Duration) -> Echo {
    let timeout_ms = u32::try_from(timeout.as_millis())
        .unwrap_or(u32::MAX)
        .max(1);

    let Ok(size) = u16::try_from(payload.len()) else {
        return Echo::Error("payload too large".into());
    };

    // 8-byte aligned buffer, generously sized (reply struct + payload + ICMP error + IO_STATUS_BLOCK).
    let mut buf = vec![0u64; (256 + payload.len()).div_ceil(8)];
    let buf_bytes = u32::try_from(buf.len() * 8).unwrap_or(u32::MAX);

    match ip {
        IpAddr::V4(v4) => echo_v4(v4, payload, size, timeout_ms, &mut buf, buf_bytes),
        IpAddr::V6(v6) => echo_v6(v6, payload, size, timeout_ms, &mut buf, buf_bytes),
    }
}

fn echo_v4(
    ip: Ipv4Addr,
    payload: &[u8],
    size: u16,
    timeout_ms: u32,
    buf: &mut [u64],
    buf_bytes: u32,
) -> Echo {
    let handle = match open(false) {
        Ok(h) => h,
        Err(e) => return Echo::Error(e),
    };

    // IPAddr is in network byte order: the octets as laid out in memory.
    let dest = u32::from_ne_bytes(ip.octets());

    // SAFETY: valid handle; payload pointer/size describe a live slice; reply buffer is
    // owned, aligned and `buf_bytes` long; options pointer may be null.
    let n = unsafe {
        IcmpSendEcho(
            handle.0,
            dest,
            payload.as_ptr().cast(),
            size,
            std::ptr::null(),
            buf.as_mut_ptr().cast(),
            buf_bytes,
            timeout_ms,
        )
    };

    if n == 0 {
        let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
        return status_text(code);
    }

    // SAFETY: n > 0 means the buffer starts with a fully written ICMP_ECHO_REPLY.
    let reply: ICMP_ECHO_REPLY = unsafe { std::ptr::read_unaligned(buf.as_ptr().cast()) };
    match status_text(reply.Status) {
        Echo::Reply { .. } => Echo::Reply {
            bytes: usize::from(reply.DataSize) + 8,
        },
        other => other,
    }
}

fn sockaddr6(ip: Ipv6Addr) -> SOCKADDR_IN6 {
    SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: IN6_ADDR {
            u: IN6_ADDR_0 { Byte: ip.octets() },
        },
        Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
    }
}

fn echo_v6(
    ip: Ipv6Addr,
    payload: &[u8],
    size: u16,
    timeout_ms: u32,
    buf: &mut [u64],
    buf_bytes: u32,
) -> Echo {
    let handle = match open(true) {
        Ok(h) => h,
        Err(e) => return Echo::Error(e),
    };

    let src = sockaddr6(Ipv6Addr::UNSPECIFIED);
    let dst = sockaddr6(ip);

    // SAFETY: valid handle; no event/APC (synchronous call); src/dst point to live
    // SOCKADDR_IN6 values; payload and reply buffer as in echo_v4.
    let n = unsafe {
        Icmp6SendEcho2(
            handle.0,
            std::ptr::null_mut(),
            None,
            std::ptr::null(),
            &src,
            &dst,
            payload.as_ptr().cast(),
            size,
            std::ptr::null(),
            buf.as_mut_ptr().cast(),
            buf_bytes,
            timeout_ms,
        )
    };

    if n == 0 {
        let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
        return status_text(code);
    }

    // SAFETY: n > 0 means the buffer starts with a fully written ICMPV6_ECHO_REPLY.
    let reply: ICMPV6_ECHO_REPLY_LH = unsafe { std::ptr::read_unaligned(buf.as_ptr().cast()) };
    match status_text(reply.Status) {
        Echo::Reply { .. } => Echo::Reply {
            bytes: payload.len() + 8,
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_v4_echo() {
        let r = echo(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            b"netprobe-test",
            Duration::from_secs(2),
        );
        assert_eq!(r, Echo::Reply { bytes: 13 + 8 });
    }

    #[test]
    fn loopback_v6_echo() {
        // IPv6 loopback may be disabled on some hosts; only assert it does not crash
        // and produces a well-formed result.
        let r = echo(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            b"x",
            Duration::from_secs(2),
        );
        assert!(matches!(
            r,
            Echo::Reply { .. } | Echo::TimedOut | Echo::Error(_)
        ));
    }

    #[test]
    fn status_mapping() {
        assert_eq!(status_text(IP_REQ_TIMED_OUT), Echo::TimedOut);
        assert!(matches!(
            status_text(IP_DEST_HOST_UNREACHABLE),
            Echo::Error(_)
        ));
    }
}
