//! Host-side SSH agent forwarding (`com.docker.sandbox/ssh-agent@1`).
//!
//! Private keys stay in the host SSH agent; the guest connects to `/run/osbx/ssh-agent.sock`
//! over vsock. When the kit requests restricted signing (`unrestricted: false` with `sign:`
//! namespaces), every SSH agent message is parsed on the host and only identity listing
//! (`SSH2_AGENTC_REQUEST_IDENTITIES`) and `SSHSIG` signatures matching an approved namespace are
//! forwarded; all other requests receive `SSH_AGENT_FAILURE`.

use std::io::{self, Read, Write};
use std::path::PathBuf;

/// Maximum SSH agent packet accepted on a filtered connection (256 KiB).
const MAX_PACKET: usize = 256 * 1024;
const SSH_AGENT_FAILURE: u8 = 5;
const SSH2_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH2_AGENTC_SIGN_REQUEST: u8 = 13;

/// Access policy applied to a forwarded SSH agent connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshAgentPolicy {
    /// Forward raw bytes to the host agent without filtering.
    Unrestricted,
    /// Allow only `REQUEST_IDENTITIES` and `SSHSIG` signing for the listed namespaces (e.g. `git`).
    SignOnly(Vec<String>),
}

/// Host SSH agent forwarding configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshAgentConfig {
    /// Path to the host's `SSH_AUTH_SOCK`.
    pub socket: PathBuf,
    /// Filtering policy enforced on the host side.
    pub policy: SshAgentPolicy,
}

/// Read one length-prefixed SSH agent message (`u32 BE length` + payload). Returns `Ok(None)` on EOF.
fn read_packet(r: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_PACKET {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid ssh-agent packet length {len}"),
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    Ok(Some(payload))
}

fn write_packet(w: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "ssh-agent packet too large"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

fn take_ssh_string<'a>(buf: &mut &'a [u8]) -> Option<&'a [u8]> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes(buf[..4].try_into().ok()?) as usize;
    *buf = &buf[4..];
    if buf.len() < len {
        return None;
    }
    let (head, rest) = buf.split_at(len);
    *buf = rest;
    Some(head)
}

/// Extract the `SSHSIG` namespace from an `SSH2_AGENTC_SIGN_REQUEST` payload (excluding the
/// leading message type byte). Format: `string key_blob`, `string data`, `uint32 flags`, where
/// `data` for an `SSHSIG` signature starts with `b"SSHSIG"` followed by `string namespace`.
pub fn sshsig_namespace(sign_body: &[u8]) -> Option<&str> {
    let mut p = sign_body;
    let _key_blob = take_ssh_string(&mut p)?;
    let mut data = take_ssh_string(&mut p)?;
    // remaining 4 bytes are `flags`
    if p.len() != 4 {
        return None;
    }
    let rest = data.strip_prefix(b"SSHSIG")?;
    data = rest;
    let ns = take_ssh_string(&mut data)?;
    std::str::from_utf8(ns).ok()
}

/// Check whether `payload` (type byte + body) is allowed by `policy`.
pub fn request_allowed(payload: &[u8], policy: &SshAgentPolicy) -> bool {
    let Some((&msg_type, body)) = payload.split_first() else {
        return false;
    };
    match policy {
        SshAgentPolicy::Unrestricted => true,
        SshAgentPolicy::SignOnly(namespaces) => match msg_type {
            SSH2_AGENTC_REQUEST_IDENTITIES => body.is_empty(),
            SSH2_AGENTC_SIGN_REQUEST => {
                sshsig_namespace(body).is_some_and(|ns| namespaces.iter().any(|a| a == ns))
            }
            _ => false,
        },
    }
}

/// Filter one SSH agent stream pair (`guest` <-> `host`) according to `policy`.
pub fn serve_filtered<G, H>(mut guest: G, mut host: H, policy: &SshAgentPolicy) -> io::Result<()>
where
    G: Read + Write,
    H: Read + Write,
{
    while let Some(req) = read_packet(&mut guest)? {
        if request_allowed(&req, policy) {
            write_packet(&mut host, &req)?;
            let Some(resp) = read_packet(&mut host)? else {
                break;
            };
            write_packet(&mut guest, &resp)?;
        } else {
            write_packet(&mut guest, &[SSH_AGENT_FAILURE])?;
        }
    }
    Ok(())
}

/// Bridge one guest vsock stream to the host SSH agent socket.
#[cfg(unix)]
pub fn bridge(vs: osbx_vmm::virtio::vsock::VsockStream, cfg: &SshAgentConfig) {
    use std::os::unix::net::UnixStream;
    let Ok(host) = UnixStream::connect(&cfg.socket) else {
        return;
    };
    match &cfg.policy {
        SshAgentPolicy::Unrestricted => {
            let Ok(mut host_w) = host.try_clone() else {
                return;
            };
            let mut vs_r = vs.try_clone();
            let up = std::thread::spawn(move || {
                let _ = io::copy(&mut vs_r, &mut host_w);
                let _ = host_w.shutdown(std::net::Shutdown::Write);
            });
            let mut host_r = host;
            let mut vs_w = vs;
            let _ = io::copy(&mut host_r, &mut vs_w);
            vs_w.shutdown_write();
            let _ = up.join();
        }
        SshAgentPolicy::SignOnly(_) => {
            let _ = serve_filtered(vs, host, &cfg.policy);
        }
    }
}

/// Non-Unix hosts do not have a Unix-domain `SSH_AUTH_SOCK`.
#[cfg(not(unix))]
pub fn bridge(_vs: osbx_vmm::virtio::vsock::VsockStream, _cfg: &SshAgentConfig) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_str(buf: &mut Vec<u8>, s: &[u8]) {
        buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
        buf.extend_from_slice(s);
    }

    fn sign_request(data: &[u8]) -> Vec<u8> {
        let mut p = vec![SSH2_AGENTC_SIGN_REQUEST];
        put_str(&mut p, b"fake-key-blob");
        put_str(&mut p, data);
        p.extend_from_slice(&0u32.to_be_bytes());
        p
    }

    fn sshsig_data(ns: &str) -> Vec<u8> {
        let mut d = b"SSHSIG".to_vec();
        put_str(&mut d, ns.as_bytes());
        put_str(&mut d, b""); // reserved
        put_str(&mut d, b"sha512");
        put_str(&mut d, &[0u8; 64]);
        d
    }

    #[test]
    fn sign_only_filter_allows_identities_and_declared_sshsig_namespaces_only() {
        let pol = SshAgentPolicy::SignOnly(vec!["git".into()]);
        assert!(request_allowed(&[SSH2_AGENTC_REQUEST_IDENTITIES], &pol));
        assert!(request_allowed(&sign_request(&sshsig_data("git")), &pol));
        // wrong namespace
        assert!(!request_allowed(&sign_request(&sshsig_data("file")), &pol));
        // SSH userauth (not SSHSIG) is refused
        assert!(!request_allowed(&sign_request(b"not-sshsig-login"), &pol));
        // key management (SSH2_AGENTC_ADD_IDENTITY = 17) is refused
        assert!(!request_allowed(&[17, 1, 2, 3], &pol));
    }

    #[cfg(unix)]
    #[test]
    fn filtered_bridge_forwards_allowed_and_rejects_disallowed() {
        use std::os::unix::net::UnixStream;
        let (mut client, guest_end) = UnixStream::pair().unwrap();
        let (host_end, mut fake_agent) = UnixStream::pair().unwrap();
        let pol = SshAgentPolicy::SignOnly(vec!["git".into()]);

        let agent = std::thread::spawn(move || {
            while let Ok(Some(req)) = read_packet(&mut fake_agent) {
                // echo 0x0e (SSH2_AGENT_SIGN_RESPONSE) with the first byte
                let _ = write_packet(&mut fake_agent, &[14, req[0]]);
            }
        });
        let proxy = std::thread::spawn(move || {
            let _ = serve_filtered(guest_end, host_end, &pol);
        });

        // 1. Disallowed namespace -> SSH_AGENT_FAILURE (5) without hitting fake_agent
        write_packet(&mut client, &sign_request(&sshsig_data("file"))).unwrap();
        assert_eq!(
            read_packet(&mut client).unwrap(),
            Some(vec![SSH_AGENT_FAILURE])
        );

        // 2. Allowed namespace -> forwarded to fake_agent
        write_packet(&mut client, &sign_request(&sshsig_data("git"))).unwrap();
        assert_eq!(
            read_packet(&mut client).unwrap(),
            Some(vec![14, SSH2_AGENTC_SIGN_REQUEST])
        );

        drop(client);
        let _ = proxy.join();
        let _ = agent.join();
    }
}
