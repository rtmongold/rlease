//! rlease — small DHCPv4 client (udhcpc-class).
//!
//! Usage: rlease -i IFACE [-n] [-q] [-s SCRIPT] [-l PATH] [-H NAME] [-t TRIES] [-T SECONDS]

use dhcproto::v4::{self, Decodable, Decoder, Encodable, Encoder, Message, MessageType, Opcode};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::mem;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_SERVER_PORT: u16 = 67;
const DEFAULT_TRIES: u32 = 8;
const DEFAULT_TIMEOUT_SECS: u64 = 3;
const CARRIER_WAIT_SECS: u64 = 15;

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_stop(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

fn install_stop_handlers() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_stop as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
    }
}

fn stop_requested() -> bool {
    STOP.load(Ordering::SeqCst)
}

fn sleep_interruptible(total: Duration) -> bool {
    // returns true if STOP was set
    let mut left = total;
    let slice = Duration::from_secs(1);
    while left > Duration::ZERO {
        if stop_requested() {
            return true;
        }
        let step = if left < slice { left } else { slice };
        thread::sleep(step);
        left = left.saturating_sub(step);
    }
    stop_requested()
}

struct Args {
    iface: String,
    oneshot: bool,
    quiet: bool,
    script: Option<String>,
    tries: u32,
    timeout: Duration,
    lease_path: Option<PathBuf>,
    hostname: Option<String>,
}

fn usage() -> ! {
    eprintln!(
        "usage: rlease -i IFACE [-n] [-q] [-s SCRIPT] [-l PATH] [-H NAME] [-t TRIES] [-T SECONDS]\n\
         -i  interface (required)\n\
         -l  lease file\n\
         -n  exit after lease (oneshot)\n\
         -q  quieter logging\n\
         -s  udhcpc-compatible hook script (arg: bound)\n\
         -H  hostname to send (default: /etc/hostname)\n\
         -t  discover/request attempts (default {})\n\
         -T  per-attempt timeout seconds (default {})",
        DEFAULT_TRIES, DEFAULT_TIMEOUT_SECS
    );
    std::process::exit(2);
}

fn parse_args() -> Args {
    let mut iface = None;
    let mut oneshot = false;
    let mut quiet = false;
    let mut script = None;
    let mut tries = DEFAULT_TRIES;
    let mut timeout_secs = DEFAULT_TIMEOUT_SECS;
    let mut lease_path = None;
    let mut hostname = None;

    let argv: Vec<String> = env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "-i" => {
                i += 1;
                iface = argv.get(i).cloned();
                if iface.is_none() {
                    usage();
                }
            }
            "-n" => oneshot = true,
            "-q" => quiet = true,
            "-s" => {
                i += 1;
                script = argv.get(i).cloned();
                if script.is_none() {
                    usage();
                }
            }
            "-l" => {
                i += 1;
                lease_path = argv.get(i).map(PathBuf::from);
                if lease_path.is_none() {
                    usage();
                }
            }
            "-H" => {
                i += 1;
                hostname = argv.get(i).cloned();
                if hostname.is_none() {
                    usage();
                }
            }
            "-t" => {
                i += 1;
                tries = argv
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| usage());
            }
            "-T" => {
                i += 1;
                timeout_secs = argv
                    .get(i)
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or_else(|| usage());
            }
            "-h" | "--help" => usage(),
            other => {
                eprintln!("rlease: unknown argument: {other}");
                usage();
            }
        }
        i += 1;
    }

    let Some(iface) = iface else { usage() };
    if hostname.is_none()
        && let Ok(h) = fs::read_to_string("/etc/hostname")
    {
        let h = h.trim().to_string();
        if !h.is_empty() {
            hostname = Some(h);
        }
    }
    Args {
        iface,
        oneshot,
        quiet,
        script,
        tries,
        timeout: Duration::from_secs(timeout_secs),
        lease_path,
        hostname,
    }
}

fn log(quiet: bool, msg: &str) {
    if !quiet {
        let _ = writeln!(io::stderr(), "rlease: {msg}");
    }
}

fn ip_bin() -> &'static str {
    for p in ["/usr/bin/ip", "/sbin/ip", "/usr/sbin/ip"] {
        if Path::new(p).exists() {
            return p;
        }
    }
    "ip"
}

fn run_ip(args: &[&str]) -> io::Result<()> {
    let bin = ip_bin();
    let st = Command::new(bin)
        .args(args)
        .status()
        .map_err(|e| io::Error::new(e.kind(), format!("exec {bin}: {e}")))?;
    if !st.success() {
        return Err(io::Error::other(format!("{bin} {} failed", args.join(" "))));
    }
    Ok(())
}

fn read_mac(iface: &str) -> io::Result<Vec<u8>> {
    let s = fs::read_to_string(format!("/sys/class/net/{iface}/address"))?;
    let s = s.trim();
    let mut out = Vec::new();
    for part in s.split(':') {
        out.push(u8::from_str_radix(part, 16).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("bad MAC {s}: {e}"))
        })?);
    }
    if out.len() < 6 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "MAC too short"));
    }
    Ok(out)
}

fn wait_carrier(iface: &str, quiet: bool) -> io::Result<()> {
    let path = format!("/sys/class/net/{iface}/carrier");
    let deadline = Instant::now() + Duration::from_secs(CARRIER_WAIT_SECS);
    loop {
        if let Ok(v) = fs::read_to_string(&path)
            && v.trim() == "1"
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            log(
                quiet,
                &format!("no carrier on {iface} after {CARRIER_WAIT_SECS}s; continuing"),
            );
            return Ok(());
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn mask_to_prefix(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

fn set_broadcast(sock: &UdpSocket) -> io::Result<()> {
    let fd = sock.as_raw_fd();
    let yes: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BROADCAST,
            &yes as *const _ as *const libc::c_void,
            std::mem::size_of_val(&yes) as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn bind_to_device(sock: &UdpSocket, iface: &str) -> io::Result<()> {
    let fd = sock.as_raw_fd();
    let mut ifname = [0u8; libc::IFNAMSIZ];
    let bytes = iface.as_bytes();
    if bytes.len() >= libc::IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "iface name to long",
        ));
    }
    ifname[..bytes.len()].copy_from_slice(bytes);
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            ifname.as_ptr() as *const libc::c_void,
            libc::IFNAMSIZ as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn encode_msg(msg: &Message) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut e = Encoder::new(&mut buf);
    msg.encode(&mut e)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(buf)
}

fn msg_type(msg: &Message) -> Option<MessageType> {
    match msg.opts().get(v4::OptionCode::MessageType)? {
        v4::DhcpOption::MessageType(t) => Some(*t),
        _ => None,
    }
}

fn opt_server_id(msg: &Message) -> Option<Ipv4Addr> {
    match msg.opts().get(v4::OptionCode::ServerIdentifier)? {
        v4::DhcpOption::ServerIdentifier(a) => Some(*a),
        _ => None,
    }
}

fn opt_subnet(msg: &Message) -> Option<Ipv4Addr> {
    match msg.opts().get(v4::OptionCode::SubnetMask)? {
        v4::DhcpOption::SubnetMask(a) => Some(*a),
        _ => None,
    }
}

fn opt_routers(msg: &Message) -> Vec<Ipv4Addr> {
    match msg.opts().get(v4::OptionCode::Router) {
        Some(v4::DhcpOption::Router(v)) => v.clone(),
        _ => Vec::new(),
    }
}

fn opt_dns(msg: &Message) -> Vec<Ipv4Addr> {
    match msg.opts().get(v4::OptionCode::DomainNameServer) {
        Some(v4::DhcpOption::DomainNameServer(v)) => v.clone(),
        _ => Vec::new(),
    }
}

fn opt_lease_secs(msg: &Message) -> Option<u32> {
    match msg.opts().get(v4::OptionCode::AddressLeaseTime) {
        Some(v4::DhcpOption::AddressLeaseTime(a)) => Some(*a),
        _ => None,
    }
}

fn opt_t1(msg: &Message) -> Option<u32> {
    match msg.opts().get(v4::OptionCode::Renewal) {
        Some(v4::DhcpOption::Renewal(a)) => Some(*a),
        _ => None,
    }
}

fn opt_t2(msg: &Message) -> Option<u32> {
    match msg.opts().get(v4::OptionCode::Rebinding) {
        Some(v4::DhcpOption::Rebinding(a)) => Some(*a),
        _ => None,
    }
}

fn set_hostname(msg: &mut Message, hostname: Option<&str>) {
    if let Some(h) = hostname
        && !h.is_empty()
    {
        msg.opts_mut()
            .insert(v4::DhcpOption::Hostname(h.to_string()));
    }
}

fn build_discover(xid: u32, chaddr: &[u8], hostname: Option<&str>) -> Message {
    let mut msg = Message::default();
    msg.set_opcode(Opcode::BootRequest)
        .set_xid(xid)
        .set_flags(v4::Flags::default().set_broadcast())
        .set_chaddr(chaddr);
    msg.opts_mut()
        .insert(v4::DhcpOption::MessageType(MessageType::Discover));
    msg.opts_mut()
        .insert(v4::DhcpOption::ClientIdentifier(chaddr.to_vec()));
    set_hostname(&mut msg, hostname);
    msg.opts_mut()
        .insert(v4::DhcpOption::ParameterRequestList(vec![
            v4::OptionCode::SubnetMask,
            v4::OptionCode::Router,
            v4::OptionCode::DomainNameServer,
            v4::OptionCode::DomainName,
        ]));
    msg
}

fn build_request(
    xid: u32,
    chaddr: &[u8],
    yiaddr: Ipv4Addr,
    server: Ipv4Addr,
    hostname: Option<&str>,
) -> Message {
    let mut msg = Message::default();
    msg.set_opcode(Opcode::BootRequest)
        .set_xid(xid)
        .set_flags(v4::Flags::default().set_broadcast())
        .set_chaddr(chaddr);
    msg.opts_mut()
        .insert(v4::DhcpOption::MessageType(MessageType::Request));
    msg.opts_mut()
        .insert(v4::DhcpOption::ClientIdentifier(chaddr.to_vec()));
    msg.opts_mut()
        .insert(v4::DhcpOption::RequestedIpAddress(yiaddr));
    msg.opts_mut()
        .insert(v4::DhcpOption::ServerIdentifier(server));
    set_hostname(&mut msg, hostname);
    msg.opts_mut()
        .insert(v4::DhcpOption::ParameterRequestList(vec![
            v4::OptionCode::SubnetMask,
            v4::OptionCode::Router,
            v4::OptionCode::DomainNameServer,
            v4::OptionCode::DomainName,
        ]));
    msg
}

fn build_decline(xid: u32, chaddr: &[u8], yiaddr: Ipv4Addr, server: Ipv4Addr) -> Message {
    let mut msg = Message::default();
    msg.set_opcode(Opcode::BootRequest)
        .set_xid(xid)
        .set_flags(v4::Flags::default().set_broadcast())
        .set_chaddr(chaddr);
    msg.opts_mut()
        .insert(v4::DhcpOption::MessageType(MessageType::Decline));
    msg.opts_mut()
        .insert(v4::DhcpOption::ClientIdentifier(chaddr.to_vec()));
    msg.opts_mut()
        .insert(v4::DhcpOption::RequestedIpAddress(yiaddr));
    msg.opts_mut()
        .insert(v4::DhcpOption::ServerIdentifier(server));
    msg
}

fn if_index(iface: &str) -> io::Result<i32> {
    let c = std::ffi::CString::new(iface)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(idx as i32)
}

/// Returns true if another host answers ARP for `ip` (conflict).
fn arp_conflict(iface: &str, ip: Ipv4Addr, our_mac: &[u8]) -> io::Result<bool> {
    let idx = if_index(iface)?;
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            (libc::ETH_P_ARP as u16).to_be() as libc::c_int,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as libc::c_ushort;
    sll.sll_protocol = (libc::ETH_P_ARP as u16).to_be();
    sll.sll_ifindex = idx as libc::c_int;
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &sll as *const _ as *const libc::sockaddr,
            mem::size_of_val(&sll) as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // Ethernet + ARP request (who-has ip? tell 0.0.0.0 / our MAC)
    let mut frame = [0u8; 42];
    // dst broadcast
    frame[0..6].copy_from_slice(&[0xff; 6]);
    // src MAC
    let mac = if our_mac.len() >= 6 {
        &our_mac[..6]
    } else {
        &[0u8; 6]
    };
    frame[6..12].copy_from_slice(mac);
    // ethertype ARP
    frame[12] = 0x08;
    frame[13] = 0x06;
    // ARP
    frame[14] = 0x00;
    frame[15] = 0x01; // HTYPE Ethernet
    frame[16] = 0x08;
    frame[17] = 0x00; // PTYPE IPv4
    frame[18] = 6; // HLEN
    frame[19] = 4; // PLEN
    frame[20] = 0x00;
    frame[21] = 0x01; // OPER request
    frame[22..28].copy_from_slice(mac); // SHA
    // SPA = 0.0.0.0
    // THA = zeros
    let tip = ip.octets();
    frame[38..42].copy_from_slice(&tip); // TPA
    let sent = unsafe {
        libc::send(
            fd.as_raw_fd(),
            frame.as_ptr() as *const libc::c_void,
            frame.len(),
            0,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    // wait up to 1s for a reply claiming this IP
    let tv = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            mem::size_of_val(&tv) as libc::socklen_t,
        );
    }
    let mut buf = [0u8; 128];
    loop {
        let n = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut {
                return Ok(false); // no reply → no conflict
            }
            return Err(err);
        }
        if n < 42 {
            continue;
        }
        // ARP reply? OPER == 2, SPA == ip
        if buf[12] != 0x08 || buf[13] != 0x06 {
            continue;
        }
        if buf[20] != 0x00 || buf[21] != 0x02 {
            continue;
        }
        if buf[28..32] != tip {
            continue;
        }
        // Ignore if SHA is us
        if &buf[22..28] == mac {
            continue;
        }
        return Ok(true); // conflict
    }
}
fn send_decline(
    sock: &UdpSocket,
    xid: u32,
    chaddr: &[u8],
    yiaddr: Ipv4Addr,
    server: Ipv4Addr,
) -> io::Result<()> {
    let msg = build_decline(xid, chaddr, yiaddr, server);
    let dest = SocketAddrV4::new(Ipv4Addr::BROADCAST, DHCP_SERVER_PORT);
    sock.send_to(&encode_msg(&msg)?, dest)?;
    Ok(())
}

enum DhcpReply {
    Offer(Message),
    Ack(Message),
    Nak,
}

fn recv_reply(sock: &UdpSocket, timeout: Duration, xid: u32) -> io::Result<DhcpReply> {
    sock.set_read_timeout(Some(timeout))?;
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 1500];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "dhcp recv timeout"));
        }
        sock.set_read_timeout(Some(left))?;
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "dhcp recv timeout"));
            }
            Err(e) => return Err(e),
        };
        let msg = match Message::decode(&mut Decoder::new(&buf[..n])) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if msg.xid() != xid {
            continue;
        }
        match msg_type(&msg) {
            Some(MessageType::Offer) => return Ok(DhcpReply::Offer(msg)),
            Some(MessageType::Ack) => return Ok(DhcpReply::Ack(msg)),
            Some(MessageType::Nak) => return Ok(DhcpReply::Nak),
            _ => continue,
        }
    }
}

struct Lease {
    ip: Ipv4Addr,
    prefix: u8,
    routers: Vec<Ipv4Addr>,
    dns: Vec<Ipv4Addr>,
    server: Ipv4Addr,
    lease_secs: u32,
    t1_secs: u32,
    t2_secs: u32,
    #[allow(dead_code)]
    #[allow(dead_code)]
    bound_at: Instant,
}

fn dora(
    iface: &str,
    tries: u32,
    timeout: Duration,
    quiet: bool,
    hostname: Option<&str>,
) -> io::Result<Lease> {
    let chaddr = read_mac(iface)?;
    let sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DHCP_CLIENT_PORT))?;
    set_broadcast(&sock)?;
    bind_to_device(&sock, iface)?;

    let dest = SocketAddrV4::new(Ipv4Addr::BROADCAST, DHCP_SERVER_PORT);
    for attempt in 1..=tries {
        let xid = rand_xid();
        log(
            quiet,
            &format!("discover attempt {attempt}/{tries} on {iface}"),
        );
        let discover = build_discover(xid, &chaddr, hostname);
        sock.send_to(&encode_msg(&discover)?, dest)?;

        let offer = match recv_reply(&sock, timeout, xid) {
            Ok(DhcpReply::Offer(m)) => m,
            Ok(DhcpReply::Nak) => {
                log(quiet, "nak during discover wait; retrying");
                continue;
            }
            Ok(_) => {
                log(quiet, "unexpected reply during discover; retrying");
                continue;
            }
            Err(e) => {
                log(quiet, &format!("no offer: {e}"));
                continue;
            }
        };
        let yiaddr = offer.yiaddr();
        let Some(server) = opt_server_id(&offer) else {
            log(quiet, "offermissing server id");
            continue;
        };

        let request = build_request(xid, &chaddr, yiaddr, server, hostname);
        sock.send_to(&encode_msg(&request)?, dest)?;

        let ack = match recv_reply(&sock, timeout, xid) {
            Ok(DhcpReply::Ack(m)) => m,
            Ok(DhcpReply::Nak) => {
                log(quiet, "nak from server; retrying discover");
                continue;
            }
            Ok(_) => {
                log(quiet, "unexpected reply during request; retrying");
                continue;
            }
            Err(e) => {
                log(quiet, &format!("no ack: {e}"));
                continue;
            }
        };

        let ip = ack.yiaddr();
        let mask = opt_subnet(&ack).unwrap_or_else(|| Ipv4Addr::new(255, 255, 255, 0));
        let prefix = mask_to_prefix(mask);
        let routers = opt_routers(&ack);
        let dns = opt_dns(&ack);
        let server = opt_server_id(&ack).unwrap_or(server);
        let lease_secs = opt_lease_secs(&ack).unwrap_or(3600);
        let t1_secs = opt_t1(&ack).unwrap_or(lease_secs / 2);
        let t2_secs = opt_t2(&ack).unwrap_or(lease_secs.saturating_mul(7) / 8);
        match arp_conflict(iface, ip, &chaddr) {
            Ok(true) => {
                log(quiet, &format!("ARP conflict for {ip}; sending decline"));
                let _ = send_decline(&sock, xid, &chaddr, ip, server);
                thread::sleep(Duration::from_secs(10));
                continue;
            }
            Ok(false) => {}
            Err(e) => {
                // If probe fails (permissions/no AF_PACKET), log and still bind.
                log(quiet, &format!("ARP probe failed ({e}); binding anyway"));
            }
        }

        return Ok(Lease {
            ip,
            prefix,
            routers,
            dns,
            server,
            lease_secs,
            t1_secs,
            t2_secs,
            bound_at: Instant::now(),
        });
    }

    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("dhcp failed on {iface} after {tries} tries"),
    ))
}

fn rand_xid() -> u32 {
    //cheap entropy without extra crates
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u32)
        .unwrap_or(1);
    t ^ std::process::id()
}

fn apply_builtin(iface: &str, lease: &Lease) -> io::Result<()> {
    let _ = run_ip(&["addr", "flush", "dev", iface]);
    run_ip(&[
        "addr",
        "add",
        &format!("{}/{}", lease.ip, lease.prefix),
        "dev",
        iface,
    ])?;
    run_ip(&["link", "set", iface, "up"])?;
    if let Some(gw) = lease.routers.first() {
        // replace: no prior default is fine; avoids "No such process" from del
        if run_ip(&[
            "route",
            "replace",
            "default",
            "via",
            &gw.to_string(),
            "dev",
            iface,
        ])
        .is_err()
        {
            // BusyBox without replace: ignore missing default, then add
            let _ = Command::new(ip_bin())
                .args(["route", "del", "default"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            run_ip(&[
                "route",
                "add",
                "default",
                "via",
                &gw.to_string(),
                "dev",
                iface,
            ])?;
        }
    }
    let mut resolv = String::new();
    for ns in &lease.dns {
        resolv.push_str(&format!("nameserver {ns}\n"));
    }
    fs::write("/etc/resolv.conf", resolv)?;
    Ok(())
}

fn apply_script(script: &str, iface: &str, lease: &Lease) -> io::Result<()> {
    let mask = prefix_to_dotted(lease.prefix);
    let router = lease
        .routers
        .iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let dns = lease
        .dns
        .iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(" ");

    let st = Command::new(script)
        .arg("bound")
        .env("interface", iface)
        .env("ip", lease.ip.to_string())
        .env("subnet", mask)
        .env("mask", lease.prefix.to_string())
        .env("router", router)
        .env("dns", dns)
        .status()?;
    if !st.success() {
        return Err(io::Error::other(format!("script {script} failed")));
    }
    Ok(())
}

fn prefix_to_dotted(prefix: u8) -> String {
    let bits = if prefix >= 32 {
        u32::MAX
    } else if prefix == 0 {
        0
    } else {
        (!0u32) << (32 - prefix)
    };
    Ipv4Addr::from(bits).to_string()
}

fn write_lease(path: &Path, iface: &str, lease: &Lease) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let routers = lease
        .routers
        .iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let dns = lease
        .dns
        .iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let obtained = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let body = format!(
        "iface={iface}\n\
        ip={}\n\
        prefix={}\n\
        server={}\n\
        routers={routers}\n\
        dns={dns}\n\
        lease_secs={}\n\
        t1_secs={}\n\
        t2_secs={}\n\
        obtained_unix={obtained}\n",
        lease.ip, lease.prefix, lease.server, lease.lease_secs, lease.t1_secs, lease.t2_secs,
    );
    fs::write(path, body)
}

fn read_lease(path: &Path) -> io::Result<(String, Lease, u64)> {
    let text = fs::read_to_string(path)?;
    let mut iface = String::new();
    let mut ip = None;
    let mut prefix = None;
    let mut server = None;
    let mut routers = Vec::new();
    let mut dns = Vec::new();
    let mut lease_secs = 3600u32;
    let mut t1_secs = 1800u32;
    let mut t2_secs = 3150u32;
    let mut obtained_unix = 0u64;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "iface" => iface = v.to_string(),
            "ip" => ip = v.parse().ok(),
            "prefix" => prefix = v.parse().ok(),
            "server" => server = v.parse().ok(),
            "routers" => {
                routers = v
                    .split_whitespace()
                    .filter_map(|s| s.parse().ok())
                    .collect();
            }
            "dns" => {
                dns = v
                    .split_whitespace()
                    .filter_map(|s| s.parse().ok())
                    .collect();
            }
            "lease_secs" => lease_secs = v.parse().unwrap_or(3600),
            "t1_secs" => t1_secs = v.parse().unwrap_or(lease_secs / 2),
            "t2_secs" => t2_secs = v.parse().unwrap_or(lease_secs.saturating_mul(7) / 8),
            "obtained_unix" => obtained_unix = v.parse().unwrap_or(0),
            _ => {}
        }
    }

    let ip = ip.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "lease missing ip"))?;
    let prefix =
        prefix.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "lease missing prefix"))?;
    let server =
        server.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "lease missing server"))?;

    Ok((
        iface,
        Lease {
            ip,
            prefix,
            routers,
            dns,
            server,
            lease_secs,
            t1_secs,
            t2_secs,
            bound_at: Instant::now(),
        },
        obtained_unix,
    ))
}

fn build_init_reboot(xid: u32, chaddr: &[u8], yiaddr: Ipv4Addr, hostname: Option<&str>) -> Message {
    // RFC 2131 INIT-REBOOT: broadcast REQUEST, requested IP set, NO server id
    let mut msg = Message::default();
    msg.set_opcode(Opcode::BootRequest)
        .set_xid(xid)
        .set_flags(v4::Flags::default().set_broadcast())
        .set_chaddr(chaddr);
    msg.opts_mut()
        .insert(v4::DhcpOption::MessageType(MessageType::Request));
    msg.opts_mut()
        .insert(v4::DhcpOption::ClientIdentifier(chaddr.to_vec()));
    msg.opts_mut()
        .insert(v4::DhcpOption::RequestedIpAddress(yiaddr));
    set_hostname(&mut msg, hostname);
    msg.opts_mut()
        .insert(v4::DhcpOption::ParameterRequestList(vec![
            v4::OptionCode::SubnetMask,
            v4::OptionCode::Router,
            v4::OptionCode::DomainNameServer,
            v4::OptionCode::DomainName,
        ]));
    msg
}

fn try_init_reboot(args: &Args, path: &Path) -> io::Result<Lease> {
    let (saved_iface, saved, obtained) = read_lease(path)?;
    if saved_iface != args.iface {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "lease iface mismatch",
        ));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if obtained + saved.lease_secs as u64 <= now {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "lease expired"));
    }

    let chaddr = read_mac(&args.iface)?;
    let sock = open_dhcp_socket(&args.iface)?;
    let xid = rand_xid();
    let req = build_init_reboot(xid, &chaddr, saved.ip, args.hostname.as_deref());
    let dest = SocketAddrV4::new(Ipv4Addr::BROADCAST, DHCP_SERVER_PORT);
    sock.send_to(&encode_msg(&req)?, dest)?;

    match recv_reply(&sock, args.timeout, xid)? {
        DhcpReply::Ack(ack) => {
            let ip = ack.yiaddr();
            let ip = if ip.is_unspecified() { saved.ip } else { ip };
            let mask = opt_subnet(&ack).unwrap_or_else(|| Ipv4Addr::new(255, 255, 255, 0));
            let prefix = mask_to_prefix(mask);
            let routers = opt_routers(&ack);
            let dns = opt_dns(&ack);
            let server = opt_server_id(&ack).unwrap_or(saved.server);
            let lease_secs = opt_lease_secs(&ack).unwrap_or(saved.lease_secs);
            let t1_secs = opt_t1(&ack).unwrap_or(lease_secs / 2);
            let t2_secs = opt_t2(&ack).unwrap_or(lease_secs.saturating_mul(7) / 8);
            log(
                args.quiet,
                &format!("init-reboot bound {ip}/{prefix} via {server}"),
            );
            match arp_conflict(&args.iface, ip, &chaddr) {
                Ok(true) => {
                    log(
                        args.quiet,
                        &format!("ARP conflict for {ip} on init-reboot; declining"),
                    );
                    let _ = send_decline(&sock, xid, &chaddr, ip, server);
                    return Err(io::Error::new(io::ErrorKind::AddrInUse, "arp conflict"));
                }
                Ok(false) => {}
                Err(e) => {
                    log(
                        args.quiet,
                        &format!("ARP probe failed ({e}); binding anyway"),
                    );
                }
            }
            Ok(Lease {
                ip,
                prefix,
                routers,
                dns,
                server,
                lease_secs,
                t1_secs,
                t2_secs,
                bound_at: Instant::now(),
            })
        }
        DhcpReply::Nak => Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "init-reboot nak",
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "init-reboot unexpected reply",
        )),
    }
}

fn deconfig(iface: &str) {
    let _ = run_ip(&["addr", "flush", "dev", iface]);
    let _ = Command::new(ip_bin())
        .args(["route", "del", "default"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn build_renew(xid: u32, chaddr: &[u8], lease: &Lease, hostname: Option<&str>) -> Message {
    let mut msg = Message::default();
    msg.set_opcode(Opcode::BootRequest)
        .set_xid(xid)
        .set_ciaddr(lease.ip)
        .set_chaddr(chaddr);
    msg.opts_mut()
        .insert(v4::DhcpOption::MessageType(MessageType::Request));
    msg.opts_mut()
        .insert(v4::DhcpOption::ClientIdentifier(chaddr.to_vec()));
    set_hostname(&mut msg, hostname);
    msg.opts_mut()
        .insert(v4::DhcpOption::ParameterRequestList(vec![
            v4::OptionCode::SubnetMask,
            v4::OptionCode::Router,
            v4::OptionCode::DomainNameServer,
            v4::OptionCode::DomainName,
        ]));
    msg
}

fn build_release(xid: u32, chaddr: &[u8], lease: &Lease) -> Message {
    let mut msg = Message::default();
    msg.set_opcode(Opcode::BootRequest)
        .set_xid(xid)
        .set_ciaddr(lease.ip)
        .set_chaddr(chaddr);
    msg.opts_mut()
        .insert(v4::DhcpOption::MessageType(MessageType::Release));
    msg.opts_mut()
        .insert(v4::DhcpOption::ClientIdentifier(chaddr.to_vec()));
    msg.opts_mut()
        .insert(v4::DhcpOption::ServerIdentifier(lease.server));
    msg
}

fn do_release(args: &Args, sock: &UdpSocket, chaddr: &[u8], lease: &Lease) {
    log(args.quiet, "releasing lease");
    let xid = rand_xid();
    let msg = build_release(xid, chaddr, lease);
    let dest = SocketAddrV4::new(lease.server, DHCP_SERVER_PORT);
    if let Ok(bytes) = encode_msg(&msg) {
        let _ = sock.send_to(&bytes, dest);
    }
    deconfig(&args.iface);
    if let Some(ref path) = args.lease_path {
        let _ = fs::remove_file(path);
    }
}

fn open_dhcp_socket(iface: &str) -> io::Result<UdpSocket> {
    let sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DHCP_CLIENT_PORT))?;
    set_broadcast(&sock)?;
    bind_to_device(&sock, iface)?;
    Ok(sock)
}

fn run_renew_loop(args: &Args, mut lease: Lease) -> ExitCode {
    let chaddr = match read_mac(&args.iface) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("rlease: {e}");
            return ExitCode::from(1);
        }
    };
    let sock = match open_dhcp_socket(&args.iface) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("rlease: {e}");
            return ExitCode::from(1);
        }
    };

    loop {
        if stop_requested() {
            do_release(args, &sock, &chaddr, &lease);
            return ExitCode::SUCCESS;
        }

        let t1_wait = Duration::from_secs(lease.t1_secs as u64);
        log(args.quiet, &format!("sleeping {t1_wait:?} until T1 renew"));
        if sleep_interruptible(t1_wait) {
            do_release(args, &sock, &chaddr, &lease);
            return ExitCode::SUCCESS;
        }

        let xid = rand_xid();
        let req = build_renew(xid, &chaddr, &lease, args.hostname.as_deref());
        let dest = SocketAddrV4::new(lease.server, DHCP_SERVER_PORT);
        if sock
            .send_to(&encode_msg(&req).unwrap_or_default(), dest)
            .is_err()
        {
            log(args.quiet, "renew send failed");
        }

        match recv_reply(&sock, args.timeout, xid) {
            Ok(DhcpReply::Ack(ack)) => {
                let ip = ack.yiaddr();
                let ip = if ip.is_unspecified() { lease.ip } else { ip };
                let mask = opt_subnet(&ack).unwrap_or_else(|| Ipv4Addr::new(255, 255, 255, 0));
                let prefix = mask_to_prefix(mask);
                let routers = opt_routers(&ack);
                let dns = opt_dns(&ack);
                let server = opt_server_id(&ack).unwrap_or(lease.server);
                let lease_secs = opt_lease_secs(&ack).unwrap_or(lease.lease_secs);
                let t1_secs = opt_t1(&ack).unwrap_or(lease_secs / 2);
                let t2_secs = opt_t2(&ack).unwrap_or(lease_secs.saturating_mul(7) / 8);
                lease = Lease {
                    ip,
                    prefix,
                    routers,
                    dns,
                    server,
                    lease_secs,
                    t1_secs,
                    t2_secs,
                    bound_at: Instant::now(),
                };
                log(args.quiet, &format!("renewed {ip}/{prefix} via {server}"));
                let _ = apply_builtin(&args.iface, &lease);
                if let Some(ref path) = args.lease_path {
                    let _ = write_lease(path, &args.iface, &lease);
                }
                continue;
            }
            Ok(DhcpReply::Nak) => {
                log(args.quiet, "renew nak; trying rebind");
            }
            Ok(_) => {
                log(args.quiet, "renew unexpected reply; trying rebind");
            }
            Err(_e) => {
                log(args.quiet, "renew failed; trying rebind");
            }
        }

        // T2 rebind: broadcast REQUEST
        let rebind_wait = Duration::from_secs(lease.t2_secs.saturating_sub(lease.t1_secs) as u64);
        if sleep_interruptible(rebind_wait) {
            do_release(args, &sock, &chaddr, &lease);
            return ExitCode::SUCCESS;
        }
        let xid = rand_xid();
        let req = build_renew(xid, &chaddr, &lease, args.hostname.as_deref());
        let bcast = SocketAddrV4::new(Ipv4Addr::BROADCAST, DHCP_SERVER_PORT);
        let _ = sock.send_to(&encode_msg(&req).unwrap_or_default(), bcast);
        match recv_reply(&sock, args.timeout, xid) {
            Ok(DhcpReply::Ack(ack)) => {
                let ip = ack.yiaddr();
                let ip = if ip.is_unspecified() { lease.ip } else { ip };
                let mask = opt_subnet(&ack).unwrap_or_else(|| Ipv4Addr::new(255, 255, 255, 0));
                let prefix = mask_to_prefix(mask);
                let routers = opt_routers(&ack);
                let dns = opt_dns(&ack);
                let server = opt_server_id(&ack).unwrap_or(lease.server);
                let lease_secs = opt_lease_secs(&ack).unwrap_or(3600);
                let t1_secs = opt_t1(&ack).unwrap_or(lease_secs / 2);
                let t2_secs = opt_t2(&ack).unwrap_or(lease_secs.saturating_mul(7) / 8);
                lease = Lease {
                    ip,
                    prefix,
                    routers,
                    dns,
                    server,
                    lease_secs,
                    t1_secs,
                    t2_secs,
                    bound_at: Instant::now(),
                };
                let _ = apply_builtin(&args.iface, &lease);
                if let Some(ref path) = args.lease_path {
                    let _ = write_lease(path, &args.iface, &lease);
                }
                continue;
            }
            Ok(DhcpReply::Nak) => {
                log(args.quiet, "rebind nak; rediscovering");
                deconfig(&args.iface);
                match dora(
                    &args.iface,
                    args.tries,
                    args.timeout,
                    args.quiet,
                    args.hostname.as_deref(),
                ) {
                    Ok(l) => {
                        lease = l;
                        let _ = apply_builtin(&args.iface, &lease);
                        if let Some(ref path) = args.lease_path {
                            let _ = write_lease(path, &args.iface, &lease);
                        }
                    }
                    Err(e) => {
                        eprintln!("rlease: {e}");
                        return ExitCode::from(1);
                    }
                }
            }
            Ok(_) | Err(_) => {
                log(args.quiet, "rebind failed; rediscovering");
                deconfig(&args.iface);
                match dora(
                    &args.iface,
                    args.tries,
                    args.timeout,
                    args.quiet,
                    args.hostname.as_deref(),
                ) {
                    Ok(l) => {
                        lease = l;
                        let _ = apply_builtin(&args.iface, &lease);
                        if let Some(ref path) = args.lease_path {
                            let _ = write_lease(path, &args.iface, &lease);
                        }
                    }
                    Err(e) => {
                        eprintln!("rlease: {e}");
                        return ExitCode::from(1);
                    }
                }
            }
        }
    }
}

fn main() -> ExitCode {
    install_stop_handlers();
    let args = parse_args();

    if !Path::new(&format!("/sys/class/net/{}", args.iface)).exists() {
        eprintln!("rlease: interface {} not found", args.iface);
        return ExitCode::from(1);
    }

    if let Err(e) = run_ip(&["link", "set", "lo", "up"]) {
        eprintln!("rlease: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = run_ip(&["link", "set", &args.iface, "up"]) {
        eprintln!("rlease: {e}");
        return ExitCode::from(1);
    }
    if let Err(e) = wait_carrier(&args.iface, args.quiet) {
        eprintln!("rlease: {e}");
        return ExitCode::from(1);
    }

    let lease = if let Some(ref path) = args.lease_path {
        match try_init_reboot(&args, path) {
            Ok(l) => l,
            Err(e) => {
                log(
                    args.quiet,
                    &format!("init-reboot failed ({e}); doing discover"),
                );
                match dora(
                    &args.iface,
                    args.tries,
                    args.timeout,
                    args.quiet,
                    args.hostname.as_deref(),
                ) {
                    Ok(l) => l,
                    Err(e) => {
                        eprintln!("rlease: {e}");
                        return ExitCode::from(1);
                    }
                }
            }
        }
    } else {
        match dora(
            &args.iface,
            args.tries,
            args.timeout,
            args.quiet,
            args.hostname.as_deref(),
        ) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("rlease: {e}");
                return ExitCode::from(1);
            }
        }
    };

    let apply = if let Some(ref script) = args.script {
        apply_script(script, &args.iface, &lease)
    } else {
        apply_builtin(&args.iface, &lease)
    };
    if let Err(e) = apply {
        eprintln!("rlease: apply failed: {e}");
        return ExitCode::from(1);
    }

    if let Some(ref path) = args.lease_path
        && let Err(e) = write_lease(path, &args.iface, &lease)
    {
        eprintln!("rlease: lease write failed: {e}");
        return ExitCode::from(1);
    }

    if args.oneshot {
        return ExitCode::SUCCESS;
    }

    run_renew_loop(&args, lease)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn mask_to_prefix_slash24() {
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 255, 0)), 24);
    }

    #[test]
    fn mask_to_prefix_slash32() {
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 255, 255)), 32);
    }

    #[test]
    fn prefix_to_dotted_roundtrip() {
        assert_eq!(prefix_to_dotted(24), "255.255.255.0");
        assert_eq!(prefix_to_dotted(16), "255.255.0.0");
        assert_eq!(prefix_to_dotted(0), "0.0.0.0");
    }

    #[test]
    fn discover_is_boot_requst_with_hostname() {
        let chaddr = vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let msg = build_discover(0xdeadbeef, &chaddr, Some("northstar"));
        assert_eq!(msg.xid(), 0xdeadbeef);
        assert_eq!(msg_type(&msg), Some(MessageType::Discover));
        match msg.opts().get(v4::OptionCode::Hostname) {
            Some(v4::DhcpOption::Hostname(h)) => assert_eq!(h, "northstar"),
            other => panic!("expected Hostname, got {other:?}"),
        }
        let bytes = encode_msg(&msg).expect("encode");
        assert!(!bytes.is_empty());
    }

    #[test]
    fn request_has_requested_ip_and_server_id() {
        let chaddr = vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let yi = Ipv4Addr::new(10, 0, 2, 15);
        let srv = Ipv4Addr::new(10, 0, 2, 2);
        let msg = build_request(1, &chaddr, yi, srv, None);
        assert_eq!(msg_type(&msg), Some(MessageType::Request));
        match msg.opts().get(v4::OptionCode::RequestedIpAddress) {
            Some(v4::DhcpOption::RequestedIpAddress(a)) => assert_eq!(*a, yi),
            other => panic!("expected RequestedIpAddress, got {other:?}"),
        }
        match msg.opts().get(v4::OptionCode::ServerIdentifier) {
            Some(v4::DhcpOption::ServerIdentifier(a)) => assert_eq!(*a, srv),
            other => panic!("expected ServerIdentifier, got {other:?}"),
        }
    }

    #[test]
    fn init_reboot_has_no_server_id() {
        let chaddr = vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let msg = build_init_reboot(1, &chaddr, Ipv4Addr::new(10, 0, 2, 15), None);
        assert_eq!(msg_type(&msg), Some(MessageType::Request));
        assert!(msg.opts().get(v4::OptionCode::ServerIdentifier).is_none());
    }

    #[test]
    fn decline_message_type() {
        let chaddr = vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let msg = build_decline(
            1,
            &chaddr,
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(10, 0, 2, 2),
        );
        assert_eq!(msg_type(&msg), Some(MessageType::Decline));
    }

    #[test]
    fn release_message_type() {
        let lease = Lease {
            ip: Ipv4Addr::new(10, 0, 2, 15),
            prefix: 24,
            routers: vec![Ipv4Addr::new(10, 0, 2, 2)],
            dns: vec![],
            server: Ipv4Addr::new(10, 0, 2, 2),
            lease_secs: 3600,
            t1_secs: 1800,
            t2_secs: 3600,
            bound_at: Instant::now(),
        };
        let chaddr = vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let msg = build_release(1, &chaddr, &lease);
        assert_eq!(msg_type(&msg), Some(MessageType::Release));
    }

    #[test]
    fn lease_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("rlease-test-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("eth0.lease");

        let lease = Lease {
            ip: Ipv4Addr::new(10, 0, 2, 15),
            prefix: 24,
            routers: vec![Ipv4Addr::new(10, 0, 2, 2)],
            dns: vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(9, 9, 9, 9)],
            server: Ipv4Addr::new(10, 0, 2, 2),
            lease_secs: 3600,
            t1_secs: 1800,
            t2_secs: 3150,
            bound_at: Instant::now(),
        };
        write_lease(&path, "eth0", &lease).expect("write");
        let (iface, got, obtained) = read_lease(&path).expect("read");
        assert_eq!(iface, "eth0");
        assert_eq!(got.ip, lease.ip);
        assert_eq!(got.prefix, 24);
        assert_eq!(got.server, lease.server);
        assert_eq!(got.routers, lease.routers);
        assert_eq!(got.dns, lease.dns);
        assert_eq!(got.lease_secs, 3600);
        assert!(obtained > 0);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn set_hostname_skips_empty() {
        let mut msg = Message::default();
        set_hostname(&mut msg, Some(""));
        assert!(msg.opts().get(v4::OptionCode::Hostname).is_none());
        set_hostname(&mut msg, Some("box"));
        assert!(msg.opts().get(v4::OptionCode::Hostname).is_some());
    }
}
