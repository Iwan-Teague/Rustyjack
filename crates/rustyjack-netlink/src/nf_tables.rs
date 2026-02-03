use std::collections::HashSet;
use std::ffi::CString;
use std::io;
use std::mem;
use std::net::IpAddr;
use std::os::unix::io::RawFd;

use sha1::{Digest, Sha1};
use tracing::warn;

use crate::iptables::{Chain, IptablesError, Protocol, Rule, Table, Target};

// Netfilter/netlink constants are derived from linux/netfilter/nf_tables.h and friends.
// This is a minimal subset needed to mirror Rustyjack's iptables API.
const NETLINK_NETFILTER: i32 = 12;
const NFNETLINK_V0: u8 = 0;
const NFNL_SUBSYS_NFTABLES: u16 = 10;

const NLMSG_HDRLEN: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_APPEND: u16 = 0x800;
const NLM_F_ROOT: u16 = 0x100;
const NLM_F_MATCH: u16 = 0x200;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

const NLA_F_NESTED: u16 = 1 << 15;
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
const NLA_HDRLEN: usize = 4;
const NLA_ALIGNTO: usize = 4;

const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_NEWRULE: u16 = 6;
const NFT_MSG_GETRULE: u16 = 7;
const NFT_MSG_DELRULE: u16 = 8;

const NFTA_TABLE_NAME: u16 = 1;
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_TYPE: u16 = 7;

const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;

const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_HANDLE: u16 = 3;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_RULE_USERDATA: u16 = 7;

const NFTA_LIST_ELEM: u16 = 1;

const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;

const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;

const NFTA_PAYLOAD_DREG: u16 = 1;
const NFTA_PAYLOAD_BASE: u16 = 2;
const NFTA_PAYLOAD_OFFSET: u16 = 3;
const NFTA_PAYLOAD_LEN: u16 = 4;

const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;

const NFTA_CT_DREG: u16 = 1;
const NFTA_CT_KEY: u16 = 2;

const NFTA_BITWISE_SREG: u16 = 1;
const NFTA_BITWISE_DREG: u16 = 2;
const NFTA_BITWISE_LEN: u16 = 3;
const NFTA_BITWISE_MASK: u16 = 4;
const NFTA_BITWISE_XOR: u16 = 5;

const NFTA_IMMEDIATE_DREG: u16 = 1;
const NFTA_IMMEDIATE_DATA: u16 = 2;

const NFTA_DATA_VALUE: u16 = 1;
const NFTA_DATA_VERDICT: u16 = 2;

const NFTA_VERDICT_CODE: u16 = 1;

const NFTA_NAT_TYPE: u16 = 1;
const NFTA_NAT_FAMILY: u16 = 2;
const NFTA_NAT_REG_ADDR_MIN: u16 = 3;
const NFTA_NAT_REG_ADDR_MAX: u16 = 4;
const NFTA_NAT_REG_PROTO_MIN: u16 = 5;
const NFTA_NAT_REG_PROTO_MAX: u16 = 6;
const NFTA_NAT_FLAGS: u16 = 7;

const NFTA_MASQ_FLAGS: u16 = 1;

const NFTA_LOG_PREFIX: u16 = 1;
const NFTA_LOG_LEVEL: u16 = 5;

const NFTA_REJECT_TYPE: u16 = 1;
const NFTA_REJECT_CODE: u16 = 2;

const NFTA_TCP_OPTION_KIND: u16 = 1;
const NFTA_TCP_OPTION_LENGTH: u16 = 2;
const NFTA_TCP_OPTION_DATA: u16 = 3;

const NFT_PAYLOAD_NETWORK_HEADER: u32 = 1;
const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;

const NFT_META_IIFNAME: u32 = 6;
const NFT_META_OIFNAME: u32 = 7;
const NFT_META_L4PROTO: u32 = 16;

const NFT_REG_VERDICT: u32 = 0;
const NFT_REG_1: u32 = 1;
const NFT_REG_2: u32 = 2;

const NFT_CMP_EQ: u32 = 0;
const NFT_CMP_NEQ: u32 = 1;

const NFT_CT_STATE: u32 = 0;

const NFT_NAT_SNAT: u32 = 0;
const NFT_NAT_DNAT: u32 = 1;

const NFT_ACCEPT: u32 = 1;
const NFT_DROP: u32 = 0;

const NFT_REJECT_TCP_RST: u32 = 1;
const NFT_REJECT_ICMPX_PORT_UNREACH: u32 = 3;

const NFPROTO_IPV4: u32 = 2;

const NF_INET_PRE_ROUTING: u32 = 0;
const NF_INET_LOCAL_IN: u32 = 1;
const NF_INET_FORWARD: u32 = 2;
const NF_INET_LOCAL_OUT: u32 = 3;
const NF_INET_POST_ROUTING: u32 = 4;

const NF_IP_PRI_RAW: i32 = -300;
const NF_IP_PRI_MANGLE: i32 = -150;
const NF_IP_PRI_NAT_DST: i32 = -100;
const NF_IP_PRI_FILTER: i32 = 0;
const NF_IP_PRI_NAT_SRC: i32 = 100;

const TCP_OPT_MSS: u8 = 2;
const NFT_LOG_PREFIX_MAX: usize = 64;

#[derive(Debug)]
struct NetlinkMessage {
    header: NlHeader,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct NlHeader {
    len: u32,
    msg_type: u16,
    _flags: u16,
    seq: u32,
    _pid: u32,
}

struct NetfilterSocket {
    fd: RawFd,
    seq: u32,
    pid: u32,
}

impl Drop for NetfilterSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

impl NetfilterSocket {
    fn new() -> io::Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_NETFILTER) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let pid = unsafe { libc::getpid() as u32 };
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = pid;
        addr.nl_groups = 0;
        let bind_result = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if bind_result < 0 {
            let err = io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }

        Ok(Self { fd, seq: 0, pid })
    }

    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }

    fn send(&mut self, msg_type: u16, flags: u16, payload: &[u8]) -> io::Result<u32> {
        let seq = self.next_seq();
        let msg = build_nlmsg(msg_type, flags, seq, self.pid, payload);
        let ret = unsafe { libc::send(self.fd, msg.as_ptr() as *const libc::c_void, msg.len(), 0) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(seq)
    }

    fn recv_msgs(&mut self) -> io::Result<Vec<NetlinkMessage>> {
        let mut buf = vec![0u8; 64 * 1024];
        let len =
            unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if len < 0 {
            return Err(io::Error::last_os_error());
        }
        buf.truncate(len as usize);
        Ok(parse_nlmsgs(&buf))
    }

    fn send_and_ack(&mut self, msg_type: u16, flags: u16, payload: &[u8]) -> io::Result<()> {
        let seq = self.send(msg_type, flags, payload)?;
        loop {
            let msgs = self.recv_msgs()?;
            for msg in msgs {
                if msg.header.seq != seq {
                    continue;
                }
                if msg.header.msg_type == NLMSG_ERROR {
                    return parse_nlmsg_error(&msg.payload);
                }
                if msg.header.msg_type == NLMSG_DONE {
                    return Ok(());
                }
            }
        }
    }

    fn send_and_dump(
        &mut self,
        msg_type: u16,
        flags: u16,
        payload: &[u8],
    ) -> io::Result<Vec<NetlinkMessage>> {
        let seq = self.send(msg_type, flags, payload)?;
        let mut out = Vec::new();
        loop {
            let msgs = self.recv_msgs()?;
            for msg in msgs {
                if msg.header.seq != seq {
                    continue;
                }
                match msg.header.msg_type {
                    NLMSG_ERROR => {
                        parse_nlmsg_error(&msg.payload)?;
                    }
                    NLMSG_DONE => return Ok(out),
                    _ => out.push(msg),
                }
            }
        }
    }
}

pub(crate) struct NfTablesManager {
    socket: NetfilterSocket,
    known_tables: HashSet<String>,
    known_chains: HashSet<(String, String)>,
}

impl NfTablesManager {
    pub(crate) fn new() -> Result<Self, IptablesError> {
        let socket = NetfilterSocket::new().map_err(to_netlink_error)?;
        Ok(Self {
            socket,
            known_tables: HashSet::new(),
            known_chains: HashSet::new(),
        })
    }

    pub(crate) fn add_rule(&mut self, rule: &Rule) -> Result<(), IptablesError> {
        let table = rule.table.as_str();
        let chain = rule.chain.as_str();
        self.ensure_table(table)?;
        self.ensure_chain(
            table,
            chain,
            base_chain_spec(rule.table, rule.chain.clone()),
        )?;

        let mut payload = nfgenmsg_payload();
        push_attr_string(&mut payload, NFTA_RULE_TABLE, table)?;
        push_attr_string(&mut payload, NFTA_RULE_CHAIN, chain)?;

        let exprs = build_rule_exprs(rule)?;
        push_attr_nested(&mut payload, NFTA_RULE_EXPRESSIONS, |buf| {
            buf.extend_from_slice(&exprs);
        });

        let userdata = rule_userdata(rule);
        push_attr_bytes(&mut payload, NFTA_RULE_USERDATA, &userdata);

        let msg_type = nft_msg_type(NFT_MSG_NEWRULE);
        let flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND;
        self.socket
            .send_and_ack(msg_type, flags, &payload)
            .map_err(to_netlink_error)?;
        Ok(())
    }

    pub(crate) fn delete_rule(&mut self, rule: &Rule) -> Result<(), IptablesError> {
        let table = rule.table.as_str();
        let chain = rule.chain.as_str();
        let userdata = rule_userdata(rule);
        let rules = self.list_rules(Some(table), Some(chain))?;

        if let Some(info) = rules.into_iter().find(|info| info.userdata == userdata) {
            self.delete_rule_handle(table, &info.chain, info.handle)?;
        }

        Ok(())
    }

    pub(crate) fn flush_chain(&mut self, table: Table, chain: Chain) -> Result<(), IptablesError> {
        let table_name = table.as_str();
        let chain_name = chain.as_str();
        let rules = match self.list_rules(Some(table_name), Some(chain_name)) {
            Ok(rules) => rules,
            Err(err) => {
                tracing::warn!(
                    "Failed to list rules for {} {}: {}",
                    table_name,
                    chain_name,
                    err
                );
                return Ok(());
            }
        };

        for info in rules {
            let _ = self.delete_rule_handle(table_name, &info.chain, info.handle);
        }

        Ok(())
    }

    pub(crate) fn flush_table(&mut self, table: Table) -> Result<(), IptablesError> {
        let table_name = table.as_str();
        let rules = match self.list_rules(Some(table_name), None) {
            Ok(rules) => rules,
            Err(err) => {
                tracing::warn!("Failed to list rules for {}: {}", table_name, err);
                return Ok(());
            }
        };

        for info in rules {
            let _ = self.delete_rule_handle(table_name, &info.chain, info.handle);
        }

        Ok(())
    }

    fn ensure_table(&mut self, table: &str) -> Result<(), IptablesError> {
        if self.known_tables.contains(table) {
            return Ok(());
        }

        let mut payload = nfgenmsg_payload();
        push_attr_string(&mut payload, NFTA_TABLE_NAME, table)?;
        let msg_type = nft_msg_type(NFT_MSG_NEWTABLE);
        let flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;

        match self.socket.send_and_ack(msg_type, flags, &payload) {
            Ok(()) => {
                self.known_tables.insert(table.to_string());
                Ok(())
            }
            Err(err) => match err.raw_os_error() {
                Some(code) if code == libc::EEXIST => {
                    self.known_tables.insert(table.to_string());
                    Ok(())
                }
                _ => Err(to_netlink_error(err)),
            },
        }
    }

    fn ensure_chain(
        &mut self,
        table: &str,
        chain: &str,
        base: Option<BaseChainSpec>,
    ) -> Result<(), IptablesError> {
        let key = (table.to_string(), chain.to_string());
        if self.known_chains.contains(&key) {
            return Ok(());
        }

        let mut payload = nfgenmsg_payload();
        push_attr_string(&mut payload, NFTA_CHAIN_TABLE, table)?;
        push_attr_string(&mut payload, NFTA_CHAIN_NAME, chain)?;

        if let Some(spec) = base {
            push_attr_string(&mut payload, NFTA_CHAIN_TYPE, spec.chain_type)?;
            push_attr_nested(&mut payload, NFTA_CHAIN_HOOK, |buf| {
                push_attr_u32(buf, NFTA_HOOK_HOOKNUM, spec.hook);
                push_attr_i32(buf, NFTA_HOOK_PRIORITY, spec.priority);
            });
            if let Some(policy) = spec.policy {
                push_attr_u32(&mut payload, NFTA_CHAIN_POLICY, policy);
            }
        }

        let msg_type = nft_msg_type(NFT_MSG_NEWCHAIN);
        let flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;

        match self.socket.send_and_ack(msg_type, flags, &payload) {
            Ok(()) => {
                self.known_chains.insert(key);
                Ok(())
            }
            Err(err) => match err.raw_os_error() {
                Some(code) if code == libc::EEXIST => {
                    self.known_chains.insert(key);
                    Ok(())
                }
                _ => Err(to_netlink_error(err)),
            },
        }
    }

    fn delete_rule_handle(
        &mut self,
        table: &str,
        chain: &str,
        handle: u64,
    ) -> Result<(), IptablesError> {
        let mut payload = nfgenmsg_payload();
        push_attr_string(&mut payload, NFTA_RULE_TABLE, table)?;
        push_attr_string(&mut payload, NFTA_RULE_CHAIN, chain)?;
        push_attr_u64(&mut payload, NFTA_RULE_HANDLE, handle);

        let msg_type = nft_msg_type(NFT_MSG_DELRULE);
        let flags = NLM_F_REQUEST | NLM_F_ACK;
        self.socket
            .send_and_ack(msg_type, flags, &payload)
            .map_err(to_netlink_error)?;
        Ok(())
    }

    fn list_rules(
        &mut self,
        table: Option<&str>,
        chain: Option<&str>,
    ) -> Result<Vec<RuleInfo>, IptablesError> {
        let mut payload = nfgenmsg_payload();
        if table.is_some() && chain.is_some() {
            if let Some(table) = table {
                push_attr_string(&mut payload, NFTA_RULE_TABLE, table)?;
            }
            if let Some(chain) = chain {
                push_attr_string(&mut payload, NFTA_RULE_CHAIN, chain)?;
            }
        }

        let msg_type = nft_msg_type(NFT_MSG_GETRULE);
        let flags = NLM_F_REQUEST | NLM_F_DUMP;
        let msgs = self
            .socket
            .send_and_dump(msg_type, flags, &payload)
            .map_err(to_netlink_error)?;

        let mut rules = Vec::new();
        for msg in msgs {
            let payload = msg.payload;
            if payload.len() < 4 {
                continue;
            }
            let attrs = parse_attrs(&payload[4..]);
            let mut handle = None;
            let mut userdata = None;
            let mut rule_chain = None;
            let mut rule_table = None;
            for attr in attrs {
                match attr.attr_type {
                    NFTA_RULE_HANDLE => {
                        handle = parse_u64(&attr.payload);
                    }
                    NFTA_RULE_USERDATA => {
                        userdata = Some(attr.payload);
                    }
                    NFTA_RULE_CHAIN => {
                        rule_chain = Some(parse_string(&attr.payload));
                    }
                    NFTA_RULE_TABLE => {
                        rule_table = Some(parse_string(&attr.payload));
                    }
                    _ => {}
                }
            }

            let Some(handle) = handle else { continue };
            let Some(chain_name) = rule_chain else {
                continue;
            };
            let Some(table_name) = rule_table else {
                continue;
            };

            if let Some(filter_table) = table {
                if filter_table != table_name {
                    continue;
                }
            }
            if let Some(filter_chain) = chain {
                if filter_chain != chain_name {
                    continue;
                }
            }

            rules.push(RuleInfo {
                handle,
                chain: chain_name,
                userdata: userdata.unwrap_or_default(),
            });
        }

        Ok(rules)
    }
}

#[derive(Debug)]
struct RuleInfo {
    handle: u64,
    chain: String,
    userdata: Vec<u8>,
}

struct BaseChainSpec {
    hook: u32,
    priority: i32,
    chain_type: &'static str,
    policy: Option<u32>,
}

fn base_chain_spec(table: Table, chain: Chain) -> Option<BaseChainSpec> {
    let hook = match chain {
        Chain::Input => Some(NF_INET_LOCAL_IN),
        Chain::Output => Some(NF_INET_LOCAL_OUT),
        Chain::Forward => Some(NF_INET_FORWARD),
        Chain::Prerouting => Some(NF_INET_PRE_ROUTING),
        Chain::Postrouting => Some(NF_INET_POST_ROUTING),
        Chain::Custom(_) => None,
    }?;

    let (chain_type, priority, policy) = match table {
        Table::Filter => ("filter", NF_IP_PRI_FILTER, Some(NFT_ACCEPT)),
        Table::Nat => {
            let priority = match chain {
                Chain::Prerouting => NF_IP_PRI_NAT_DST,
                Chain::Postrouting => NF_IP_PRI_NAT_SRC,
                Chain::Output => NF_IP_PRI_NAT_DST,
                _ => NF_IP_PRI_NAT_DST,
            };
            ("nat", priority, None)
        }
        Table::Mangle => ("filter", NF_IP_PRI_MANGLE, Some(NFT_ACCEPT)),
        Table::Raw => ("filter", NF_IP_PRI_RAW, Some(NFT_ACCEPT)),
    };

    Some(BaseChainSpec {
        hook,
        priority,
        chain_type,
        policy,
    })
}

fn build_rule_exprs(rule: &Rule) -> Result<Vec<u8>, IptablesError> {
    if (rule.src_port.is_some() || rule.dst_port.is_some())
        && !matches!(rule.protocol, Some(Protocol::Tcp | Protocol::Udp))
    {
        return Err(IptablesError::InvalidPort(
            "port match requires TCP or UDP protocol".to_string(),
        ));
    }

    let mut exprs = Vec::new();

    if let Some(in_iface) = &rule.in_interface {
        let iface = iface_bytes(in_iface)?;
        append_meta_cmp(&mut exprs, NFT_META_IIFNAME, &iface);
    }

    if let Some(out_iface) = &rule.out_interface {
        let iface = iface_bytes(out_iface)?;
        append_meta_cmp(&mut exprs, NFT_META_OIFNAME, &iface);
    }

    if let Some(proto) = rule.protocol {
        if proto != Protocol::All {
            append_meta_cmp(&mut exprs, NFT_META_L4PROTO, &[proto_number(proto)]);
        }
    }

    if let Some(source) = rule.source {
        let addr = ipv4_bytes(source)?;
        append_payload_cmp(&mut exprs, NFT_PAYLOAD_NETWORK_HEADER, 12, &addr);
    }

    if let Some(destination) = rule.destination {
        let addr = ipv4_bytes(destination)?;
        append_payload_cmp(&mut exprs, NFT_PAYLOAD_NETWORK_HEADER, 16, &addr);
    }

    if let Some(port) = rule.src_port {
        let data = port.to_be_bytes();
        append_payload_cmp(&mut exprs, NFT_PAYLOAD_TRANSPORT_HEADER, 0, &data);
    }

    if let Some(port) = rule.dst_port {
        let data = port.to_be_bytes();
        append_payload_cmp(&mut exprs, NFT_PAYLOAD_TRANSPORT_HEADER, 2, &data);
    }

    if let Some(state) = &rule.state {
        let mask = parse_ct_state(state)?;
        append_ct_state(&mut exprs, mask);
    }

    if rule.counter {
        append_expr(&mut exprs, "counter", |_| {});
    }

    if let Some(prefix) = &rule.log_prefix {
        append_log_expr(&mut exprs, prefix, rule.log_level)?;
    }

    append_target_exprs(&mut exprs, rule)?;

    Ok(exprs)
}

fn append_target_exprs(exprs: &mut Vec<u8>, rule: &Rule) -> Result<(), IptablesError> {
    match &rule.target {
        Target::Accept => append_verdict(exprs, NFT_ACCEPT),
        Target::Drop => append_verdict(exprs, NFT_DROP),
        Target::Reject => {
            let (reject_type, reject_code) = match rule.protocol {
                Some(Protocol::Tcp) => (NFT_REJECT_TCP_RST, 0),
                _ => (NFT_REJECT_ICMPX_PORT_UNREACH, 0),
            };
            append_expr(exprs, "reject", |buf| {
                push_attr_u32(buf, NFTA_REJECT_TYPE, reject_type);
                push_attr_u32(buf, NFTA_REJECT_CODE, reject_code);
            });
        }
        Target::Masquerade => {
            append_expr(exprs, "masq", |buf| {
                push_attr_u32(buf, NFTA_MASQ_FLAGS, 0);
            });
        }
        Target::Dnat { to, port } => {
            let addr = ipv4_bytes(*to)?;
            append_immediate_data(exprs, NFT_REG_1, &addr);
            if let Some(port) = port {
                append_immediate_data(exprs, NFT_REG_2, &port.to_be_bytes());
            }
            append_expr(exprs, "nat", |buf| {
                push_attr_u32(buf, NFTA_NAT_TYPE, NFT_NAT_DNAT);
                push_attr_u32(buf, NFTA_NAT_FAMILY, NFPROTO_IPV4);
                push_attr_u32(buf, NFTA_NAT_REG_ADDR_MIN, NFT_REG_1);
                push_attr_u32(buf, NFTA_NAT_REG_ADDR_MAX, NFT_REG_1);
                if port.is_some() {
                    push_attr_u32(buf, NFTA_NAT_REG_PROTO_MIN, NFT_REG_2);
                    push_attr_u32(buf, NFTA_NAT_REG_PROTO_MAX, NFT_REG_2);
                }
                push_attr_u32(buf, NFTA_NAT_FLAGS, 0);
            });
        }
        Target::Snat { to } => {
            let addr = ipv4_bytes(*to)?;
            append_immediate_data(exprs, NFT_REG_1, &addr);
            append_expr(exprs, "nat", |buf| {
                push_attr_u32(buf, NFTA_NAT_TYPE, NFT_NAT_SNAT);
                push_attr_u32(buf, NFTA_NAT_FAMILY, NFPROTO_IPV4);
                push_attr_u32(buf, NFTA_NAT_REG_ADDR_MIN, NFT_REG_1);
                push_attr_u32(buf, NFTA_NAT_REG_ADDR_MAX, NFT_REG_1);
                push_attr_u32(buf, NFTA_NAT_FLAGS, 0);
            });
        }
        Target::TcpMss { mss } => {
            // nftables "tcp option maxseg size set <mss>" expression (best-effort).
            append_expr(exprs, "tcp option", |buf| {
                push_attr_u8(buf, NFTA_TCP_OPTION_KIND, TCP_OPT_MSS);
                push_attr_u8(buf, NFTA_TCP_OPTION_LENGTH, 4);
                push_attr_bytes(buf, NFTA_TCP_OPTION_DATA, &mss.to_be_bytes());
            });
        }
    }
    Ok(())
}

fn append_meta_cmp(exprs: &mut Vec<u8>, key: u32, data: &[u8]) {
    append_expr(exprs, "meta", |buf| {
        push_attr_u32(buf, NFTA_META_DREG, NFT_REG_1);
        push_attr_u32(buf, NFTA_META_KEY, key);
    });
    append_expr(exprs, "cmp", |buf| {
        push_attr_u32(buf, NFTA_CMP_SREG, NFT_REG_1);
        push_attr_u32(buf, NFTA_CMP_OP, NFT_CMP_EQ);
        push_attr_nested(buf, NFTA_CMP_DATA, |cmp| {
            push_attr_bytes(cmp, NFTA_DATA_VALUE, data);
        });
    });
}

fn append_payload_cmp(exprs: &mut Vec<u8>, base: u32, offset: u32, data: &[u8]) {
    append_expr(exprs, "payload", |buf| {
        push_attr_u32(buf, NFTA_PAYLOAD_DREG, NFT_REG_1);
        push_attr_u32(buf, NFTA_PAYLOAD_BASE, base);
        push_attr_u32(buf, NFTA_PAYLOAD_OFFSET, offset);
        push_attr_u32(buf, NFTA_PAYLOAD_LEN, data.len() as u32);
    });
    append_expr(exprs, "cmp", |buf| {
        push_attr_u32(buf, NFTA_CMP_SREG, NFT_REG_1);
        push_attr_u32(buf, NFTA_CMP_OP, NFT_CMP_EQ);
        push_attr_nested(buf, NFTA_CMP_DATA, |cmp| {
            push_attr_bytes(cmp, NFTA_DATA_VALUE, data);
        });
    });
}

fn append_ct_state(exprs: &mut Vec<u8>, mask: u32) {
    append_expr(exprs, "ct", |buf| {
        push_attr_u32(buf, NFTA_CT_DREG, NFT_REG_1);
        push_attr_u32(buf, NFTA_CT_KEY, NFT_CT_STATE);
    });
    append_expr(exprs, "bitwise", |buf| {
        push_attr_u32(buf, NFTA_BITWISE_SREG, NFT_REG_1);
        push_attr_u32(buf, NFTA_BITWISE_DREG, NFT_REG_1);
        push_attr_u32(buf, NFTA_BITWISE_LEN, 4);
        push_attr_bytes(buf, NFTA_BITWISE_MASK, &mask.to_ne_bytes());
        push_attr_bytes(buf, NFTA_BITWISE_XOR, &[0u8; 4]);
    });
    append_expr(exprs, "cmp", |buf| {
        push_attr_u32(buf, NFTA_CMP_SREG, NFT_REG_1);
        push_attr_u32(buf, NFTA_CMP_OP, NFT_CMP_NEQ);
        push_attr_nested(buf, NFTA_CMP_DATA, |cmp| {
            push_attr_bytes(cmp, NFTA_DATA_VALUE, &[0u8; 4]);
        });
    });
}

fn append_immediate_data(exprs: &mut Vec<u8>, reg: u32, data: &[u8]) {
    append_expr(exprs, "immediate", |buf| {
        push_attr_u32(buf, NFTA_IMMEDIATE_DREG, reg);
        push_attr_nested(buf, NFTA_IMMEDIATE_DATA, |imm| {
            push_attr_bytes(imm, NFTA_DATA_VALUE, data);
        });
    });
}

fn append_verdict(exprs: &mut Vec<u8>, verdict: u32) {
    append_expr(exprs, "immediate", |buf| {
        push_attr_u32(buf, NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
        push_attr_nested(buf, NFTA_IMMEDIATE_DATA, |imm| {
            push_attr_nested(imm, NFTA_DATA_VERDICT, |verdict_data| {
                push_attr_u32(verdict_data, NFTA_VERDICT_CODE, verdict);
            });
        });
    });
}

fn append_log_expr(
    exprs: &mut Vec<u8>,
    prefix: &str,
    level: Option<u32>,
) -> Result<(), IptablesError> {
    let prefix_bytes = build_log_prefix(prefix);
    append_expr(exprs, "log", |buf| {
        push_attr_bytes(buf, NFTA_LOG_PREFIX, &prefix_bytes);
        if let Some(level) = level {
            push_attr_u32(buf, NFTA_LOG_LEVEL, level);
        }
    });
    Ok(())
}

fn append_expr(exprs: &mut Vec<u8>, name: &str, build: impl FnOnce(&mut Vec<u8>)) {
    push_attr_nested(exprs, NFTA_LIST_ELEM, |elem| {
        let mut name_bytes = Vec::with_capacity(name.len() + 1);
        name_bytes.extend_from_slice(name.as_bytes());
        name_bytes.push(0);
        push_attr_bytes(elem, NFTA_EXPR_NAME, &name_bytes);
        push_attr_nested(elem, NFTA_EXPR_DATA, build);
    });
}

fn build_log_prefix(prefix: &str) -> Vec<u8> {
    let mut bytes = prefix.as_bytes().to_vec();
    if bytes.len() >= NFT_LOG_PREFIX_MAX {
        bytes.truncate(NFT_LOG_PREFIX_MAX - 1);
        warn!(
            "Log prefix truncated to {} bytes to satisfy nftables limits",
            NFT_LOG_PREFIX_MAX - 1
        );
    }
    bytes.push(0);
    bytes
}

fn rule_userdata(rule: &Rule) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(rule.table.as_str().as_bytes());
    hasher.update(rule.chain.as_str().as_bytes());
    if let Some(proto) = rule.protocol {
        hasher.update(&[proto_number(proto)]);
    }
    if let Some(ref iface) = rule.in_interface {
        hasher.update(iface.as_bytes());
    }
    if let Some(ref iface) = rule.out_interface {
        hasher.update(iface.as_bytes());
    }
    if let Some(src) = rule.source {
        hasher.update(ipv4_bytes(src).unwrap_or_default());
    }
    if let Some(dst) = rule.destination {
        hasher.update(ipv4_bytes(dst).unwrap_or_default());
    }
    if let Some(port) = rule.src_port {
        hasher.update(port.to_be_bytes());
    }
    if let Some(port) = rule.dst_port {
        hasher.update(port.to_be_bytes());
    }
    if let Some(ref state) = rule.state {
        hasher.update(state.as_bytes());
    }

    match &rule.target {
        Target::Accept => hasher.update(b"accept"),
        Target::Drop => hasher.update(b"drop"),
        Target::Reject => hasher.update(b"reject"),
        Target::Masquerade => hasher.update(b"masq"),
        Target::Dnat { to, port } => {
            hasher.update(b"dnat");
            if let Ok(addr) = ipv4_bytes(*to) {
                hasher.update(addr);
            }
            if let Some(port) = port {
                hasher.update(port.to_be_bytes());
            }
        }
        Target::Snat { to } => {
            hasher.update(b"snat");
            if let Ok(addr) = ipv4_bytes(*to) {
                hasher.update(addr);
            }
        }
        Target::TcpMss { mss } => {
            hasher.update(b"tcpmss");
            hasher.update(mss.to_be_bytes());
        }
    }

    let digest = hasher.finalize();
    let mut out = Vec::with_capacity(3 + digest.len());
    out.extend_from_slice(b"rj:");
    out.extend_from_slice(&digest);
    out
}

fn parse_ct_state(state: &str) -> Result<u32, IptablesError> {
    let mut mask = 0u32;
    for token in state.split(',') {
        let token = token.trim().to_uppercase();
        if token.is_empty() {
            continue;
        }
        match token.as_str() {
            "INVALID" => mask |= 1 << 0,
            "ESTABLISHED" => mask |= 1 << 1,
            "NEW" => mask |= 1 << 2,
            "RELATED" => mask |= 1 << 3,
            "UNTRACKED" => mask |= 1 << 4,
            _ => {
                return Err(IptablesError::InvalidArgument(
                    "unsupported conntrack state".to_string(),
                ))
            }
        }
    }
    if mask == 0 {
        return Err(IptablesError::InvalidArgument(
            "empty conntrack state".to_string(),
        ));
    }
    Ok(mask)
}

fn iface_bytes(name: &str) -> Result<[u8; libc::IFNAMSIZ as usize], IptablesError> {
    let mut buf = [0u8; libc::IFNAMSIZ as usize];
    let bytes = name.as_bytes();
    if bytes.len() >= buf.len() {
        return Err(IptablesError::InvalidInterface(name.to_string()));
    }
    buf[..bytes.len()].copy_from_slice(bytes);
    Ok(buf)
}

fn ipv4_bytes(addr: IpAddr) -> Result<[u8; 4], IptablesError> {
    match addr {
        IpAddr::V4(v4) => Ok(v4.octets()),
        IpAddr::V6(_) => Err(IptablesError::InvalidAddress(addr.to_string())),
    }
}

fn proto_number(proto: Protocol) -> u8 {
    match proto {
        Protocol::Tcp => 6,
        Protocol::Udp => 17,
        Protocol::Icmp => 1,
        Protocol::All => 0,
    }
}

fn nft_msg_type(msg: u16) -> u16 {
    (NFNL_SUBSYS_NFTABLES << 8) | msg
}

fn nfgenmsg_payload() -> Vec<u8> {
    vec![libc::AF_INET as u8, NFNETLINK_V0, 0, 0]
}

fn nla_align(len: usize) -> usize {
    (len + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1)
}

fn push_attr_bytes(buf: &mut Vec<u8>, attr_type: u16, data: &[u8]) {
    let len = NLA_HDRLEN + data.len();
    let aligned = nla_align(len);
    buf.extend_from_slice(&(len as u16).to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(data);
    if aligned > len {
        buf.resize(buf.len() + (aligned - len), 0);
    }
}

fn push_attr_nested(buf: &mut Vec<u8>, attr_type: u16, build: impl FnOnce(&mut Vec<u8>)) {
    let start = buf.len();
    buf.extend_from_slice(&[0u8; NLA_HDRLEN]);
    build(buf);
    let len = buf.len() - start;
    let attr_type = attr_type | NLA_F_NESTED;
    let len_bytes = (len as u16).to_ne_bytes();
    buf[start..start + 2].copy_from_slice(&len_bytes);
    buf[start + 2..start + 4].copy_from_slice(&attr_type.to_ne_bytes());
    let aligned = nla_align(len);
    if aligned > len {
        buf.resize(buf.len() + (aligned - len), 0);
    }
}

fn push_attr_string(buf: &mut Vec<u8>, attr_type: u16, value: &str) -> Result<(), IptablesError> {
    let cstr = CString::new(value)
        .map_err(|_| IptablesError::InvalidArgument("invalid string".to_string()))?;
    push_attr_bytes(buf, attr_type, cstr.as_bytes_with_nul());
    Ok(())
}

fn push_attr_u32(buf: &mut Vec<u8>, attr_type: u16, value: u32) {
    push_attr_bytes(buf, attr_type, &value.to_ne_bytes());
}

fn push_attr_i32(buf: &mut Vec<u8>, attr_type: u16, value: i32) {
    push_attr_bytes(buf, attr_type, &value.to_ne_bytes());
}

fn push_attr_u64(buf: &mut Vec<u8>, attr_type: u16, value: u64) {
    push_attr_bytes(buf, attr_type, &value.to_ne_bytes());
}

fn push_attr_u8(buf: &mut Vec<u8>, attr_type: u16, value: u8) {
    push_attr_bytes(buf, attr_type, &[value]);
}

fn build_nlmsg(msg_type: u16, flags: u16, seq: u32, pid: u32, payload: &[u8]) -> Vec<u8> {
    let len = NLMSG_HDRLEN + payload.len();
    let mut buf = Vec::with_capacity(len);
    buf.extend_from_slice(&(len as u32).to_ne_bytes());
    buf.extend_from_slice(&msg_type.to_ne_bytes());
    buf.extend_from_slice(&flags.to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&pid.to_ne_bytes());
    buf.extend_from_slice(payload);
    buf
}

fn parse_nlmsgs(buf: &[u8]) -> Vec<NetlinkMessage> {
    let mut msgs = Vec::new();
    let mut offset = 0usize;
    while offset + NLMSG_HDRLEN <= buf.len() {
        let header = parse_nl_header(&buf[offset..offset + NLMSG_HDRLEN]);
        let msg_len = header.len as usize;
        if msg_len < NLMSG_HDRLEN || offset + msg_len > buf.len() {
            break;
        }
        let payload_start = offset + NLMSG_HDRLEN;
        let payload_end = offset + msg_len;
        let payload = buf[payload_start..payload_end].to_vec();
        msgs.push(NetlinkMessage { header, payload });
        offset += nla_align(msg_len);
    }
    msgs
}

fn parse_nl_header(buf: &[u8]) -> NlHeader {
    let len = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let msg_type = u16::from_ne_bytes([buf[4], buf[5]]);
    let flags = u16::from_ne_bytes([buf[6], buf[7]]);
    let seq = u32::from_ne_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let pid = u32::from_ne_bytes([buf[12], buf[13], buf[14], buf[15]]);
    NlHeader {
        len,
        msg_type,
        _flags: flags,
        seq,
        _pid: pid,
    }
}

fn parse_nlmsg_error(payload: &[u8]) -> io::Result<()> {
    if payload.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short nlmsg error",
        ));
    }
    let err = i32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if err == 0 {
        return Ok(());
    }
    Err(io::Error::from_raw_os_error(-err))
}

struct Attr {
    attr_type: u16,
    payload: Vec<u8>,
}

fn parse_attrs(buf: &[u8]) -> Vec<Attr> {
    let mut attrs = Vec::new();
    let mut offset = 0usize;
    while offset + NLA_HDRLEN <= buf.len() {
        let len = u16::from_ne_bytes([buf[offset], buf[offset + 1]]) as usize;
        let attr_type = u16::from_ne_bytes([buf[offset + 2], buf[offset + 3]])
            & !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);
        if len < NLA_HDRLEN || offset + len > buf.len() {
            break;
        }
        let payload_start = offset + NLA_HDRLEN;
        let payload_end = offset + len;
        attrs.push(Attr {
            attr_type,
            payload: buf[payload_start..payload_end].to_vec(),
        });
        offset += nla_align(len);
    }
    attrs
}

fn parse_u64(buf: &[u8]) -> Option<u64> {
    if buf.len() < 8 {
        return None;
    }
    Some(u64::from_ne_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]))
}

fn parse_string(buf: &[u8]) -> String {
    let trimmed = buf
        .iter()
        .take_while(|b| **b != 0)
        .cloned()
        .collect::<Vec<u8>>();
    String::from_utf8_lossy(&trimmed).to_string()
}

fn to_netlink_error(err: io::Error) -> IptablesError {
    match err.raw_os_error() {
        Some(code) if code == libc::EPERM || code == libc::EACCES => {
            IptablesError::PermissionDenied
        }
        _ => IptablesError::NetlinkError(err.to_string()),
    }
}
