#![feature(ip)]

use structopt::StructOpt;

use anyhow::{anyhow, Context, Result};
use futures_util::{StreamExt, TryStreamExt};
use regex::Regex;
use rtnetlink::constants::{RTMGRP_IPV4_IFADDR, RTMGRP_IPV6_IFADDR, RTMGRP_LINK};
use rtnetlink::packet::rtnl;
use rtnetlink::sys::SocketAddr;
use std::convert::TryInto;
use std::net::{Ipv4Addr, Ipv6Addr};

use proto::strapper::{self, node_state_service_client::NodeStateServiceClient};

#[derive(StructOpt)]
struct Opt {
    #[structopt(default_value = "http://leader.infra.ibj.io:55555", long, short)]
    endpoint: tonic::transport::Uri,

    #[structopt(long)]
    exclude_ifaces: Vec<Regex>,
}

async fn read_hostname() -> Result<String> {
    Ok(tokio::fs::read_to_string("/proc/sys/kernel/hostname")
        .await
        .context("error reading hostname")?
        .trim_end()
        .to_owned())
}

fn iface_for<'a>(
    v: &'a mut Vec<strapper::Interface>,
    addr: &rtnl::address::AddressMessage,
) -> Option<&'a mut strapper::Interface> {
    for i in v {
        if i.index == addr.header.index {
            return Some(i);
        }
    }
    None
}

fn add_addr(
    v: &mut Vec<strapper::Interface>,
    addr: &rtnl::address::AddressMessage,
) -> Result<bool> {
    process_addr_message(v, addr, |i, a| {
        for ea in &i.ipaddr {
            if ea == &a {
                return false;
            }
        }

        i.ipaddr.push(a);
        true
    })
}

fn del_addr(
    v: &mut Vec<strapper::Interface>,
    addr: &rtnl::address::AddressMessage,
) -> Result<bool> {
    process_addr_message(v, addr, |i, a| {
        let mut r = false;
        i.ipaddr.retain(|v| if v != &a {
            true
        } else {
            r = true;
            false
        });
        r
    })
}

fn process_addr_message<F>(
    v: &mut Vec<strapper::Interface>,
    addr: &rtnl::address::AddressMessage,
    f: F,
) -> Result<bool>
where
    F: Fn(&mut strapper::Interface, String) -> bool,
{
    let iface = match iface_for(v, addr) {
        Some(v) => v,
        None => return Ok(false),
    };

    let mut changes = false;

    for nla in addr.nlas.iter() {
        if let rtnl::address::nlas::Nla::Address(addr) = nla {
            let addrstr = if addr.len() == 16 {
                let a: [u8; 16] = addr.as_slice().try_into().unwrap();
                let addr = Ipv6Addr::from(a);
                if !addr.is_global() {
                    continue;
                }
                addr.to_string()
            } else if addr.len() == 4 {
                let a: [u8; 4] = addr.as_slice().try_into().unwrap();
                let addr = Ipv4Addr::from(a);
                if !(addr.is_private() || addr.is_global()) {
                    continue;
                }
                addr.to_string()
            } else {
                return Err(anyhow!("non-recognized address format"));
            };

            if f(iface, addrstr) {
                changes = true;
            }
        }
    }

    Ok(changes)
}

fn add_iface_if_not_exists_and_not_excluded(
    v: &mut Vec<strapper::Interface>,
    exclude_ifaces: &Vec<Regex>,
    l: &rtnl::link::LinkMessage,
) -> Result<bool> {
    let mut i_name = None;
    let mut i_perm_mac = None;

    for nla in l.nlas.iter() {
        match nla {
            rtnl::link::nlas::Nla::IfName(name) => {
                for r in exclude_ifaces {
                    if r.is_match(name) {
                        return Ok(false);
                    }
                }

                for iface in v.iter() {
                    if &iface.name == name {
                        return Ok(false);
                    }
                }
                i_name = Some(name);
            }
            rtnl::link::nlas::Nla::Address(addr) => {
                let mac = eui48::MacAddress::from_bytes(&addr)?;
                i_perm_mac = Some(mac.to_hex_string());
            }
            _ => {}
        };
    }

    i_name
        .zip(i_perm_mac)
        .map(|(name, mac)| strapper::Interface {
            name: name.clone(),
            mac,
            ipaddr: Vec::new(),
            index: l.header.index,
        })
        .map(|iface| {
            v.push(iface);
            true
        })
        .ok_or(anyhow!("name or mac is unexpectedly missing"))
}

async fn process_ifaces(
    handle: &rtnetlink::Handle,
    ignore_ifaces: &Vec<Regex>,
) -> Result<Vec<strapper::Interface>> {
    let mut ret = Vec::new();
    let mut interfaces = handle.link().get().execute();

    while let Some(r) = interfaces
        .try_next()
        .await
        .context("error listing interfaces")?
    {
        add_iface_if_not_exists_and_not_excluded(&mut ret, &ignore_ifaces, &r)?;
    }

    list_addresses_for_af(handle, libc::AF_INET6 as u8, &mut ret).await?;
    list_addresses_for_af(handle, libc::AF_INET as u8, &mut ret).await?;

    Ok(ret)
}

async fn list_addresses_for_af(handle: &rtnetlink::Handle, af: u8, r: &mut Vec<strapper::Interface>) -> Result<()> {
    let mut message = handle.address().get();
    message.message_mut().header.family = af;
    let mut addrs = message.execute();
    while let Some(addr) = addrs.try_next().await.context("address lookup failed")? {
        add_addr(r, &addr)?;
    }
    Ok(())
}

async fn advertise(
    endpoint: &tonic::transport::Uri,
    advertisement: &strapper::NodeAdvertisement,
) -> Result<()> {
    let mut client = NodeStateServiceClient::connect(endpoint.clone()).await?;
    client.advertise(advertisement.clone()).await?;
    Ok(())
}

async fn try_advertise(
    endpoint: &tonic::transport::Uri,
    advertisement: &strapper::NodeAdvertisement,
) -> Result<()> {
    for try_cnt in 0..10 {
        match advertise(endpoint, advertisement).await {
            Ok(_) => return Ok(()),
            Err(e) => {
                let next_try = 2_u64.pow(try_cnt);
                println!(
                    "advertise failed ({}, try {}), trying again in {} seconds",
                    e, try_cnt, next_try
                );
                tokio::time::sleep(tokio::time::Duration::from_secs(next_try)).await;
            }
        }
    }

    Err(anyhow!("advertise exceeded tries"))
}

fn advertise_ready() -> Result<()> {
    println!("notifying systemd of 'ready' state...");
    while !systemd::daemon::notify(false, [(systemd::daemon::STATE_READY, "1")].iter())? {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    Ok(())
}

async fn run_advertise(opt: &Opt) -> Result<()> {
    let (mut connection, handle, mut messages) = rtnetlink::new_connection()?;

    let addr = SocketAddr::new(0, RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR);

    connection.socket_mut().bind(&addr)?;

    tokio::spawn(connection);
    let (hostname, ifaces) = tokio::try_join!(
        read_hostname(),
        process_ifaces(&handle, &opt.exclude_ifaces)
    )?;

    println!("{}: {:?}", hostname, ifaces);

    let mut advertisement = strapper::NodeAdvertisement {
        hostname,
        interfaces: ifaces,
    };

    try_advertise(&opt.endpoint, &advertisement).await?;
    advertise_ready()?;

    println!("Waiting for address updates.");

    while let Some((message, _)) = messages.next().await {
        let has_changes = if let rtnetlink::packet::NetlinkPayload::InnerMessage(i) = message.payload {
            match i {
                rtnl::RtnlMessage::NewAddress(addr) => {
                    add_addr(&mut advertisement.interfaces, &addr)
                },
                rtnl::RtnlMessage::DelAddress(addr) => {
                    del_addr(&mut advertisement.interfaces, &addr)
                },
                _ => Ok(false)
            }?
        } else { false };

        if has_changes {
            println!("Advertising address changes: {:?}", advertisement);
            try_advertise(&opt.endpoint, &advertisement).await?;
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let opt = Opt::from_args();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;

    rt.block_on(run_advertise(&opt))?;

    Ok(())
}
