#![feature(ip)]

use structopt::StructOpt;

use anyhow::{anyhow, Context, Result};
use futures_util::TryStreamExt;
use regex::Regex;
use rtnetlink::packet::rtnl;
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

async fn process_ifaces(
    handle: &rtnetlink::Handle,
    ignore_ifaces: &Vec<Regex>,
) -> Result<Vec<strapper::Interface>> {
    let mut ret = Vec::new();
    let mut interfaces = handle.link().get().execute();

    'outer: while let Some(r) = interfaces
        .try_next()
        .await
        .context("error listing interfaces")?
    {
        let mut i_name = None;
        let mut i_perm_mac = None;
        for nla in r.nlas.into_iter() {
            match nla {
                rtnl::link::nlas::Nla::IfName(name) => {
                    if ignore_ifaces.iter().any(|r| r.is_match(&name)) {
                        continue 'outer;
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

        if let Some((name, mac)) = i_name.zip(i_perm_mac) {
            let mut iface = strapper::Interface {
                name,
                mac,
                ipaddr: Vec::new(),
            };
            addresses_for_iface_idx(
                handle,
                r.header.index,
                libc::AF_INET6 as u8,
                &mut iface.ipaddr,
            )
            .await
            .context("failed to list addresses for iface ipv6")?;
            addresses_for_iface_idx(
                handle,
                r.header.index,
                libc::AF_INET as u8,
                &mut iface.ipaddr,
            )
            .await
            .context("failed to list addresses for iface ipv4")?;
            if !iface.ipaddr.is_empty() {
                ret.push(iface)
            }
        }
    }

    Ok(ret)
}

async fn addresses_for_iface_idx(
    handle: &rtnetlink::Handle,
    idx: u32,
    af: u8,
    addr_vec: &mut Vec<String>,
) -> Result<()> {
    let mut message = handle.address().get().set_link_index_filter(idx);
    message.message_mut().header.family = af;
    let mut addrs = message.execute();
    let a = match addrs.try_next().await.context("address lookup failed")? {
        Some(a) => a,
        None => return Ok(()),
    };
    for nla in a.nlas.into_iter() {
        if let rtnl::address::nlas::Nla::Address(addr) = nla {
            addr_vec.push(if addr.len() == 16 {
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
            });
        } else {
        }
    }
    Ok(())
}

async fn advertise(
    endpoint: tonic::transport::Uri,
    advertisement: strapper::NodeAdvertisement,
) -> Result<()> {
    let mut client = NodeStateServiceClient::connect(endpoint).await?;
    client.advertise(advertisement.clone()).await?;
    Ok(())
}

async fn run_advertise(opt: &Opt) -> Result<()> {
    let (connection, handle, _) = rtnetlink::new_connection()?;

    tokio::spawn(connection);
    let (hostname, ifaces) = tokio::try_join!(
        read_hostname(),
        process_ifaces(&handle, &opt.exclude_ifaces)
    )?;

    println!("{}: {:?}", hostname, ifaces);

    let advertisement = strapper::NodeAdvertisement {
        hostname,
        interfaces: ifaces,
    };
    loop {
        match advertise(opt.endpoint.clone(), advertisement.clone()).await {
            Ok(_) => break,
            Err(e) => {
                println!("advertise failed ({}), trying again in 1min", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            }
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let opt = Opt::from_args();

    let rt = tokio::runtime::Builder::new_current_thread().build()?;

    rt.block_on(run_advertise(&opt))?;

    while !systemd::daemon::notify(false, [(systemd::daemon::STATE_READY, "1")].iter())? {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // If the process is running for 20 years, that's just straight up insane.
    // If this returns early, assume something else woke it up.
    std::thread::sleep(std::time::Duration::from_secs(60 * 60 * 24 * 365 * 20));

    Ok(())
}
