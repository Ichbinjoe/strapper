#![feature(ip)]

use structopt::StructOpt;

use anyhow::{anyhow, Context, Result};
use futures_util::TryStreamExt;
use regex::Regex;
use rtnetlink::packet::rtnl;
use std::convert::TryInto;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use sha2::{Sha256, Digest};

use proto::strapper::{self, node_state_service_client::NodeStateServiceClient};

#[derive(StructOpt)]
struct Opt {
    #[structopt(default_value = "http://leader.infra.ibj.io:55555", long, short)]
    endpoint: tonic::transport::Uri,

    #[structopt(long)]
    exclude_ifaces: Vec<Regex>,
    
    #[structopt(default_value = "/etc/ssh/ssh_host_rsa_key.pub", long, short="rsa")]
    rsa_pub_key: String,

    #[structopt(default_value = "/etc/ssh/ssh_host_dsa_key.pub", long, short="dsa")]
    dsa_pub_key: String,

    #[structopt(default_value = "/etc/ssh/ssh_host_ecdsa_key.pub", long, short="ec")]
    ecdsa_pub_key: String,

    #[structopt(default_value = "/etc/ssh/ssh_host_ed25519_key.pub", long, short="ed")]
    ed25519_pub_key: String,
}

async fn read_hostname() -> Result<String> {
    Ok(tokio::fs::read_to_string("/proc/sys/kernel/hostname")
        .await
        .context("error reading hostname")?
        .trim_end()
        .to_owned())
}

async fn read_ssh_pub_host_key(String key_location) -> Result<String> {
    let public_key = tokio::fs::read_to_string(key_location)
        .await
        .context("error reading pub key")?
        .trim_end()
        .split(" ")
        .nth(1)
        .to_owned()
    //TODO: Base64 decode, sha256 fingerprint(get hex)(dump to hex function)(unhex on server and check length of sha hash to be proper), then send that over to the central server
    //TODO: On central server map the algo type -> proper powerdns record type format for sshfp
}

fn match_ssh_pub_entry(keys: &HashMap<String, String>, key_type: str, pub_entry: Result<String>) {
    match pub_entry {
        Ok(pub_key) =>  keys.insert(key_type.to_string(), pub_key),
        Err(e) => println!("Error when reading {}_pub_key: {:?}", key_type, e) 
    }
} 

async fn read_ssh_host_keys(rsa: String, dsa: String, ecdsa: String, ed25519: String) -> Result<HashMap<String, String>> {
    let mut keys = HashMap::new();

    let (rsa_entry, dsa_entry, ecdsa_entry, ed25519_entry) = tokio::join!(
        read_ssh_pub_host_key(rsa),
        read_ssh_pub_host_key(dsa),
        read_ssh_pub_host_key(ecdsa),
        read_ssh_pub_host_key(ed25519)
    )

    match_ssh_pub_entry(keys, "rsa", rsa_entry)
    match_ssh_pub_entry(keys, "dsa", dsa_entry)
    match_ssh_pub_entry(keys, "ecdsa", ecdsa_entry)
    match_ssh_pub_entry(keys, "ed25519", ed25519_entry)

    Ok(keys)
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
                name: name,
                mac: mac,
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

async fn advertise(endpoint: tonic::transport::Uri, advertisement: strapper::NodeAdvertisement) -> Result<()> {
    let mut client = NodeStateServiceClient::connect(endpoint).await?;
    client.advertise(advertisement.clone()).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::from_args();

    let (connection, handle, _) = rtnetlink::new_connection()?;

    tokio::spawn(connection);
    let (hostname, ifaces, keys) = tokio::try_join!(
        read_hostname(),
        process_ifaces(&handle, &opt.exclude_ifaces),
        read_ssh_host_keys(opt.rsa_pub_key, opt.dsa_pub_key, opt.ecdsa_pub_key, opt.ed25519_pub_key)
    )?;

    println!("{}: {:?}", hostname, ifaces);
    println!("Keys: {:?}", keys);

    let advertisement = strapper::NodeAdvertisement {
        hostname,
        interfaces: ifaces,
        pubkeys: keys
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
