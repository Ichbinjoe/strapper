use structopt::StructOpt;

use anyhow::{ensure, Result};
use itertools::Itertools;
use log::{debug, error, info};
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use tonic::transport::Server;

use proto::strapper::{
    self,
    node_state_service_server::{NodeStateService, NodeStateServiceServer},
};

#[derive(StructOpt)]
struct Opt {
    #[structopt(default_value = "[::]:55555", long, short)]
    bind: SocketAddr,

    #[structopt(default_value = "http://localhost:8080", long, short)]
    pdns_endpoint: String,

    #[structopt(default_value = "localhost", long)]
    pdns_server: String,

    #[structopt(long)]
    pdns_api_key: Option<String>,

    #[structopt(long, short)]
    remappers: Vec<Remapper>,
}

#[derive(Serialize)]
struct PdnsRecord {
    content: String,
    disabled: bool,
}

#[derive(Serialize)]
struct PdnsRrsetUpdate {
    name: String,
    #[serde(rename = "type")]
    type_: &'static str,
    ttl: u32,
    changetype: &'static str,
    records: Vec<PdnsRecord>,
    comments: Vec<String>,
}

#[derive(Serialize)]
struct PdnsPartialZoneRrsetPatch {
    rrsets: Vec<PdnsRrsetUpdate>,
}

struct PdnsApi {
    client: reqwest::Client,
    endpoint: String,
    server: String,
    key: Option<String>,
}

impl PdnsApi {
    fn build_zone_update_request(
        &self,
        zone: &str,
        update: PdnsRrsetUpdate,
    ) -> reqwest::RequestBuilder {
        let url = format!(
            "{}/api/v1/servers/{}/zones/{}",
            self.endpoint, self.server, zone
        );
        let mut req = self.client.patch(&url);
        if let Some(k) = &self.key {
            req = req.header("X-API-Key", k);
        }

        let partial_patch = PdnsPartialZoneRrsetPatch {
            rrsets: vec![update],
        };

        debug!("update: {}", serde_json::to_string(&partial_patch).unwrap());

        req.json(&partial_patch)
    }
}

struct Remapper {
    net: ipnet::IpNet,
    zone: String,
    entry_fmt: String,
}

impl FromStr for Remapper {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split("@").collect();
        ensure!(
            parts.len() == 3,
            "invalid number of parts (should be 3 split by @)"
        );

        Ok(Remapper {
            net: ipnet::IpNet::from_str(parts[0])?,
            zone: parts[1].to_owned(),
            entry_fmt: parts[2].to_owned(),
        })
    }
}

struct NSServer {
    pdns: PdnsApi,
    remappers: Vec<Remapper>,
}

#[tonic::async_trait]
impl NodeStateService for NSServer {
    async fn advertise(
        &self,
        request: tonic::Request<strapper::NodeAdvertisement>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        println!("Received {:?}", request.get_ref());

        let jobs: Vec<tokio::task::JoinHandle<_>> = request
            .get_ref()
            .interfaces
            .iter()
            .flat_map(|iface| iface.ipaddr.iter())
            .filter_map(|a| IpAddr::from_str(a).ok())
            .cartesian_product(&self.remappers)
            .filter(|(a, remapper)| remapper.net.contains(a))
            .map(|(a, remapper)| {
                let zone = &remapper.zone;
                let name = remapper
                    .entry_fmt
                    .replace("{}", &request.get_ref().hostname);
                let rrsetupdate = PdnsRrsetUpdate {
                    name,
                    type_: if a.is_ipv4() { "A" } else { "AAAA" },
                    ttl: 3600,
                    changetype: "REPLACE",
                    records: vec![PdnsRecord {
                        content: a.to_string(),
                        disabled: false,
                    }],
                    comments: vec![],
                };
                let request = self.pdns.build_zone_update_request(&zone, rrsetupdate);
                debug!("Sending request to pdns: {:?}", request);
                tokio::spawn(request.send())
            })
            .collect();

        for result in futures::future::join_all(jobs).await {
            let r = result
                .map_err(|j| {
                    error!("request unexpectedly cancel/panic'd: {:?}", j);
                    tonic::Status::unavailable("pdns request cancelled/paniced")
                })
                .and_then(|result| {
                    result.map_err(|e| {
                        error!("request failed: {:?}", e);
                        tonic::Status::unavailable("pdns request failed")
                    })
                })?;
            if r.status() != reqwest::StatusCode::NO_CONTENT {
                error!(
                    "unexpected result: {} - {:?}",
                    r.status(),
                    r.text().await.ok()
                );
                return Err(tonic::Status::unavailable("invalid pdns response"));
            }
        }

        Ok(tonic::Response::new(()))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let opt = Opt::from_args();

    let nssserver = NSServer {
        pdns: PdnsApi {
            client: reqwest::Client::new(),
            endpoint: opt.pdns_endpoint,
            server: opt.pdns_server,
            key: opt.pdns_api_key,
        },
        remappers: opt.remappers,
    };

    info!("service node state service on {}", opt.bind);

    Server::builder()
        .add_service(NodeStateServiceServer::new(nssserver))
        .serve(opt.bind)
        .await?;

    Ok(())
}
