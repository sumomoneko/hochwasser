use std::collections::HashMap;
use std::collections::HashSet;
use std::os::unix::prelude::AsRawFd;
use std::process;

use anyhow::{bail, Result};

use bytes::BytesMut;
use itertools::Itertools;
use log::log_enabled;
use raw_socket::tokio::RawSocket;

use log::{debug, error};
use structopt::clap;
use structopt::StructOpt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

#[derive(Debug, PartialEq)]
struct Ifs(Vec<String>);

impl std::str::FromStr for Ifs {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s
            .split(",")
            .map(|x| x.trim().to_owned())
            .collect::<Vec<_>>();
        if s.len() < 2 {
            bail!("parse error")
        } else {
            Ok(Ifs(s))
        }
    }
}

#[derive(Debug, StructOpt)]
#[structopt(long_version(option_env!("LONG_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))))]
#[structopt(setting(clap::AppSettings::ColoredHelp))]
pub struct Opt {
    /// Flooding Group of Interfaces. ex. "veth0,veth1 veth1,veth2,veth3"
    #[structopt(name = "comma_separated_interfaces", required = true)]
    interfaces: Vec<Ifs>,
}

#[tokio::main]
async fn main() {
    env_logger::init();
    debug!("hallo");
    let opt = Opt::from_args();
    if let Err(e) = run(opt).await {
        error!("Application error: {:?}", e);
        process::exit(1);
    }
}

async fn run(opt: Opt) -> Result<()> {
    let (tx, mut rx) = mpsc::channel(32);

    debug!("interfaces: {:?}", opt.interfaces);

    let mut output_groups = HashMap::new();
    {
        // "tun0,tun1,tun2" "tun2,tun3" -> [{0,1,2}, {2,3}]
        let if_groups: Vec<_> = opt
            .interfaces
            .into_iter()
            .map::<Result<HashSet<_>>, _>(|ifs| {
                let t = ifs
                    .0
                    .into_iter()
                    .map(|ifname| nix::net::if_::if_nametoindex(&ifname[..]))
                    .try_collect()?;
                Ok(t)
            })
            .try_collect()?;

        // [{0,1,2}, {2,3}] -> { 0: {1,2};  1: {0,2}; 2: {0,1,3}; 3:{2,} }
        if_groups.into_iter().for_each(|group_members| {
            group_members.iter().for_each(|i| {
                group_members.iter().for_each(|j| {
                    if *i != *j {
                        output_groups.entry(*i).or_insert(HashSet::new()).insert(*j);
                    }
                })
            });
        });
    }

    // {0: write_handle0, 1: write_handle1, ...}
    let mut writers = HashMap::new();
    // for lifetime keeping.
    let mut reader_handle = Vec::new();

    output_groups
        .keys()
        .cloned()
        .map::<Result<()>, _>(|in_idx| {
            let sock = RawSocket::new(
                raw_socket::Domain::from(libc::PF_PACKET),
                raw_socket::Type::raw(),
                Some(raw_socket::Protocol::from(
                    (libc::ETH_P_ALL as u16).to_be() as libc::c_int
                )),
            )?;

            // https://github.com/yhoazk/LF331_V2/blob/e1b908f596a44c8366ef3cb0a51041dbe55d5131/network/bpf/ptp_802.15/lib_ptp/ptp_cap.cpp#L66
            let la = nix::sys::socket::LinkAddr(libc::sockaddr_ll {
                sll_family: libc::AF_PACKET as u16,
                sll_protocol: (libc::ETH_P_ALL as u16).to_be(),
                sll_ifindex: in_idx as libc::c_int,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 0,
                sll_addr: [0, 0, 0, 0, 0, 0, 0, 0],
            });

            let sa = nix::sys::socket::SockAddr::Link(la);

            let fd = sock.as_raw_fd();
            nix::sys::socket::bind(fd, &sa)?;

            let (mut read_handle, write_handle) = tokio::io::split(sock);
            writers.insert(in_idx, write_handle);

            let tx_cloned = tx.clone();
            let join_handle = tokio::spawn(async move {
                loop {
                    let mut buf = BytesMut::with_capacity(1500);
                    read_handle.read_buf(&mut buf).await.unwrap();
                    if log_enabled!(log::Level::Debug) {
                        let interfaces = nix::net::if_::if_nameindex().unwrap();
                        let if_name = interfaces
                            .iter()
                            .find(|i| i.index() == in_idx)
                            .unwrap()
                            .name();
                        debug!("read from {:?}; {:X?}", if_name, &buf[..]);
                    }
                    tx_cloned.send((in_idx, buf)).await.unwrap();
                }
            });
            reader_handle.push(join_handle);

            Ok(())
        })
        .try_collect()?;

    loop {
        while let Some((in_idx, mut buf)) = rx.recv().await {
            for out_idx in output_groups.get(&in_idx).unwrap().iter() {
                if log_enabled!(log::Level::Debug) {
                    let interfaces = nix::net::if_::if_nameindex().unwrap();
                    let in_if_name = interfaces
                        .iter()
                        .find(|i| i.index() == in_idx)
                        .unwrap()
                        .name();
                    let out_if_name = interfaces
                        .iter()
                        .find(|i| i.index() == *out_idx)
                        .unwrap()
                        .name();
                    debug!(
                        "write from:{:?} to {:?}; {:X?}",
                        in_if_name,
                        out_if_name,
                        &buf[..]
                    );
                }

                if let Err(e) = writers.get_mut(out_idx).unwrap().write(&mut buf).await {
                    error!("write failed: idx:{}; {:X?}", out_idx, e);
                }
            }
        }
    }
}
