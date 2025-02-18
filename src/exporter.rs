use crate::softether_reader::SoftEtherReader;
use anyhow::Error;
use std::collections::HashSet;
use std::sync::Mutex;
use hyper::header::ContentType;
use hyper::mime::{Mime, SubLevel, TopLevel};
use hyper::server::{Request, Response, Server};
use hyper::uri::RequestUri;
use lazy_static::lazy_static;
use std::time::Instant;
use prometheus;
use prometheus::{register_gauge_vec, Encoder, GaugeVec, TextEncoder};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use toml;

lazy_static! {
    static ref UP: GaugeVec =
        register_gauge_vec!("softether_up", "The last query is successful.", &["hub"]).unwrap();
    static ref ONLINE: GaugeVec =
        register_gauge_vec!("softether_online", "Hub online.", &["hub"]).unwrap();
    static ref SESSIONS: GaugeVec =
        register_gauge_vec!("softether_sessions", "Number of sessions.", &["hub"]).unwrap();
    static ref SESSIONS_CLIENT: GaugeVec = register_gauge_vec!(
        "softether_sessions_client",
        "Number of client sessions.",
        &["hub"]
    )
    .unwrap();
    static ref SESSIONS_BRIDGE: GaugeVec = register_gauge_vec!(
        "softether_sessions_bridge",
        "Number of bridge sessions.",
        &["hub"]
    )
    .unwrap();
    static ref USERS: GaugeVec =
        register_gauge_vec!("softether_users", "Number of users.", &["hub"]).unwrap();
    static ref GROUPS: GaugeVec =
        register_gauge_vec!("softether_groups", "Number of groups.", &["hub"]).unwrap();
    static ref MAC_TABLES: GaugeVec = register_gauge_vec!(
        "softether_mac_tables",
        "Number of entries in MAC table.",
        &["hub"]
    )
    .unwrap();
    static ref IP_TABLES: GaugeVec = register_gauge_vec!(
        "softether_ip_tables",
        "Number of entries in IP table.",
        &["hub"]
    )
    .unwrap();
    static ref LOGINS: GaugeVec =
        register_gauge_vec!("softether_logins", "Number of logins.", &["hub"]).unwrap();
    static ref OUTGOING_UNICAST_PACKETS: GaugeVec = register_gauge_vec!(
        "softether_outgoing_unicast_packets",
        "Outgoing unicast transfer in packets.",
        &["hub"]
    )
    .unwrap();
    static ref OUTGOING_UNICAST_BYTES: GaugeVec = register_gauge_vec!(
        "softether_outgoing_unicast_bytes",
        "Outgoing unicast transfer in bytes.",
        &["hub"]
    )
    .unwrap();
    static ref OUTGOING_BROADCAST_PACKETS: GaugeVec = register_gauge_vec!(
        "softether_outgoing_broadcast_packets",
        "Outgoing broadcast transfer in packets.",
        &["hub"]
    )
    .unwrap();
    static ref OUTGOING_BROADCAST_BYTES: GaugeVec = register_gauge_vec!(
        "softether_outgoing_broadcast_bytes",
        "Outgoing broadcast transfer in bytes.",
        &["hub"]
    )
    .unwrap();
    static ref INCOMING_UNICAST_PACKETS: GaugeVec = register_gauge_vec!(
        "softether_incoming_unicast_packets",
        "Incoming unicast transfer in packets.",
        &["hub"]
    )
    .unwrap();
    static ref INCOMING_UNICAST_BYTES: GaugeVec = register_gauge_vec!(
        "softether_incoming_unicast_bytes",
        "Incoming unicast transfer in bytes.",
        &["hub"]
    )
    .unwrap();
    static ref INCOMING_BROADCAST_PACKETS: GaugeVec = register_gauge_vec!(
        "softether_incoming_broadcast_packets",
        "Incoming broadcast transfer in packets.",
        &["hub"]
    )
    .unwrap();
    static ref INCOMING_BROADCAST_BYTES: GaugeVec = register_gauge_vec!(
        "softether_incoming_broadcast_bytes",
        "Incoming broadcast transfer in bytes.",
        &["hub"]
    )
    .unwrap();
    static ref BUILD_INFO: GaugeVec = register_gauge_vec!(
        "softether_build_info",
        "A metric with a constant '1' value labeled by version, revision and rustversion",
        &["version", "revision", "rustversion"]
    )
    .unwrap();
    static ref USER_TRANSFER_BYTES: GaugeVec = register_gauge_vec!(
        "softether_user_transfer_bytes",
        "User transfer in bytes.",
        &["hub", "user"]
    )
    .unwrap();
    static ref USER_TRANSFER_PACKETS: GaugeVec = register_gauge_vec!(
        "softether_user_transfer_packets",
        "User transfer in packets.",
        &["hub", "user"]
    )
    .unwrap();

    static ref USER_DURATION_SECONDS: GaugeVec = register_gauge_vec!(
        "softether_user_duration_seconds",
        "Duration in seconds since the first session appearance.",    
        &["hub", "user", "source_ip" ]
    )
    .unwrap();
    static ref LABEL_COMBINATIONS: Mutex<HashSet<Vec<String>>> = Mutex::new(HashSet::<Vec<String>>::new());
    static ref USER_SESSION_TIMESTAMPS: Mutex<HashMap<Vec<String>, Instant>> = Mutex::new(HashMap::new());

}

static LANDING_PAGE: &'static str = "<html>
<head><title>SoftEther Exporter</title></head>
<body>
<h1>SoftEther Exporter</h1>
<p><a href=\"/metrics\">Metrics</a></p>
</body>
";

static VERSION: &'static str = env!("CARGO_PKG_VERSION");
static GIT_REVISION: Option<&'static str> = option_env!("GIT_REVISION");
static RUST_VERSION: Option<&'static str> = option_env!("RUST_VERSION");

#[derive(Debug, Deserialize)]
pub struct Config {
    vpncmd: Option<String>,
    server: Option<String>,
    hubs: Vec<Hub>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Hub {
    name: Option<String>,
    password: Option<String>,
}

impl Config {
    pub fn from_file(file: &Path) -> Result<Config, Error> {
        let mut f = File::open(file)?;
        let mut s = String::new();
        let _ = f.read_to_string(&mut s);
        let config: Config = toml::from_str(&s)?;
        Ok(config)
    }
}

pub struct Exporter;

impl Exporter {
    pub fn start(config: Config, listen_address: &str, _verbose: bool) -> Result<(), Error> {
        let encoder = TextEncoder::new();
        let vpncmd = config.vpncmd.unwrap_or(String::from("vpncmd"));
        let server = config.server.unwrap_or(String::from("localhost"));
        let hubs = config.hubs;

        let addr = if listen_address.starts_with(":") {
            format!("0.0.0.0{}", listen_address)
        } else {
            String::from(listen_address)
        };

        println!("Server started: {}", addr);

        Server::http(addr)?.handle(move |req: Request, mut res: Response| {
            if req.uri == RequestUri::AbsolutePath("/metrics".to_string()) {
                for hub in hubs.clone() {
                    let name = hub.name.unwrap_or(String::from(""));
                    let password = hub.password.unwrap_or(String::from(""));
                    let status =
                        match SoftEtherReader::hub_status(&vpncmd, &server, &name, &password) {
                            Ok(x) => x,
                            Err(x) => {
                                UP.with_label_values(&[&name]).set(0.0);
                                println!("Hub status read failed: {}", x);
                                continue;
                            }
                        };

                    let sessions =
                        match SoftEtherReader::hub_sessions(&vpncmd, &server, &name, &password) {
                            Ok(x) => x,
                            Err(x) => {
                                UP.with_label_values(&[&name]).set(0.0);
                                println!("Hub sessions read failed: {}", x);
                                continue;
                            }
                        };

                    let mut current_session_keys: std::collections::HashSet<Vec<String>> = std::collections::HashSet::new();

                    UP.with_label_values(&[&status.name]).set(1.0);
                    ONLINE
                        .with_label_values(&[&status.name])
                        .set(if status.online { 1.0 } else { 0.0 });
                    SESSIONS
                        .with_label_values(&[&status.name])
                        .set(status.sessions);
                    SESSIONS_CLIENT
                        .with_label_values(&[&status.name])
                        .set(status.sessions_client);
                    SESSIONS_BRIDGE
                        .with_label_values(&[&status.name])
                        .set(status.sessions_bridge);
                    USERS.with_label_values(&[&status.name]).set(status.users);
                    GROUPS.with_label_values(&[&status.name]).set(status.groups);
                    MAC_TABLES
                        .with_label_values(&[&status.name])
                        .set(status.mac_tables);
                    IP_TABLES
                        .with_label_values(&[&status.name])
                        .set(status.ip_tables);
                    LOGINS.with_label_values(&[&status.name]).set(status.logins);
                    OUTGOING_UNICAST_PACKETS
                        .with_label_values(&[&status.name])
                        .set(status.outgoing_unicast_packets);
                    OUTGOING_UNICAST_BYTES
                        .with_label_values(&[&status.name])
                        .set(status.outgoing_unicast_bytes);
                    OUTGOING_BROADCAST_PACKETS
                        .with_label_values(&[&status.name])
                        .set(status.outgoing_broadcast_packets);
                    OUTGOING_BROADCAST_BYTES
                        .with_label_values(&[&status.name])
                        .set(status.outgoing_broadcast_bytes);
                    INCOMING_UNICAST_PACKETS
                        .with_label_values(&[&status.name])
                        .set(status.incoming_unicast_packets);
                    INCOMING_UNICAST_BYTES
                        .with_label_values(&[&status.name])
                        .set(status.incoming_unicast_bytes);
                    INCOMING_BROADCAST_PACKETS
                        .with_label_values(&[&status.name])
                        .set(status.incoming_broadcast_packets);
                    INCOMING_BROADCAST_BYTES
                        .with_label_values(&[&status.name])
                        .set(status.incoming_broadcast_bytes);

                    let mut transfer_bytes = HashMap::new();
                    let mut transfer_packets = HashMap::new();


                    {
                        let set = LABEL_COMBINATIONS.lock().unwrap();
                        for labels in set.iter() {
                            let label_values: Vec<&str> = labels.iter().map(|s| s.as_str()).collect();

                            match USER_TRANSFER_BYTES.get_metric_with_label_values(&label_values) {
                                Ok(metric) => {
                                    metric.set(0.0);
                                }
                                Err(e) => {
                                    eprintln!("Fehler beim Abrufen der Metrik für Labels {:?}: {:?}", label_values, e);
                                }
                            }
                        }
                    }
                    for session in sessions {

                        {
                            let labels = vec![status.name.clone(), session.user.clone()];
                            let mut set = LABEL_COMBINATIONS.lock().unwrap();
                            set.insert(labels);
                        }

                        // Erstelle den Schlüssel mit hub, user und source (source entspricht dem Label "source_ip")
                        let key = vec![
                            status.name.clone(),
                            session.user.clone(),
                            session.source.clone(), // <-- Hier wird session.source vorausgesetzt
                        ];
                        current_session_keys.insert(key.clone());


                        let now = Instant::now();
                        {
                            let mut timestamps = USER_SESSION_TIMESTAMPS.lock().unwrap();
                            // Falls diese Kombination noch nicht existiert, speichern wir jetzt den Zeitpunkt
                            timestamps.entry(key.clone()).or_insert(now);
                            // Berechne die verstrichene Zeit in Sekunden seit dem ersten Auftreten
                            let first_seen = timestamps.get(&key).unwrap();
                            let duration_seconds = now.duration_since(*first_seen).as_secs() as f64;
                            USER_DURATION_SECONDS
                                .with_label_values(&[&status.name, &session.user, &session.source])
                                .set(duration_seconds);
                        }

                        if let Some(val) = transfer_bytes.get(&session.user) {
                            let val = val + session.transfer_bytes;
                            transfer_bytes.insert(session.user.clone(), val);
                           

                        } else {
                            let val = session.transfer_bytes;
                            transfer_bytes.insert(session.user.clone(), val);
                        }
                        if let Some(val) = transfer_packets.get(&session.user) {
                            let val = val + session.transfer_packets;
                            transfer_packets.insert(session.user.clone(), val);
                        } else {
                            let val = session.transfer_packets;
                            transfer_packets.insert(session.user.clone(), val);
                        }
                    }
                    for (user, bytes) in &transfer_bytes {
                        USER_TRANSFER_BYTES
                            .with_label_values(&[&status.name, user])
                            .set(*bytes);
                    }
                    for (user, packets) in &transfer_packets {
                        USER_TRANSFER_PACKETS
                            .with_label_values(&[&status.name, user])
                            .set(*packets);
                    }



                    // Entferne veraltete Einträge:
                    {
                        let mut timestamps = USER_SESSION_TIMESTAMPS.lock().unwrap();
                        // Sammle alle Keys, die nicht mehr in der aktuellen Rückgabe vorhanden sind.
                        let keys_to_remove: Vec<Vec<String>> = timestamps
                            .keys()
                            .cloned()
                            .filter(|key| !current_session_keys.contains(key))
                            .collect();

                        for key in keys_to_remove {
                            match USER_DURATION_SECONDS.remove_label_values(&[&key[0], &key[1], &key[2]]) {
                                Ok(()) => {
                                    println!(
                                        "Removed USER_DURATION_SECONDS gauge for hub: {}, user: {}, source: {}",
                                        key[0], key[1], key[2]
                                    );
                                }
                                Err(e) => {
                                    eprintln!("Removed USER_DURATION_SECONDS  error for hub: {}, user: {}, source: {}:  {:?}",  key[0], key[1], key[2], e);
                                }
                            }
                            // Entferne den Eintrag aus der globalen Zeitstempel-Map
                            timestamps.remove(&key);
                        }
                    }




                }

              

              

                let git_revision = GIT_REVISION.unwrap_or("");
                let rust_version = RUST_VERSION.unwrap_or("");
                BUILD_INFO
                    .with_label_values(&[&VERSION, &git_revision, &rust_version])
                    .set(1.0);

                let metric_familys = prometheus::gather();
                let mut buffer = vec![];
                encoder.encode(&metric_familys, &mut buffer).unwrap();
                res.headers_mut()
                    .set(ContentType(encoder.format_type().parse::<Mime>().unwrap()));
                res.send(&buffer).unwrap();
            } else {
                res.headers_mut()
                    .set(ContentType(Mime(TopLevel::Text, SubLevel::Html, vec![])));
                res.send(LANDING_PAGE.as_bytes()).unwrap();
            }
        })?;

        Ok(())
    }
}
