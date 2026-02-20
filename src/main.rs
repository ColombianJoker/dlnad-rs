use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

use clap::Parser;
use dns_lookup::lookup_addr;
use gethostname::gethostname;
use local_ip_address::local_ip;
use log::{error, info};
use mp4ameta::Tag;
use uuid::Uuid;

const NUM_THREADS: i32 = 64;
const CONTENT_DIR_XML: &str = include_str!("ContentDir.xml");
const X_MS_MEDIA_RECEIVER_REGISTRAR_XML: &str = include_str!("X_MS_MediaReceiverRegistrar.xml");
const CONNECTION_MGR_XML: &str = include_str!("ConnectionMgr.xml");
const ROOT_DESC_XML: &str = include_str!("rootDesc.xml");
const GET_SORT_CAPABILITIES_RESPONSE_XML: &str = include_str!("get_sort_capabilities_response.xml");
const SSDP_PORT: i32 = 1900;
const DLNA_FEATURES: &str =
    "DLNA.ORG_OP=01;DLNA.ORG_CI=0;DLNA.ORG_FLAGS=01700000000000000000000000000000";

#[derive(Parser, Debug)]
#[command(
        author,
        version = env!("BUILD_VERSION"),
        about = "Gunther: A simple DLNA server for LG WebOS",
        long_about = None,
        help_template = "{bin} {version}\n{author-with-newline}{about-section}\n{usage-heading} {usage}\n\n{all-args}\n{after-help}"
    )]
struct Cli {
    #[arg(short, long, default_value_t = 8200)]
    port: u16,

    #[arg(short = 'i', long = "ip", default_value = "0.0.0.0")]
    ip_address: String,

    #[arg(short = 'd', long = "directory", default_value = ".")]
    directory: String,

    #[arg(short = 'c', long = "cache")]
    cache: bool,

    #[arg(short = 'C', long = "config", env = "DLNAD_CONFIG")]
    config: Option<String>,

    #[arg(short, long)]
    name: Option<String>,

    #[arg(short = 'v', long)]
    verbose: bool,

    #[arg(long, hide = true)]
    debug: bool,
}

fn main() {
    let cli = Cli::parse();

    // Handle logger immediately at start
    let log_level = if cli.verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    env_logger::Builder::new().filter_level(log_level).init();

    // Resolve Config Path: Flag > Env > Default
    let config_path = cli
        .config
        .clone()
        .unwrap_or_else(|| shellexpand::tilde("~/.dlnad").into_owned());
    let path = Path::new(&config_path);

    // Resolve or Generate UUID
    let mut uuid_str = String::new();
    let mut config_lines: Vec<String> = Vec::new();

    if path.exists() {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                if line.starts_with("UUID=") {
                    uuid_str = line
                        .split('=')
                        .nth(1)
                        .unwrap_or("")
                        .trim_matches('"')
                        .trim()
                        .to_string();
                }
                config_lines.push(line.to_string());
            }
        }
    }

    if uuid_str.is_empty() {
        uuid_str = Uuid::new_v4().to_string();
        info!("No persistent UUID found. Generating: {}", uuid_str);
        config_lines.push(format!("UUID=\"{}\"", uuid_str));
        if let Err(e) = fs::write(path, config_lines.join("\n")) {
            error!("Failed to save UUID to {}: {}", config_path, e);
        }
    }

    let server_uuid = uuid_str;
    let usn = format!(
        "uuid:{}::urn:schemas-upnp-org:device:MediaServer:1",
        server_uuid
    );

    // Sharing directory setup
    let shared_dir_raw = if cli.directory == "." {
        std::env::current_dir()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string()
    } else {
        shellexpand::tilde(&cli.directory).into_owned()
    };

    let directory_clone = fs::canonicalize(&shared_dir_raw)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or(shared_dir_raw);

    // Network and Logger Setup
    let server_ip = if cli.ip_address == "0.0.0.0" {
        local_ip()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|_| "127.0.0.1".to_string())
    } else {
        cli.ip_address.clone()
    };

    let server_name = cli.name.unwrap_or_else(|| {
        gethostname()
            .into_string()
            .unwrap_or_else(|_| "Gunther".to_string())
    });

    info!(
        "DLNA server {} (version {}) listening on {}:{}",
        server_name,
        env!("BUILD_VERSION"),
        server_ip,
        cli.port
    );
    if cli.verbose {
        info!("Server UUID: {}", server_uuid);
    }

    info!("Sharing directory: {}", directory_clone);

    // SSDP Multicast Setup
    let ssdp_socket = UdpSocket::bind(format!("0.0.0.0:{}", SSDP_PORT)).unwrap();
    let multicast_addr = "239.255.255.250".parse().unwrap();
    let interface_ip: std::net::Ipv4Addr = server_ip.parse().unwrap();
    ssdp_socket
        .join_multicast_v4(&multicast_addr, &interface_ip)
        .unwrap();

    let mut ssdp_response = Vec::new();
    write!(ssdp_response, "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\nLOCATION: http://{}:{}/rootDesc.xml\r\nSERVER: UPnP/1.0 DLNADOC/1.50 Gunther/{}\r\nST: urn:schemas-upnp-org:device:MediaServer:1\r\nUSN: {}\r\n\r\n",
        server_ip, cli.port, env!("BUILD_VERSION"), usn
    ).unwrap();

    let ssdp_socket_clone = ssdp_socket.try_clone().unwrap();
    thread::spawn(move || {
        let mut buffer = [0; 4096];
        loop {
            if let Ok((_, src_addr)) = ssdp_socket_clone.recv_from(&mut buffer) {
                let _ = ssdp_socket_clone.send_to(&ssdp_response, src_addr);
            }
        }
    });

    // 5. TCP Thread Pool Setup
    let cache: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    let connected_clients: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    let tcp_listener = TcpListener::bind(format!("0.0.0.0:{}", cli.port)).unwrap();
    let (tx, rx) = mpsc::channel();
    let rx = Arc::new(Mutex::new(rx));

    for _ in 0..NUM_THREADS {
        let rx = Arc::clone(&rx);
        let cache = Arc::clone(&cache);
        let clients_clone = Arc::clone(&connected_clients);
        let ip_to_pass = server_ip.clone();
        let port_to_pass = cli.port;
        let dir_for_thread = directory_clone.clone();
        let server_name_clone = server_name.clone();
        let server_uuid_clone = server_uuid.clone();
        let debug_flag = cli.debug;
        let cache_flag = cli.cache;

        thread::spawn(move || {
            loop {
                let stream = rx.lock().unwrap().recv().unwrap();
                handle_client(
                    stream,
                    cache.clone(),
                    Arc::clone(&clients_clone),
                    ip_to_pass.clone(),
                    port_to_pass,
                    dir_for_thread.clone(),
                    server_name_clone.clone(),
                    server_uuid_clone.clone(),
                    debug_flag,
                    cache_flag,
                );
            }
        });
    }

    for tcp_stream in tcp_listener.incoming() {
        if let Ok(stream) = tcp_stream {
            tx.send(stream).unwrap();
        }
    }
}

fn handle_client(
    mut stream: TcpStream,
    cache: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    connected_clients: Arc<Mutex<HashSet<String>>>,
    ip_address: String,
    port: u16,
    directory: String,
    server_name: String,
    server_uuid: String,
    debug: bool,
    cache_enabled: bool,
) {
    if let Ok(addr) = stream.peer_addr() {
        let client_ip_str = addr.ip().to_string();
        let mut clients = connected_clients.lock().unwrap();
        if clients.insert(client_ip_str.clone()) {
            let hostname = lookup_addr(&addr.ip()).unwrap_or_else(|_| client_ip_str.clone());
            info!("New client connected: {} ({})", client_ip_str, hostname);
        }
    }

    let mut buf = vec![0; 8192];
    if let Ok(n) = stream.read(&mut buf) {
        if n > 0 {
            let request = String::from_utf8_lossy(&buf[..n]);
            if debug {
                info!("DEBUG REQUEST:\n{}", request);
            }

            let method = request.split_whitespace().next().unwrap_or("");
            match method {
                "GET" => handle_get_request(
                    stream,
                    &request,
                    ip_address,
                    port,
                    directory,
                    server_name,
                    server_uuid,
                    debug,
                ),
                "POST" => handle_post_request(
                    stream,
                    request.to_string(),
                    cache,
                    ip_address,
                    port,
                    directory,
                    server_name,
                    debug,
                    cache_enabled,
                ),
                "SUBSCRIBE" => handle_subscribe_request(stream, server_uuid, debug),
                "HEAD" => handle_head_request(stream, debug),
                _ => (),
            }
        }
    }
}

fn handle_get_request(
    mut stream: TcpStream,
    http_request: &str,
    ip_address: String,
    port: u16,
    directory: String,
    server_name: String,
    server_uuid: String,
    _debug: bool,
) {
    let path = decode(http_request.split_whitespace().nth(1).unwrap_or("/"));
    let trimmed_path = path.trim_start_matches(['.', '/']);
    let combined_path = format!("{}/{}", directory, path);

    match trimmed_path {
        "rootDesc.xml"
        | "ContentDir.xml"
        | "ConnectionMgr.xml"
        | "X_MS_MediaReceiverRegistrar.xml" => {
            let content = match trimmed_path {
                "rootDesc.xml" => ROOT_DESC_XML
                    .replace(
                        "<friendlyName>Gunther</friendlyName>",
                        &format!("<friendlyName>{}</friendlyName>", server_name),
                    )
                    .replace(
                        "uuid:4d696e69-444c-164e-9d41-b827eb96c6c2",
                        &format!("uuid:{}", server_uuid),
                    ),
                "ContentDir.xml" => CONTENT_DIR_XML.to_string(),
                "ConnectionMgr.xml" => CONNECTION_MGR_XML.to_string(),
                _ => X_MS_MEDIA_RECEIVER_REGISTRAR_XML.to_string(),
            };
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/xml\r\nConnection: close\r\n\r\n",
                content.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(content.as_bytes());
            return;
        }
        _ => (),
    }

    if let Ok(file) = File::open(&combined_path) {
        let file_size = file.metadata().unwrap().len();
        let mut start_range = 0;
        let ext = Path::new(&combined_path)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        let mime_type = match ext.as_str() {
            "vtt" => "text/vtt",
            "srt" => "text/srt",
            "jpg" | "jpeg" => "image/jpeg",
            "png" => "image/png",
            _ => "video/mp4",
        };

        let mut extra_headers = String::new();
        if ext == "vtt" || ext == "srt" {
            let safe_path = encode(path.trim_start_matches('/'));
            extra_headers = format!(
                "CaptionInfo.sec: http://{}:{}/{}\r\nContentFeatures.dlna.org: {}\r\n",
                ip_address,
                port,
                safe_path,
                "DLNA.ORG_PN=SUBTITLE;DLNA.ORG_OP=01;DLNA.ORG_CI=0;DLNA.ORG_FLAGS=01700000000000000000000000000000"
            );
        }

        if let Some(line) = http_request
            .lines()
            .find(|l| l.starts_with("Range: bytes="))
        {
            if let Some(r) = line.strip_prefix("Range: bytes=") {
                start_range = r
                    .split('-')
                    .next()
                    .and_then(|n| n.parse::<u64>().ok())
                    .unwrap_or(0);
            }
        }

        let header = format!(
            "HTTP/1.1 {} Partial Content\r\nContent-Range: bytes {}-{}/{}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\n{}Connection: close\r\n\r\n",
            if start_range > 0 { "206" } else { "200" },
            start_range,
            file_size - 1,
            file_size,
            mime_type,
            file_size - start_range,
            extra_headers
        );

        let _ = stream.write_all(header.as_bytes());
        let mut file = file;
        let _ = file.seek(SeekFrom::Start(start_range));
        let mut buffer = [0; 8192];
        while let Ok(n) = file.read(&mut buffer) {
            if n == 0 || stream.write_all(&buffer[..n]).is_err() {
                break;
            }
        }
    }
}

fn handle_post_request(
    mut stream: TcpStream,
    request: String,
    cache: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    ip_address: String,
    port: u16,
    directory: String,
    server_name: String,
    debug: bool,
    cache_enabled: bool,
) {
    let response_body = if request.contains("#GetSortCapabilities") {
        GET_SORT_CAPABILITIES_RESPONSE_XML.to_string()
    } else {
        let object_id = request
            .find("<ObjectID>")
            .and_then(|start| {
                request[start + 10..]
                    .find("</ObjectID>")
                    .map(|end| &request[start + 10..start + 10 + end])
            })
            .unwrap_or("0");

        if debug {
            info!("DEBUG: Handling POST request for ObjectID: {}", object_id);
        }

        let start_index = request
            .find("<StartingIndex>")
            .and_then(|s| {
                request[s + 15..]
                    .find("</StartingIndex>")
                    .map(|e| request[s + 15..s + 15 + e].parse::<usize>().unwrap_or(0))
            })
            .unwrap_or(0);

        let requested_count = request
            .find("<RequestedCount>")
            .and_then(|s| {
                request[s + 16..]
                    .find("</RequestedCount>")
                    .map(|e| request[s + 16..s + 16 + e].parse::<usize>().unwrap_or(100))
            })
            .unwrap_or(100);

        if cache_enabled {
            let cache_key = format!("{}:{}:{}", object_id, start_index, requested_count);
            let mut cache_lock = cache.lock().unwrap();
            if let Some(cached) = cache_lock.get(&cache_key) {
                String::from_utf8_lossy(cached).to_string()
            } else {
                let resp = if object_id == "0"
                    || Path::new(&format!("{}/{}", directory, decode(object_id))).is_dir()
                {
                    generate_browse_response(
                        object_id,
                        start_index,
                        requested_count,
                        ip_address,
                        port,
                        directory,
                        server_name.clone(),
                    )
                } else {
                    generate_meta_response(object_id, ip_address, port, server_name.clone())
                };
                cache_lock.insert(cache_key, resp.as_bytes().to_vec());
                resp
            }
        } else {
            if object_id == "0"
                || Path::new(&format!("{}/{}", directory, decode(object_id))).is_dir()
            {
                generate_browse_response(
                    object_id,
                    start_index,
                    requested_count,
                    ip_address,
                    port,
                    directory,
                    server_name.clone(),
                )
            } else {
                generate_meta_response(object_id, ip_address, port, server_name.clone())
            }
        }
    };

    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nContent-Length: {}\r\nConnection: close\r\nEXT:\r\nServer: {}/{}\r\n\r\n",
        response_body.len(),
        server_name,
        env!("BUILD_VERSION")
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(response_body.as_bytes());
}

fn handle_subscribe_request(mut stream: TcpStream, server_uuid: String, debug: bool) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nSID: uuid:{}\r\nTIMEOUT: Second-300\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        server_uuid
    );

    if debug {
        info!("DEBUG: SUSCRIBE Response:\n{}", response);
    }
    let _ = stream.write_all(response.as_bytes());
}

fn handle_head_request(mut stream: TcpStream, _debug: bool) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: video/mp4\r\nAccept-Ranges: bytes\r\nContent-Length: 0\r\ncontentFeatures.dlna.org: {}\r\nConnection: close\r\n\r\n",
        DLNA_FEATURES
    );
    let _ = stream.write_all(response.as_bytes());
}

fn generate_browse_response(
    path: &str,
    start_index: usize,
    requested_count: usize,
    ip_address: String,
    port: u16,
    directory: String,
    _server_name: String,
) -> String {
    let mut didl_raw = String::from(
        "<DIDL-Lite xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:upnp=\"urn:schemas-upnp-org:metadata-1-0/upnp/\" xmlns:sec=\"http://www.sec.co.kr/\" xmlns=\"urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/\">",
    );
    let relative_dir = if path == "0" {
        "".to_string()
    } else {
        decode(path)
    };
    let full_path = Path::new(&directory).join(&relative_dir);
    let mut entries = Vec::new();

    if let Ok(dir) = fs::read_dir(full_path) {
        for entry in dir.filter_map(Result::ok) {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            let entry_path = entry.path();
            let ext = entry_path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();
            if entry_path.is_dir() || ["mp4", "mkv", "avi", "mov"].contains(&ext.as_str()) {
                entries.push((name, entry_path.is_dir(), entry_path));
            }
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let total_matches = entries.len();
    let returned = entries
        .iter()
        .skip(start_index)
        .take(if requested_count == 0 {
            total_matches
        } else {
            requested_count
        });

    let mut count = 0;
    for (name, is_dir, entry_path) in returned {
        let child_id = if relative_dir.is_empty() {
            name.clone()
        } else {
            format!("{}/{}", relative_dir, name)
        };
        let encoded_id = encode(&child_id);
        let mut display_title = encode_title_name(name);
        let mut duration_str = String::new();
        let mut subtitle_xml = String::new();
        let mut thumb_xml = String::new();

        if !is_dir {
            if let Ok(tag) = Tag::read_from_path(entry_path) {
                if let Some(t) = tag.title() {
                    display_title = encode_title_name(t);
                }
                duration_str = format!(
                    " duration=\"{}\"",
                    format_duration(tag.duration().as_secs())
                );
            }
            // Subtitle & Thumb logic (dynamic port)
            if let Some(p) = ["srt", "vtt"]
                .iter()
                .map(|e| entry_path.with_extension(e))
                .find(|p| p.exists())
            {
                let sub_url = format!(
                    "http://{}:{}/{}",
                    ip_address,
                    port,
                    encode(&format!(
                        "{}/{}",
                        relative_dir,
                        p.file_name().unwrap().to_string_lossy()
                    ))
                );
                subtitle_xml = format!(
                    "<res protocolInfo=\"http-get:*:{} :*\">{}</res><sec:CaptionInfoEx xmlns:sec=\"http://www.sec.co.kr/\">{}</sec:CaptionInfoEx>",
                    if p.extension().unwrap() == "srt" {
                        "text/srt"
                    } else {
                        "text/vtt"
                    },
                    sub_url,
                    sub_url
                );
            }
            if let Some(p) = ["jpg", "png"]
                .iter()
                .map(|e| entry_path.with_extension(e))
                .find(|p| p.exists())
            {
                let thumb_url = format!(
                    "http://{}:{}/{}",
                    ip_address,
                    port,
                    encode(&format!(
                        "{}/{}",
                        relative_dir,
                        p.file_name().unwrap().to_string_lossy()
                    ))
                );
                thumb_xml = format!(
                    "<upnp:albumArtURI dlna:profileID=\"JPEG_TN\" xmlns:dlna=\"urn:schemas-dlna-org:metadata-1-0/\">{}</upnp:albumArtURI>",
                    thumb_url
                );
            }
        }

        if *is_dir {
            didl_raw += &format!(
                "<container id=\"{}\" parentID=\"{}\" restricted=\"1\" searchable=\"1\"><dc:title>{}</dc:title><upnp:class>object.container.storageFolder</upnp:class></container>",
                encoded_id, path, display_title
            );
        } else {
            didl_raw += &format!(
                "<item id=\"{}\" parentID=\"{}\" restricted=\"1\"><dc:title>{}</dc:title>{}<upnp:class>object.item.videoItem</upnp:class><res protocolInfo=\"http-get:*:video/mp4:{}\"{}>http://{}:{}/{}</res>{}</item>",
                encoded_id,
                path,
                display_title,
                thumb_xml,
                DLNA_FEATURES,
                duration_str,
                ip_address,
                port,
                encoded_id,
                subtitle_xml
            );
        }
        count += 1;
    }
    didl_raw += "</DIDL-Lite>";
    let escaped = didl_raw
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&apos;");
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:BrowseResponse xmlns:u=\"urn:schemas-upnp-org:service:ContentDirectory:1\"><Result>{}</Result><NumberReturned>{}</NumberReturned><TotalMatches>{}</TotalMatches><UpdateID>1</UpdateID></u:BrowseResponse></s:Body></s:Envelope>",
        escaped, count, total_matches
    )
}

fn generate_meta_response(
    path: &str,
    ip_address: String,
    port: u16,
    _server_name: String,
) -> String {
    let result_xml = fmt::format(format_args!(
        include_str!("meta_response_result.xml"),
        ip_address, path
    ))
    .replace(":8200/", &format!(":{}/", port))
    .replace(
        "http-get:*:video/mp4:*",
        &format!("http-get:*:video/mp4:{}", DLNA_FEATURES),
    );
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:BrowseResponse xmlns:u=\"urn:schemas-upnp-org:service:ContentDirectory:1\"><Result>{}</Result><NumberReturned>1</NumberReturned><TotalMatches>1</TotalMatches><UpdateID>1</UpdateID></u:BrowseResponse></s:Body></s:Envelope>",
        result_xml
    )
}

fn format_duration(seconds: u64) -> String {
    format!(
        "{:01}:{:02}:{:02}",
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60
    )
}
fn decode(s: &str) -> String {
    s.replace("%20", " ").replace("&amp;", "&")
}
fn encode(s: &str) -> String {
    s.replace(" ", "%20").replace("&", "&amp;")
}
fn encode_title_name(s: &str) -> String {
    s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
}
