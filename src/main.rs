use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use clap::Parser;
use gethostname::gethostname;
use local_ip_address::local_ip;
use log::{error, info, warn};

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
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long, default_value_t = 8200)]
    port: u16,

    #[arg(short = 'i', long = "ip", default_value = "0.0.0.0")]
    ip_address: String,

    #[arg(short = 'd', long = "directory", default_value = ".")]
    directory: String,

    #[arg(short, long)]
    name: Option<String>,

    #[arg(short = 'v', long)]
    verbose: bool,
}

fn main() {
    let cli = Cli::parse();

    let server_ip = if cli.ip_address == "0.0.0.0" {
        match local_ip() {
            Ok(ip) => {
                let ip_str = ip.to_string();
                info!("Detected primary IP address: {}", ip_str);
                ip_str
            }
            Err(e) => {
                warn!(
                    "Could not detect primary IP ({}), falling back to 127.0.0.1",
                    e
                );
                "127.0.0.1".to_string()
            }
        }
    } else {
        cli.ip_address.clone()
    };

    let log_level = if cli.verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };
    env_logger::Builder::new().filter_level(log_level).init();

    let server_name = match cli.name {
        Some(name) => name,
        None => gethostname()
            .into_string()
            .unwrap_or_else(|_| "Gunther".to_string()),
    };

    let cache: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    let tcp_listener = TcpListener::bind(format!("0.0.0.0:{}", cli.port)).unwrap();
    info!(
        "DLNA server {} listening on {}:{}",
        server_name, server_ip, cli.port
    );

    let ssdp_socket =
        UdpSocket::bind(format!("0.0.0.0:{}", SSDP_PORT)).expect("Could not bind SSDP socket");
    let multicast_addr = "239.255.255.250"
        .parse()
        .expect("Invalid multicast address");
    let interface_ip: std::net::Ipv4Addr = server_ip.parse().expect("Invalid Server IP format");
    ssdp_socket
        .join_multicast_v4(&multicast_addr, &interface_ip)
        .expect("Failed to join multicast group");

    let mut ssdp_response = Vec::new();
    write!(
        ssdp_response,
        "HTTP/1.1 200 OK\r\n\
        CACHE-CONTROL: max-age=1800\r\n\
        EXT:\r\n\
        LOCATION: http://{}:{}/rootDesc.xml\r\n\
        SERVER: DLNA/1.0 DLNADOC/1.50 UPnP/1.0 {}/1.3.0\r\n\
        ST: urn:schemas-upnp-org:device:MediaServer:1\r\n\
        USN: uuid:4d696e69-444c-164e-9d41-b827eb96c6c2::urn:schemas-upnp-org:device:MediaServer:1\r\n\
        \r\n",
        server_ip, cli.port, server_name
    ).unwrap();

    let ssdp_socket_clone = ssdp_socket
        .try_clone()
        .expect("Could not clone SSDP socket");
    thread::spawn(move || {
        let mut buffer = [0; 4096];
        loop {
            match ssdp_socket_clone.recv_from(&mut buffer) {
                Ok((_size, src_addr)) => {
                    let _ = ssdp_socket_clone.send_to(&ssdp_response, src_addr);
                }
                Err(err) => error!("SSDP Error: {:?}", err),
            }
        }
    });

    let (tx, rx) = mpsc::channel();
    let rx = Arc::new(Mutex::new(rx));
    for _ in 0..NUM_THREADS {
        let rx = Arc::clone(&rx);
        let cache = Arc::clone(&cache);
        let ip_to_pass = server_ip.clone();
        let directory_clone = cli.directory.clone();
        let server_name_clone = server_name.clone();

        thread::spawn(move || {
            loop {
                let stream = rx.lock().unwrap().recv().unwrap();
                handle_client(
                    stream,
                    cache.clone(),
                    ip_to_pass.clone(),
                    directory_clone.clone(),
                    server_name_clone.clone(),
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
    ip_address: String,
    directory: String,
    server_name: String,
) {
    let mut buffer = Vec::new();
    let _ = stream.set_read_timeout(Some(Duration::from_millis(5000)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(5000)));

    let mut buf = vec![0; 4096];
    if let Ok(n) = stream.read(&mut buf) {
        if n > 0 {
            buffer.extend_from_slice(&buf[..n]);
            if let Ok(request) = std::str::from_utf8(&buffer) {
                let method = request.split_whitespace().next().unwrap_or("");
                match method {
                    "GET" => {
                        handle_get_request(stream, request, ip_address, directory, server_name)
                    }
                    "HEAD" => handle_head_request(stream),
                    "POST" => handle_post_request(
                        stream,
                        request.to_string(),
                        cache,
                        ip_address,
                        directory,
                        server_name,
                    ),
                    _ => (),
                }
            }
        }
    }
}

fn handle_head_request(mut stream: TcpStream) {
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
        Content-Type: video/mp4\r\n\
        Accept-Ranges: bytes\r\n\
        Content-Length: 0\r\n\
        contentFeatures.dlna.org: {}\r\n\r\n",
        DLNA_FEATURES
    );
    let _ = stream.write_all(response.as_bytes());
}

fn handle_get_request(
    mut stream: TcpStream,
    http_request: &str,
    _ip_address: String,
    directory: String,
    server_name: String,
) {
    let mut parts = http_request.split_whitespace();
    parts.next();
    let path = decode(parts.next().unwrap_or("/"));
    let trimmed_path = path.trim_start_matches(['.', '/']);
    let combined_path = format!("{}/{}", directory, path);

    match trimmed_path {
        "rootDesc.xml" => {
            let content = ROOT_DESC_XML.replace(
                "<friendlyName>Gunther</friendlyName>",
                &format!("<friendlyName>{}</friendlyName>", server_name),
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
                content.len(),
                content
            );
            let _ = stream.write_all(response.as_bytes());
            return;
        }
        "ContentDir.xml" | "ConnectionMgr.xml" | "X_MS_MediaReceiverRegistrar.xml" => {
            let content = match trimmed_path {
                "ContentDir.xml" => CONTENT_DIR_XML,
                "ConnectionMgr.xml" => CONNECTION_MGR_XML,
                _ => X_MS_MEDIA_RECEIVER_REGISTRAR_XML,
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
                content.len(),
                content
            );
            let _ = stream.write_all(response.as_bytes());
            return;
        }
        _ => (),
    }

    let mut file = match File::open(&combined_path) {
        Ok(f) => f,
        Err(_) => {
            let _ = stream.write_all(b"HTTP/1.1 404 NOT FOUND\r\n\r\n");
            return;
        }
    };

    let file_size = file.metadata().unwrap().len();
    let mut start_range: u64 = 0;

    if let Some(line) = http_request
        .lines()
        .find(|l| l.starts_with("Range: bytes="))
    {
        if let Some(r) = line.strip_prefix("Range: bytes=") {
            if let Some(parsed) = r.split('-').next().and_then(|n| n.parse::<u64>().ok()) {
                start_range = parsed;
            }
        }
    }

    file.seek(SeekFrom::Start(start_range)).unwrap();

    let status = if start_range > 0 {
        "HTTP/1.1 206 Partial Content"
    } else {
        "HTTP/1.1 200 OK"
    };
    let header = format!(
        "{}\r\n\
        Content-Range: bytes {}-{}/{}\r\n\
        Content-Type: video/mp4\r\n\
        Content-Length: {}\r\n\
        Accept-Ranges: bytes\r\n\
        transferMode.dlna.org: Streaming\r\n\
        contentFeatures.dlna.org: {}\r\n\
        Connection: close\r\n\r\n",
        status,
        start_range,
        file_size - 1,
        file_size,
        file_size - start_range,
        DLNA_FEATURES
    );

    if stream.write_all(header.as_bytes()).is_ok() {
        let mut buffer = [0; 8192];
        let mut remaining = file_size - start_range;
        while remaining > 0 {
            let to_read = std::cmp::min(remaining as usize, buffer.len());
            if let Ok(n) = file.read(&mut buffer[..to_read]) {
                if n == 0 || stream.write_all(&buffer[..n]).is_err() {
                    break;
                }
                remaining -= n as u64;
            } else {
                break;
            }
        }
    }
}

fn generate_meta_response(path: &str, ip_address: String, server_name: String) -> String {
    let result_xml = fmt::format(format_args!(
        include_str!("meta_response_result.xml"),
        ip_address, path
    ))
    .replace(
        "http-get:*:video/mp4:*",
        &format!("http-get:*:video/mp4:{}", DLNA_FEATURES),
    );
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nContent-Length: {}\r\nServer: {}/1.3.0\r\n\r\n\
        <?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:BrowseResponse xmlns:u=\"urn:schemas-upnp-org:service:ContentDirectory:1\"><Result>{}</Result><NumberReturned>1</NumberReturned><TotalMatches>1</TotalMatches></u:BrowseResponse></s:Body></s:Envelope>",
        result_xml.len() + 300,
        server_name,
        result_xml
    )
}

fn handle_post_request(
    mut stream: TcpStream,
    request: String,
    cache: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    ip_address: String,
    directory: String,
    server_name: String,
) {
    if request.contains("#GetSortCapabilities") {
        let res = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
            GET_SORT_CAPABILITIES_RESPONSE_XML.len(),
            GET_SORT_CAPABILITIES_RESPONSE_XML
        );
        let _ = stream.write_all(res.as_bytes());
        return;
    }

    let object_id = if let Some(s) = request.find("<ObjectID>") {
        let start = s + 10;
        let end = request[start..].find("</ObjectID>").unwrap_or(0);
        &request[start..start + end]
    } else {
        "0"
    };

    let mut cache_lock = cache.lock().unwrap();
    if let Some(cached) = cache_lock.get(object_id) {
        let _ = stream.write_all(cached);
    } else {
        let decoded_id = decode(object_id.strip_prefix("64$").unwrap_or(object_id));
        let path = format!("{}/{}", directory, decoded_id);
        let response = if Path::new(&path).is_dir() {
            generate_browse_response(object_id, 0, 100, ip_address, directory, server_name)
        } else {
            generate_meta_response(object_id, ip_address, server_name)
        };
        cache_lock.insert(object_id.to_string(), response.as_bytes().to_vec());
        let _ = stream.write_all(response.as_bytes());
    }
}

fn generate_browse_response(
    path: &str,
    _start: u32,
    _count: u32,
    _ip_address: String,
    directory: String,
    server_name: String,
) -> String {
    let mut didl = String::from(
        "&lt;DIDL-Lite xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:upnp=\"urn:schemas-upnp-org:metadata-1-0/upnp/\" xmlns=\"urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/\"&gt;",
    );
    let full_path = format!("{}/{}", directory, decode(path));
    let mut entries = 0;

    if let Ok(dir) = fs::read_dir(full_path) {
        for entry in dir.filter_map(Result::ok) {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            if entry.path().is_dir() {
                didl += &format!(
                    "&lt;container id=\"{path}/{}\" parentID=\"{path}\" restricted=\"1\"&gt;&lt;dc:title&gt;{}&lt;/dc:title&gt;...",
                    encode(&name),
                    encode_title_name(&name)
                );
            } else {
                didl += &format!(
                    "&lt;item id=\"{path}/{}\" parentID=\"{path}\" restricted=\"1\"&gt;&lt;dc:title&gt;{}&lt;/dc:title&gt;...",
                    encode(&name),
                    encode_title_name(&name)
                );
            }
            entries += 1;
        }
    }
    didl += "&lt;/DIDL-Lite&gt;";
    let soap = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:BrowseResponse xmlns:u=\"urn:schemas-upnp-org:service:ContentDirectory:1\"><Result>{didl}</Result><NumberReturned>{entries}</NumberReturned><TotalMatches>{entries}</TotalMatches></u:BrowseResponse></s:Body></s:Envelope>"
    );
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nServer: {}/1.3.0\r\n\r\n{}",
        soap.len(),
        server_name,
        soap
    )
}

fn decode(s: &str) -> String {
    s.replace("%20", " ").replace("&amp;", "&")
}

fn encode(s: &str) -> String {
    s.replace(' ', "%20").replace('&', "&amp;")
}

fn encode_title_name(s: &str) -> String {
    s.replace('&', "&amp;")
}
