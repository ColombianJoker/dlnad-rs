use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

use clap::Parser;
use gethostname::gethostname;
use local_ip_address::local_ip;
use log::info;
use mp4ameta::Tag;

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
        // This template ensures the version is printed in the help output
        help_template = "{bin} {version}\n{author-with-newline}{about-section}\n{usage-heading} {usage}\n\n{all-args}\n{after-help}"
    )]
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
    #[arg(long, hide = true)]
    debug: bool,
}

fn main() {
    let cli = Cli::parse();
    let server_ip = if cli.ip_address == "0.0.0.0" {
        match local_ip() {
            Ok(ip) => ip.to_string(),
            Err(_) => "127.0.0.1".to_string(),
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

    info!(
        "DLNA server {} (version {}) listening on {}:{}",
        server_name,
        env!("BUILD_VERSION"),
        server_ip,
        cli.port
    );

    let cache: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    let tcp_listener = TcpListener::bind(format!("0.0.0.0:{}", cli.port)).unwrap();

    let ssdp_socket = UdpSocket::bind(format!("0.0.0.0:{}", SSDP_PORT)).unwrap();
    let multicast_addr = "239.255.255.250".parse().unwrap();
    let interface_ip: std::net::Ipv4Addr = server_ip.parse().unwrap();
    ssdp_socket
        .join_multicast_v4(&multicast_addr, &interface_ip)
        .unwrap();

    let mut ssdp_response = Vec::new();
    write!(ssdp_response, "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nEXT:\r\nLOCATION: http://{}:{}/rootDesc.xml\r\nSERVER: UPnP/1.0 DLNADOC/1.50 Gunther/{}\r\nST: urn:schemas-upnp-org:device:MediaServer:1\r\nUSN: uuid:4d696e69-444c-164e-9d41-b827eb96c6c2::urn:schemas-upnp-org:device:MediaServer:1\r\n\r\n", server_ip, cli.port, env!("BUILD_VERSION")).unwrap();

    let ssdp_socket_clone = ssdp_socket.try_clone().unwrap();
    thread::spawn(move || {
        let mut buffer = [0; 4096];
        loop {
            if let Ok((_, src_addr)) = ssdp_socket_clone.recv_from(&mut buffer) {
                let _ = ssdp_socket_clone.send_to(&ssdp_response, src_addr);
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
        let debug_flag = cli.debug;

        thread::spawn(move || {
            loop {
                let stream = rx.lock().unwrap().recv().unwrap();
                handle_client(
                    stream,
                    cache.clone(),
                    ip_to_pass.clone(),
                    directory_clone.clone(),
                    server_name_clone.clone(),
                    debug_flag,
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
    debug: bool,
) {
    let mut buf = vec![0; 8192];
    if let Ok(n) = stream.read(&mut buf) {
        if n > 0 {
            let request = String::from_utf8_lossy(&buf[..n]);
            if debug {
                info!("DEBUG REQUEST:\n{}", request);
            }
            let method = request.split_whitespace().next().unwrap_or("");
            match method {
                "GET" => {
                    handle_get_request(stream, &request, ip_address, directory, server_name, debug)
                }
                "POST" => handle_post_request(
                    stream,
                    request.to_string(),
                    cache,
                    ip_address,
                    directory,
                    server_name,
                    debug,
                ),
                "SUBSCRIBE" => handle_subscribe_request(stream, debug),
                "HEAD" => handle_head_request(stream, debug),
                _ => (),
            }
        }
    }
}

fn handle_subscribe_request(mut stream: TcpStream, debug: bool) {
    let response = "HTTP/1.1 200 OK\r\nSID: uuid:4d696e69-444c-164e-9d41-b827eb96c6c2\r\nTIMEOUT: Second-300\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    if debug {
        info!("DEBUG RESPONSE HEADERS:\n{}", response);
    }
    let _ = stream.write_all(response.as_bytes());
}

fn handle_head_request(mut stream: TcpStream, debug: bool) {
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: video/mp4\r\nAccept-Ranges: bytes\r\nContent-Length: 0\r\ncontentFeatures.dlna.org: {}\r\nConnection: close\r\n\r\n",
        DLNA_FEATURES
    );
    if debug {
        info!("DEBUG RESPONSE HEADERS:\n{}", response);
    }
    let _ = stream.write_all(response.as_bytes());
}

fn handle_get_request(
    mut stream: TcpStream,
    http_request: &str,
    ip_address: String,
    directory: String,
    server_name: String,
    debug: bool,
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
                "rootDesc.xml" => ROOT_DESC_XML.replace(
                    "<friendlyName>Gunther</friendlyName>",
                    &format!("<friendlyName>{}</friendlyName>", server_name),
                ),
                "ContentDir.xml" => CONTENT_DIR_XML.to_string(),
                "ConnectionMgr.xml" => CONNECTION_MGR_XML.to_string(),
                _ => X_MS_MEDIA_RECEIVER_REGISTRAR_XML.to_string(),
            };
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/xml\r\nConnection: close\r\n\r\n",
                content.len()
            );
            if debug {
                info!("DEBUG RESPONSE HEADERS:\n{}", header);
            }
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
                "CaptionInfo.sec: http://{}:8200/{}\r\n\
                 ContentFeatures.dlna.org: {}\r\n",
                ip_address,
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
            "HTTP/1.1 {} Partial Content\r\n\
            Content-Range: bytes {}-{}/{}\r\n\
            Content-Type: {}\r\n\
            Content-Length: {}\r\n\
            Accept-Ranges: bytes\r\n\
            {}Connection: close\r\n\r\n",
            if start_range > 0 { "206" } else { "200" },
            start_range,
            file_size - 1,
            file_size,
            mime_type,
            file_size - start_range,
            extra_headers
        );

        if debug {
            info!("DEBUG RESPONSE HEADERS:\n{}", header);
        }
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
    directory: String,
    server_name: String,
    debug: bool,
) {
    let response_body = if request.contains("#GetSortCapabilities") {
        GET_SORT_CAPABILITIES_RESPONSE_XML.to_string()
    } else {
        let object_id = request
            .find("<ObjectID>")
            .map(|s| {
                let start = s + 10;
                let end = request[start..].find("</ObjectID>").unwrap_or(0);
                &request[start..start + end]
            })
            .unwrap_or("0");

        let start_index = request
            .find("<StartingIndex>")
            .map(|s| {
                let start = s + 15;
                let end = request[start..].find("</StartingIndex>").unwrap_or(0);
                request[start..start + end].parse::<usize>().unwrap_or(0)
            })
            .unwrap_or(0);

        let requested_count = request
            .find("<RequestedCount>")
            .map(|s| {
                let start = s + 16;
                let end = request[start..].find("</RequestedCount>").unwrap_or(0);
                request[start..start + end].parse::<usize>().unwrap_or(0)
            })
            .unwrap_or(100);

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
                    directory,
                    server_name.clone(),
                )
            } else {
                generate_meta_response(object_id, ip_address, server_name.clone())
            };
            cache_lock.insert(cache_key, resp.as_bytes().to_vec());
            resp
        }
    };

    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nContent-Length: {}\r\nConnection: close\r\nEXT:\r\nServer: {}/{}\r\n\r\n",
        response_body.len(),
        server_name,
        env!("BUILD_VERSION")
    );
    if debug {
        info!("DEBUG RESPONSE HEADERS:\n{}", header);
    }
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(response_body.as_bytes());
}

fn format_duration(seconds: u64) -> String {
    let h = seconds / 3600;
    let m = (seconds % 3600) / 60;
    let s = seconds % 60;
    format!("{:01}:{:02}:{:02}", h, m, s)
}

fn generate_browse_response(
    path: &str,
    start_index: usize,
    requested_count: usize,
    ip_address: String,
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
            let is_dir = entry_path.is_dir();
            let ext = entry_path
                .extension()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();
            if is_dir || ["mp4", "mkv", "avi", "mov"].contains(&ext.as_str()) {
                entries.push((name, is_dir, entry_path));
            }
        }
    }

    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let total_matches = entries.len();
    let slice = entries
        .iter()
        .skip(start_index)
        .take(if requested_count == 0 {
            total_matches
        } else {
            requested_count
        });

    let mut returned_count = 0;
    for (name, is_dir, entry_path) in slice {
        let child_id = if relative_dir.is_empty() {
            name.clone()
        } else {
            format!("{}/{}", relative_dir, name)
        };
        let encoded_id = encode(&child_id);

        let mut display_title = encode_title_name(name);
        let mut display_artist = String::new();
        let mut display_desc = String::new();
        let mut duration_str = String::new();
        let mut subtitle_xml = String::new();
        let mut thumb_xml = String::new();
        let mut video_res_attr = String::new();

        if !*is_dir {
            if let Ok(tag) = Tag::read_from_path(entry_path) {
                if let Some(t) = tag.title() {
                    display_title = encode_title_name(t);
                }
                if let Some(a) = tag.artist() {
                    display_artist = format!("<upnp:artist>{}</upnp:artist>", encode_title_name(a));
                }
                display_desc = format!(
                    "<dc:description>{}</dc:description>",
                    encode_title_name(name)
                );
                let d = tag.duration();
                duration_str = format!(" duration=\"{}\"", format_duration(d.as_secs()));
            }

            // Subtitle Detection
            let srt_path = entry_path.with_extension("srt");
            let vtt_path = entry_path.with_extension("vtt");
            let (sub_path, sub_mime) = if srt_path.exists() {
                (Some(srt_path), "text/srt")
            } else if vtt_path.exists() {
                (Some(vtt_path), "text/vtt")
            } else {
                (None, "")
            };

            if let Some(p) = sub_path {
                let sub_name = p.file_name().unwrap().to_string_lossy();
                let sub_child_id = if relative_dir.is_empty() {
                    sub_name.into_owned()
                } else {
                    format!("{}/{}", relative_dir, sub_name)
                };
                let sub_url = format!("http://{}:8200/{}", ip_address, encode(&sub_child_id));
                video_res_attr = format!(
                    " pv:subtitleFileUri=\"{}\" xmlns:pv=\"http://www.pv.com/pvns/\"",
                    sub_url
                );
                subtitle_xml = format!(
                    "<res protocolInfo=\"http-get:*:{} :*\">{}</res>\
                     <sec:CaptionInfoEx xmlns:sec=\"http://www.sec.co.kr/\">{}</sec:CaptionInfoEx>",
                    sub_mime, sub_url, sub_url
                );
            }

            // Thumbnail Detection
            let jpg_path = entry_path.with_extension("jpg");
            let png_path = entry_path.with_extension("png");
            let thumb_path = if jpg_path.exists() {
                Some(jpg_path)
            } else if png_path.exists() {
                Some(png_path)
            } else {
                None
            };

            if let Some(p) = thumb_path {
                let thumb_name = p.file_name().unwrap().to_string_lossy();
                let thumb_child_id = if relative_dir.is_empty() {
                    thumb_name.into_owned()
                } else {
                    format!("{}/{}", relative_dir, thumb_name)
                };
                let thumb_url = format!("http://{}:8200/{}", ip_address, encode(&thumb_child_id));
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
                "<item id=\"{}\" parentID=\"{}\" restricted=\"1\"><dc:title>{}</dc:title>{}{}{}<upnp:class>object.item.videoItem</upnp:class><res protocolInfo=\"http-get:*:video/mp4:{}\"{}{}>http://{}:8200/{}</res>{}</item>",
                encoded_id,
                path,
                display_title,
                display_artist,
                display_desc,
                thumb_xml,
                DLNA_FEATURES,
                duration_str,
                video_res_attr,
                ip_address,
                encoded_id,
                subtitle_xml
            );
        }
        returned_count += 1;
    }
    didl_raw += "</DIDL-Lite>";
    let escaped_didl = didl_raw
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&apos;");

    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:BrowseResponse xmlns:u=\"urn:schemas-upnp-org:service:ContentDirectory:1\"><Result>{}</Result><NumberReturned>{}</NumberReturned><TotalMatches>{}</TotalMatches><UpdateID>1</UpdateID></u:BrowseResponse></s:Body></s:Envelope>",
        escaped_didl, returned_count, total_matches
    )
}

fn generate_meta_response(path: &str, ip_address: String, _server_name: String) -> String {
    let result_xml = fmt::format(format_args!(
        include_str!("meta_response_result.xml"),
        ip_address, path
    ))
    .replace(
        "http-get:*:video/mp4:*",
        &format!("http-get:*:video/mp4:{}", DLNA_FEATURES),
    );
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:BrowseResponse xmlns:u=\"urn:schemas-upnp-org:service:ContentDirectory:1\"><Result>{}</Result><NumberReturned>1</NumberReturned><TotalMatches>1</TotalMatches><UpdateID>1</UpdateID></u:BrowseResponse></s:Body></s:Envelope>",
        result_xml
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
