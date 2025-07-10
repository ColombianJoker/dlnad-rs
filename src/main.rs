// main.rs
use std::net::TcpListener;
use std::net::UdpSocket;
use std::thread;
use std::sync::mpsc;
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::Mutex;
use std::io::Write;
use std::io::Read;
use std::fs;
use std::io::SeekFrom;
use std::path::Path;

use std::fs::File;
use std::collections::BTreeMap;
use std::io::Seek;
use std::collections::HashMap;

use std::time::Duration;
use clap::Parser; // Add this line to import Parser from clap
use gethostname::gethostname; // Import gethostname

const NUM_THREADS: i32 = 64; // Number of threads on the thread pool
const CONTENT_DIR_XML: &str = include_str!("ContentDir.xml");
const X_MS_MEDIA_RECEIVER_REGISTRAR_XML: &str = include_str!("X_MS_MediaReceiverRegistrar.xml");
const CONNECTION_MGR_XML: &str = include_str!("ConnectionMgr.xml");
const ROOT_DESC_XML: &str = include_str!("rootDesc.xml");
const GET_SORT_CAPABILITIES_RESPONSE_XML: &str = include_str!("get_sort_capabilities_response.xml");

// Define a struct to parse command-line arguments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Optional port to listen on for TCP connections
    #[arg(short, long, default_value_t = 8200)]
    port: u16,

    /// IP address to use for the DLNA server
    #[arg(short = 'i', long = "ip", default_value = "0.0.0.0")]
    ip_address: String,

    /// Directory to share via DLNA
    #[arg(short = 'd', long = "directory", default_value = ".")]
    directory: String,

    /// Name of the DLNA server to be shown to clients. Defaults to the computer's hostname.
    #[arg(short, long)] // Removed default_value_t
    name: Option<String>, // Changed to Option<String>
}

fn main() {
    let cli = Cli::parse(); // Parse the command-line arguments

    // Determine the server name: use provided name, or fallback to hostname, or a generic default
    let server_name = match cli.name {
        Some(name) => name,
        None => {
            gethostname().into_string().unwrap_or_else(|_| "RustyDLNA".to_string())
        }
    };

    let cache: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));
    // Use the parsed port from the CLI arguments
    let tcp_listener = TcpListener::bind(format!("0.0.0.0:{}", cli.port)).unwrap();
    println!("DLNA server '{}' listening on port {}", server_name, cli.port);

    let ssdp_socket = UdpSocket::bind("0.0.0.0:1900").unwrap();
    let multicast_addr = "239.255.255.250".parse().unwrap();
    ssdp_socket.join_multicast_v4(&multicast_addr, &cli.ip_address.parse().unwrap()).unwrap(); // Use cli.ip_address
    let mut response_bytes = Vec::new();

    write!(
        response_bytes,
        "HTTP/1.1 200 OK\r\n\
        CACHE-CONTROL: max-age=1800\r\n\
        EXT:\r\n\
        LOCATION: http://{}:{}/rootDesc.xml\r\n\
        SERVER: DLNA/1.0 DLNADOC/1.50 UPnP/1.0 {}/1.3.0\r\n\
        ST: urn:schemas-upnp-org:device:MediaServer:1\r\n\
        USN: uuid:4d696e69-444c-164e-9d41-b827eb96c6c2::urn:schemas-upnp-org:device:MediaServer:1\r\n\
        \r\n",
        cli.ip_address, // Use cli.ip_address
        cli.port, // Use the parsed port here as well
        server_name // Use the determined server_name here
    ).unwrap();
    let mut buffer = [0; 4096];

    thread::spawn(move || {
        loop {
            match ssdp_socket.recv_from(&mut buffer) {
                Ok((_size, src_addr)) => {
                    println!("Received SSDP search request from: {:?} Size: {}", src_addr, buffer.len());
                    match ssdp_socket.send_to(&response_bytes, src_addr) {
                        Err(err) => eprintln!("Failed to send SSDP response: {:?}", err),
                        Ok(_) => println!("Sent SSDP response to: {:?}", src_addr),
                    }
                }
                Err(err) => eprintln!("Failed to receive SSDP request: {:?}", err),
            }
        }
    });

    // Create a channel for communication between the main thread and worker threads
    let (tx, rx) = mpsc::channel();
    let rx = Arc::new(Mutex::new(rx));

    // Spawn worker threads
    for _ in 0..NUM_THREADS {
        let rx = Arc::clone(&rx);
        let cache = Arc::clone(&cache);
        let ip_address_clone = cli.ip_address.clone(); // Clone ip_address for the thread
        let directory_clone = cli.directory.clone(); // Clone directory for the thread
        // Removed: let name_clone = cli.name.clone(); // No longer need to clone name for handle_client

        thread::spawn(move || {
            loop {
                let stream = rx.lock().unwrap().recv().unwrap();
                // Handle each TCP connection
                handle_client(stream, cache.clone(), ip_address_clone.clone(), directory_clone.clone()); // Removed name parameter
            }
        });
    }

    // Main loop for handling TCP connections
    for tcp_stream in tcp_listener.incoming() {
        match tcp_stream {
            Ok(stream) => {
                tx.send(stream).unwrap();
            }
            Err(e) => {
                eprintln!("DLNA server error: {}", e);
            }
        }
    }
}

fn handle_client(mut stream: TcpStream, cache: Arc<Mutex<HashMap<String, Vec<u8>>>>, ip_address: String, directory: String) { // Removed name parameter
	
    let mut buffer = Vec::new();
    let _ = stream.set_read_timeout(Some(Duration::from_millis(5000)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(5000)));

    loop {
        let mut buf = vec![0; 4096]; // Temporary buffer for each read operation
        match stream.read(&mut buf) {
            Ok(0) => {
                // End of stream (EOF) reached, break out of the loop
                break;
            },
            Ok(n) => {
                // Data read successfully, extend buffer with the actual data read
                buffer.extend_from_slice(&buf[..n]);
                match n < buf.len() {
                    true => {
                        // Less than a full buffer read, so we're done
                        break;
                    },
                    false => (),
                }
            },
            Err(e) => {
                match e.kind() {
                    std::io::ErrorKind::WouldBlock => {
                        // Non-blocking operation would block, continue looping or take other action
                        // Continue looping or take appropriate action depending on your application logic
                        // In some cases, you might want to sleep or wait before attempting to read again
                    },
                    _ => {
                        // Error occurred during read operation, break out of the loop or handle the error
                        break;
                    }
                }
            }
        }
    }

    match buffer.is_empty() {
        true => (),
        false => match std::str::from_utf8(&buffer) {
            Ok(request) => match request.split_whitespace().next() {
                Some(method) => match method.to_uppercase().as_str() {
                    "GET" => handle_get_request(stream, request, ip_address, directory), // Removed name parameter
                    "HEAD" => handle_head_request(stream),
                    "POST" => handle_post_request(stream, request.to_string(), cache, ip_address, directory), // Pass ip_address and directory
                    _ => eprintln!("Unsupported HTTP method: {}", method),
                },
                None => eprintln!("Malformed HTTP request: missing method"),
            },
            Err(err) => eprintln!("Error decoding HTTP request: {}", err),
        },
    }

}



fn handle_head_request(mut stream: TcpStream) {
    let response = "HTTP/1.1 200 OK\r\n";
    let content_type = "Content-Type: video/mp4\r\n";
    let content_length = format!("Content-Length: 9999\r\n");
    let date_header = "Date: Fri, 08 Nov 2024 05:39:08 GMT\r\n";
    let ext_header = "EXT:\r\n\r\n";

    let _ = stream.write_all(format!("{}{}{}{}{}", response, content_type, content_length, date_header, ext_header).as_bytes()); // Added `let _ =` here

}




fn handle_get_request(mut stream: TcpStream, http_request: &str, _ip_address: String, directory: String) { // Removed _name parameter
    let mut http_request_parts = http_request.split_whitespace();
    let _http_method = match http_request_parts.next() { // Added `_` to http_method
        Some(method) => method,
        None => {
            eprintln!("Malformed HTTP request: missing method");
            return;
        }
    };
	let http_path = match http_request_parts.next() {
        Some(path) => path,
        None => {
            eprintln!("Malformed HTTP request: missing path");
            return;
        }
    };
    let decoded_path = decode(http_path);
    let trimmed_path = decoded_path.trim_start_matches(['.', '/']);
	
    let combined_path = format!("{}/{}", directory, decoded_path); // Use directory

    let mut file = match trimmed_path {
        "icons/lrg.png" => {
            match File::open("lrg.png") {
                Ok(file) => file,
                Err(_) => {
                    let response = "HTTP/1.1 404 NOT FOUND\r\n\r\n";
                    match stream.write_all(response.as_bytes()) {
                        Ok(_) => return,
                        Err(err) => {
                            eprintln!("Error sending response: {}", err);
                            return;
                        }
                    }
                }
            }
        }
        "ContentDir.xml" => {
                    let xml_content = CONTENT_DIR_XML;
                    let mut response = Vec::new();

        				write!(
        					response,
        					"HTTP/1.1 200 OK\r\n\
        				Content-Length: {}\r\n\
        				Content-Type: text/xml\r\n\
        				\r\n\
        				{}",
        					xml_content.len(),
        					xml_content
        				).unwrap();

        				match stream.write_all(response.as_slice()) {
        					Ok(_) => return,
        					Err(err) => {
        						eprintln!("Error sending response: {}", err);
        						return;
        					}
        				}
                }
                "X_MS_MediaReceiverRegistrar.xml" => {
                            let xml_content = X_MS_MEDIA_RECEIVER_REGISTRAR_XML;
            
                            let mut response = Vec::new();

                			write!(
                				response,
                				"HTTP/1.1 200 OK\r\n\
                			Content-Length: {}\r\n\
                			Content-Type: text/xml\r\n\
                			\r\n\
                			{}",
                				xml_content.len(),
                				xml_content
                			).unwrap();

                			match stream.write_all(response.as_slice()) {
                				Ok(_) => return,
                				Err(err) => {
                					eprintln!("Error sending response: {}", err);
                					return;
                				}
                			}
                        }
                        "ConnectionMgr.xml" => {
                                    let xml_content = CONNECTION_MGR_XML;
                        	        let mut response = Vec::new();

                        			write!(
                        				response,
                        				"HTTP/1.1 200 OK\r\n\
                        			Content-Length: {}\r\n\
                        			Content-Type: text/xml\r\n\
                        			\r\n\
                        			{}",
                        				xml_content.len(),
                        				xml_content
                        			).unwrap();

                        			match stream.write_all(response.as_slice()) {
                        				Ok(_) => return,
                        				Err(err) => {
                        					eprintln!("Error sending response: {}", err);
                        					return;
                        				}
                        			}
                                }
                                "rootDesc.xml" => {
                                            let xml_content = ROOT_DESC_XML;
                                            let mut response = Vec::new();

                                			write!(
                                				response,
                                				"HTTP/1.1 200 OK\r\n\
                                			Content-Length: {}\r\n\
                                			Content-Type: text/xml\r\n\
                                			\r\n\
                                			{}",
                                				xml_content.len(),
                                				xml_content
                                			).unwrap();

                                			match stream.write_all(response.as_slice()) {
                                				Ok(_) => return,
                                				Err(err) => {
                                					eprintln!("Error sending response: {}", err);
                                					return;
                                				}
                                			}
                                        }
        _ => match File::open(&combined_path) {
            Ok(file) => file,
            Err(err) => {
                eprintln!("Error opening file: {}, Reason: {}", combined_path, err);
                return;
            }
        },
    };

    // Extracting Range header
    let mut range: u64 = 0;
    match http_request.lines().find(|line| line.starts_with("Range: bytes=")) {
        Some(line) => {
            match line.strip_prefix("Range: bytes=") {
                Some(r) => {
                    match r.split('-').next().and_then(|num| num.parse::<u64>().ok()) {
                        Some(parsed_range) => {
                            range = parsed_range;
                        }
                        None => println!("Failed to parse range value"),
                    }
                }
                None => println!("Failed to strip prefix from Range header"),
            }
        }
        None => println!("No Range header found"),
    }

    let file_size = file.metadata().unwrap().len();

    file.seek(SeekFrom::Start(range)).unwrap();

	let mut response_header = Vec::new();

	write!(
		response_header,
		"HTTP/1.1 206 Partial Content\r\n\
	Content-Range: bytes {}-{}/{}\r\n\
	Content-Type: video/mp4\r\n\
	Content-Length: {}\r\n\
	\r\n",
		range,
		file_size - 1,
		file_size,
		file_size - range,
	).unwrap();

    match stream.write(&response_header) {
        Ok(_) => (),
        Err(err) => {
            eprintln!("Error sending response header: {}", err);
            return;
        }
    }

    let mut buffer = [0; 8192];
    let mut remaining = file_size - range;

    while remaining > 0 {
        let bytes_to_read = std::cmp::min(remaining as usize, buffer.len());
        let bytes_read = match file.read(&mut buffer[..bytes_to_read]) {
            Ok(0) => break,
            Ok(bytes_read) => bytes_read,
            Err(err) => {
                eprintln!("Error reading file: {}", err);
                return;
            }
        };

        match stream.write_all(&buffer[..bytes_read]) {
            Ok(_) => (),
            Err(err) => {
                eprintln!("Error sending response body: {}", err);
                return;
            }
        }

        remaining -= bytes_read as u64;
    }
}


fn handle_post_request(
    mut stream: TcpStream,
    request: String,
    cache: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    ip_address: String, // Add ip_address
    directory: String,  // Add directory
) {
    println!("Request: {}", request);
    
    let contains_get_sort_capabilities = request.contains("#GetSortCapabilities");
    let xml_content = GET_SORT_CAPABILITIES_RESPONSE_XML;

    let mut response = Vec::new();
    write!(
        &mut response,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
        xml_content.len(),
        xml_content
    ).unwrap();

    match contains_get_sort_capabilities {
        true => match stream.write_all(&response) {
            Err(err) => eprintln!("Error sending response: {}", err),
            _ => return,
        },
        false => (),
    }

    // Extract the ObjectID (existing logic)
    let object_id = request
        .find("ObjectID")
        .and_then(|start_index| {
            request[start_index..]
                .find('>')
                .map(|open_index| start_index + open_index + 1)
        })
        .and_then(|object_id_start| {
            request[object_id_start..]
                .find('<')
                .map(|end_index| &request[object_id_start..object_id_start + end_index])
        })
        .unwrap_or("");
    println!("Object ID: {}", object_id);

    // Extract the User-Agent (new logic)
    let user_agent = request
        .lines()
        .find(|line| line.to_lowercase().starts_with("user-agent:"))
        .and_then(|line| line.splitn(2, ':').nth(1))
        .map(|agent| agent.trim().to_string())
        .unwrap_or_else(|| "Unknown".to_string());  // Default to "Unknown" if User-Agent is not found
    
    println!("User-Agent: {}", user_agent);

    // Set requested_count to 5000 if the User-Agent matches the specified value
    let mut requested_count = request
        .find("</RequestedCount>")
        .and_then(|tmp| {
            request[..tmp]
                .rfind('>')
                .map(|tmp2| request[tmp2 + 1..tmp].trim())
        })
        .and_then(|value_str| value_str.parse::<u32>().ok())
        .unwrap_or(0); // Default to 0 if not found

    match user_agent.contains("Platinum") {
        true => {
            requested_count = 5000;
            println!("User-Agent contains 'Platinum'. Requested count set to 5000.");
        }
        false => {
            println!("User-Agent does not contain 'Platinum'. Using requested_count: {}", requested_count);
        }
    }
    // Extract StartingIndex (existing logic)
    let starting_index = request
        .find("</StartingIndex>")
        .and_then(|start_index| {
            request[..start_index]
                .rfind('>')
                .map(|close_index| request[close_index + 1..start_index].trim())
        })
        .and_then(|value_str| value_str.parse::<u32>().ok());

    let mut cache = match cache.lock() {
        Ok(locked_cache) => locked_cache,
        Err(_poisoned) => { // Added `_` to poisoned
            eprintln!("Mutex poisoned. Could not acquire lock.");
            return; // Or handle as needed
        }
    };

    // Get the cached response from the HashMap
    let cached_response = cache.get(object_id);
    match cached_response {
        Some(cached_response) => {
            let _ = stream.write_all(cached_response).map_err(|err| eprintln!("Error sending response: {}", err)); // Added `let _ =` here
            return;
        }
        None => {
		    match object_id.is_empty() {
                true => {
                    eprintln!("Error: ObjectID is empty.");
                    return; // Return early if object_id is empty
                },
                false => {
                    // Continue with the rest of the logic if object_id is not empty
                    // The `object_id_stripped` below is the one actually used, so we remove the unused one here.
                }
            }
            let object_id_stripped = object_id.strip_prefix("64$").unwrap_or(object_id).strip_prefix("0").unwrap_or(object_id);
            let combined_path = format!("{}/{}", directory, &decode(object_id_stripped)); // Use directory
            println!("Path Requested: {}", combined_path);
            println!("ObjectID Requested: {}", object_id_stripped);

            let path = Path::new(&combined_path);

            // Check if the object_id is a folder or a file
            if path.is_dir() {
                // If it's a folder, call generate_browse_response.
                let browse_response = generate_browse_response(
                    object_id_stripped,
                    &starting_index.unwrap(),
                    &requested_count, // Use the updated requested_count here
                    ip_address, // Pass ip_address
                    directory,  // Pass directory
                );
                let response_bytes = browse_response.as_bytes(); // Convert the browse response to bytes.

                // Cache the response.
                cache.insert(object_id.to_string(), response_bytes.to_vec());
                println!("Added ObjectID {} (folder) to cache.", object_id);

                // Write the response to the stream.
                let _ = stream.write_all(response_bytes).map_err(|err| eprintln!("Error sending response: {}", err)); // Added `let _ =` here
                return;
            } else if path.is_file() {
                println!("It's a file {}", path.display());
                // If it's a file, call generate_meta.
                let meta_response = generate_meta_response(object_id, ip_address); // Pass ip_address
                let response_bytes = meta_response.as_bytes(); // Convert the metadata response to bytes.

                // Write the response to the stream.
                let _ = stream.write_all(response_bytes).map_err(|err| eprintln!("Error sending response: {}", err)); // Added `let _ =` here
                return;
            } else {
                // Handle the case where the object is neither a folder nor a file (e.g., symbolic link, invalid path, etc.).
                eprintln!("Error: ObjectID {} is neither a valid file nor a valid folder.", object_id);
                return; // You could handle this differently, such as returning an.
            }
        }
    }
}



fn generate_meta_response(path: &str, ip_address: String) -> String { // Add ip_address
    // Hardcoded Date header and XML content as specified.
    let date_header = "Fri, 08 Nov 2024 05:39:08 GMT";
    let result_xml = format!(
            include_str!("meta_response_result.xml"), // Corrected usage as discussed previously
            ip_address, // Use ip_address
    	    path
        );
	println!("{}", result_xml);
    // Concatenate all parts into a single string.
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nConnection: close\r\nContent-Length: 2048\r\nServer: Debian DLNADOC/1.50 UPnP/1.0 MiniDLNA/1.3.0\r\nDate: {}\r\nEXT:\r\n\r\n<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:BrowseResponse xmlns:u=\"urn:schemas-upnp-org:service:ContentDirectory:1\"><Result>{}</Result><NumberReturned>1</NumberReturned><TotalMatches>1</TotalMatches><UpdateID>1</UpdateID></u:BrowseResponse></s:Body></s:Envelope>",
        date_header,
        result_xml
    );

    response
}

fn generate_browse_response(path: &str, starting_index: &u32, requested_count: &u32, ip_address: String, directory: String) -> String { // Add ip_address and directory

    let combined_path = format!("{}/{}", directory, &decode(path)); // Use directory
    let mut soap_response = String::with_capacity(1024);
    let mut count = 0;

    soap_response.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:BrowseResponse xmlns:u=\"urn:schemas-upnp-org:service:ContentDirectory:1\"><Result>&lt;DIDL-Lite xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:upnp=\"urn:schemas-upnp-org:metadata-1-0/upnp/\" xmlns=\"urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/\"&gt;");

    let mut directories = BTreeMap::new();
    let mut files = BTreeMap::new();

    match fs::read_dir(combined_path.clone()) {
        Ok(dir_entries) => {
            for entry in dir_entries.filter_map(Result::ok) {
                match entry.file_name().to_str() {
                    Some(name) => {
                        let entry_path = entry.path();
                        let is_dir = entry_path.is_dir();
                        match is_dir {
                            true => {
                                directories.insert(name.to_string(), entry_path);
                            }
                            false => {
                                files.insert(name.to_string(), entry_path);
                            }
                        };
                    }
                    None => println!("Failed to convert entry name to string"),
                }
            }
        }
        Err(_err) => println!("Error reading directory: {}", combined_path), // Added `_` to err
    }

    let mut loop_count = 0;
    // Process directories first
    for (name, _) in directories {
        match loop_count >= *starting_index + requested_count {
            true => break,
            false => (),
        }
        match loop_count < *starting_index {
            true => {
                loop_count += 1;
                continue;
            }
            false => (),
        }

        soap_response += &format!(
            "&lt;container id=\"{}{}/\" parentID=\"{}/\" restricted=\"1\" searchable=\"1\" childCount=\"0\"&gt;&lt;dc:title&gt;{}&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.storageFolder&lt;/upnp:class&gt;&lt;upnp:storageUsed&gt;-1&lt;/upnp:storageUsed&gt;&lt;/container&gt;",
            path, encode_title_name(&name), path, encode_title_name(&name)
        );
        println!(
        "&lt;container id=\"{}{}/\" parentID=\"{}/\" restricted=\"1\" searchable=\"1\" childCount=\"0\"&gt;&lt;dc:title&gt;{}&lt;/dc:title&gt;&lt;upnp:class&gt;object.container.storageFolder&lt;/upnp:class&gt;&lt;upnp:storageUsed&gt;-1&lt;/upnp:storageUsed&gt;&lt;/container&gt;",
        path, encode_title_name(&name), path, encode_title_name(&name)
    );

        loop_count += 1;
        count += 1;
    }

    // Process files
    for (name, _) in files {
        match loop_count >= *starting_index + requested_count {
            true => break,
            false => (),
        }
        match loop_count < *starting_index {
            true => {
                loop_count += 1;
                continue;
            }
            false => (),
        }

        soap_response += &format!(
            "&lt;item id=\"{}{}\" parentID=\"{}\" restricted=\"1\" searchable=\"1\"&gt;&lt;dc:title&gt;{}&lt;/dc:title&gt;&lt;upnp:class&gt;object.item.videoItem&lt;/upnp:class&gt;&lt;res protocolInfo=\"http-get:*:video/mp4:*\"&gt;http://{}:8200/{}{}&lt;/res&gt;&lt;/item&gt;",
            path, encode(&name), encode(path), encode_title_name(&name), ip_address, encode(path), encode(&name) // Use ip_address
        );


        loop_count += 1;
        count += 1;
    }

    // Append the closing tags using format!
    soap_response += &format!(
        "&lt;/DIDL-Lite&gt;</Result><NumberReturned>{}</NumberReturned><TotalMatches>{}</TotalMatches><UpdateID>0</UpdateID></u:BrowseResponse></s:Body></s:Envelope>",
        count, count
    );

    let soap_response_size = soap_response.len();
    format!("HTTP/1.1 200 OK\r\nConnection: Keep-Alive\r\nContent-Type: text/xml;\r\nContent-Length: {}\r\nServer: RustyDLNA DLNADOC/1.50 UPnP/1.0 RustyDLNA6/1.3.0\r\n\r\n{}", soap_response_size, soap_response)
}

fn decode(s: &str) -> String {
    let mut decoded = String::from(s);
    decoded = decoded.replace("%20", " ");
    decoded = decoded.replace("%27", "'");
    decoded = decoded.replace("%28", "(");
    decoded = decoded.replace("%29", ")");
    decoded = decoded.replace("%22", "\"");
    decoded = decoded.replace("%23", "#");
    decoded = decoded.replace("%2C", ",");
    decoded = decoded.replace("%E2%80%99", "\u{2019}");
    decoded = decoded.replace("&apos;", "'");
    decoded = decoded.replace("&amp;", "&");
    decoded = decoded.replace("&amp;amp;", "&");
    decoded = decoded.replace("%C3%A1", "\u{00E1}");
    decoded = decoded.replace("%C3%A9", "\u{00E9}");
    decoded
}


fn encode(s: &str) -> String {
    let mut encoded = String::from(s);
    
    encoded = encoded.replace(' ', "%20");
    encoded = encoded.replace('\'', "%27");
    encoded = encoded.replace('(', "%28");
    encoded = encoded.replace(')', "%29");
    encoded = encoded.replace('\"', "%22");
    encoded = encoded.replace('#', "%23");
    encoded = encoded.replace(',', "%2C");
    encoded = encoded.replace('\u{2019}', "%E2%80%99");
    encoded = encoded.replace('&', "&amp;amp;");
    encoded = encoded.replace('\u{00E1}', "%C3%A1");
    encoded = encoded.replace('\u{00E9}', "%C3%A9");
    encoded
}
fn encode_title_name(s: &str) -> String {
    let mut encoded = String::from(s);
    
    encoded = encoded.replace('&', "&amp;amp;");
    encoded
}