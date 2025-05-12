use std::fs::File;
use std::io::{Read, ErrorKind};
use std::path::Path;
use std::net::{UdpSocket, Ipv4Addr}; // SocketAddr is implicitly used by UdpSocket
use std::collections::HashMap;
use std::convert::TryInto;

// ---------------
// Data Structures for Extracted Configuration (from Protobuf)
// ---------------

/// Holds the information extracted from a NetworkResolution's client.
#[derive(Debug, Clone)]
struct ExtractedInfo {
    tags: Vec<String>, // Tags associated with this network entry
    ip: String,        // IP address as a string
    port: i32,         // Port number
}

// ---------------
// Protobuf Decoding Constants and Helper Functions
// ---------------

// Protobuf Wire Types
const WIRE_TYPE_VARINT: u32 = 0;
const WIRE_TYPE_64BIT: u32 = 1;
const WIRE_TYPE_LENGTH_DELIMITED: u32 = 2;
// const WIRE_TYPE_START_GROUP: u32 = 3; // Deprecated
// const WIRE_TYPE_END_GROUP: u32 = 4;   // Deprecated
const WIRE_TYPE_32BIT: u32 = 5;

/// Reads a varint from the buffer and advances the buffer slice.
/// Varints are a method of serializing integers using one or more bytes.
fn read_varint(buffer: &mut &[u8]) -> Result<u64, String> {
    let mut value: u64 = 0;
    let mut shift: u8 = 0;
    let original_len = buffer.len();

    for i in 0..original_len {
        // A u64 varint should not be longer than 10 bytes.
        if i >= 10 {
            return Err("Varint too long (max 10 bytes for u64)".to_string());
        }
        let byte = buffer[i];
        // Add the 7 data bits of the byte to the value.
        value |= ((byte & 0x7F) as u64) << shift;
        shift += 7;
        // If the MSB is 0, this is the last byte of the varint.
        if byte & 0x80 == 0 {
            *buffer = &buffer[(i + 1)..]; // Advance the buffer
            return Ok(value);
        }
    }
    Err("Buffer too short to complete varint or varint malformed".to_string())
}

/// Reads a Protobuf tag (field number and wire type) from the buffer.
fn read_tag(buffer: &mut &[u8]) -> Result<(u32, u32), String> {
    let tag_val = read_varint(buffer)?;
    let wire_type = (tag_val & 0x07) as u32; // Last 3 bits are the wire type
    let field_number = (tag_val >> 3) as u32; // The rest is the field number
    if field_number == 0 {
        return Err("Invalid field number 0 in tag".to_string());
    }
    Ok((field_number, wire_type))
}

/// Reads a length-delimited field from the buffer.
/// This is used for strings, bytes, embedded messages, and packed repeated fields.
fn read_length_delimited<'a>(buffer: &mut &'a [u8]) -> Result<&'a [u8], String> {
    let len = read_varint(buffer)? as usize;
    if buffer.len() < len {
        return Err(format!(
            "Buffer too short for length-delimited data. Expected {} bytes, found {}",
            len,
            buffer.len()
        ));
    }
    let (data_slice, rest_slice) = buffer.split_at(len);
    *buffer = rest_slice; // Advance the buffer
    Ok(data_slice)
}

/// Skips a field in the Protobuf stream based on its wire type.
fn skip_field(buffer: &mut &[u8], wire_type: u32) -> Result<(), String> {
    match wire_type {
        WIRE_TYPE_VARINT => {
            read_varint(buffer)?; // Read and discard
        }
        WIRE_TYPE_64BIT => {
            if buffer.len() < 8 {
                return Err("Buffer too short to skip 64-bit field".to_string());
            }
            *buffer = &buffer[8..]; // Skip 8 bytes
        }
        WIRE_TYPE_LENGTH_DELIMITED => {
            let len = read_varint(buffer)? as usize;
            if buffer.len() < len {
                return Err("Buffer too short to skip length-delimited field".to_string());
            }
            *buffer = &buffer[len..]; // Skip 'len' bytes
        }
        WIRE_TYPE_32BIT => {
            if buffer.len() < 4 {
                return Err("Buffer too short to skip 32-bit field".to_string());
            }
            *buffer = &buffer[4..]; // Skip 4 bytes
        }
        3 | 4 => { // Start/End group (deprecated in proto3)
            return Err("Deprecated wire types (start/end group) not supported for skipping.".to_string());
        }
        _ => return Err(format!("Unknown wire type encountered: {}", wire_type)),
    }
    Ok(())
}

// ---------------
// Protobuf Message Parsing Functions
// ---------------

/// Parses a `Uri` message.
/// message Uri { string ip = 1; int32 port = 2; }
fn parse_uri_message_proto(
    mut data: &[u8], // Slice representing the Uri message
    tags_for_this_uri: &[String],
    results: &mut Vec<ExtractedInfo>,
) -> Result<(), String> {
    let mut ip_opt: Option<String> = None;
    let mut port_opt: Option<i32> = None;

    while !data.is_empty() {
        let (field_number, wire_type) = read_tag(&mut data)?;
        match field_number {
            1 => { // ip (string)
                if wire_type != WIRE_TYPE_LENGTH_DELIMITED {
                    return Err(format!("Uri.ip: Expected wire type {}, got {}", WIRE_TYPE_LENGTH_DELIMITED, wire_type));
                }
                let ip_bytes = read_length_delimited(&mut data)?;
                ip_opt = Some(String::from_utf8(ip_bytes.to_vec())
                    .map_err(|e| format!("Uri.ip: Invalid UTF-8 string: {}", e))?);
            }
            2 => { // port (int32)
                if wire_type != WIRE_TYPE_VARINT {
                    return Err(format!("Uri.port: Expected wire type {}, got {}", WIRE_TYPE_VARINT, wire_type));
                }
                let port_val = read_varint(&mut data)?;
                port_opt = Some(port_val as i32); // int32 is encoded as varint
            }
            _ => skip_field(&mut data, wire_type)
                .map_err(|e| format!("Uri: Error skipping field {}: {}", field_number, e))?,
        }
    }

    if let (Some(ip_str), Some(port_num)) = (ip_opt, port_opt) {
        results.push(ExtractedInfo {
            tags: tags_for_this_uri.to_vec(), // Clone the tags for this specific IP/port
            ip: ip_str,
            port: port_num,
        });
    } else {
        // If a Uri message is incomplete (missing ip or port), we might log it or return an error.
        // For now, we only add it if both are present. This could be an error if they are mandatory.
        // return Err("Uri message incomplete: missing IP or port.".to_string());
    }
    Ok(())
}

/// Parses a `Uri_Slot` message.
/// message Uri_Slot { int32 internal_port = 1; repeated Uri uri = 2; }
fn parse_uri_slot_message_proto(
    mut data: &[u8], // Slice representing the Uri_Slot message
    tags_for_slot: &[String],
    results: &mut Vec<ExtractedInfo>,
) -> Result<(), String> {
    while !data.is_empty() {
        let (field_number, wire_type) = read_tag(&mut data)?;
        match field_number {
            1 => { // internal_port (int32) - We ignore this field's value
                if wire_type != WIRE_TYPE_VARINT {
                    // Even if ignoring, validate type for correct skipping
                    return Err(format!("Uri_Slot.internal_port: Expected wire type {}, got {}", WIRE_TYPE_VARINT, wire_type));
                }
                skip_field(&mut data, wire_type)
                    .map_err(|e| format!("Uri_Slot: Error skipping internal_port: {}", e))?;
            }
            2 => { // uri (repeated Uri message)
                if wire_type != WIRE_TYPE_LENGTH_DELIMITED {
                     return Err(format!("Uri_Slot.uri: Expected wire type {}, got {}", WIRE_TYPE_LENGTH_DELIMITED, wire_type));
                }
                let uri_message_bytes = read_length_delimited(&mut data)?;
                parse_uri_message_proto(uri_message_bytes, tags_for_slot, results)
                    .map_err(|e| format!("Uri_Slot: Error parsing nested Uri message: {}", e))?;
            }
            _ => skip_field(&mut data, wire_type)
                .map_err(|e| format!("Uri_Slot: Error skipping field {}: {}", field_number, e))?,
        }
    }
    Ok(())
}

/// Parses an `Instance` message.
/// message Instance { Service.Api api = 1; repeated Uri_Slot uri_slot = 2; }
fn parse_instance_message_proto(
    mut data: &[u8], // Slice representing the Instance message
    tags_for_instance: &[String],
    results: &mut Vec<ExtractedInfo>,
) -> Result<(), String> {
    while !data.is_empty() {
        let (field_number, wire_type) = read_tag(&mut data)?;
        match field_number {
            1 => { // api (Service.Api message) - We ignore this field
                // We must correctly skip it, assuming it's length-delimited if it's a message.
                skip_field(&mut data, wire_type)
                    .map_err(|e| format!("Instance: Error skipping api field: {}", e))?;
            }
            2 => { // uri_slot (repeated Uri_Slot message)
                if wire_type != WIRE_TYPE_LENGTH_DELIMITED {
                     return Err(format!("Instance.uri_slot: Expected wire type {}, got {}", WIRE_TYPE_LENGTH_DELIMITED, wire_type));
                }
                let uri_slot_message_bytes = read_length_delimited(&mut data)?;
                parse_uri_slot_message_proto(uri_slot_message_bytes, tags_for_instance, results)
                    .map_err(|e| format!("Instance: Error parsing nested Uri_Slot message: {}", e))?;
            }
            _ => skip_field(&mut data, wire_type)
                .map_err(|e| format!("Instance: Error skipping field {}: {}", field_number, e))?,
        }
    }
    Ok(())
}

/// Parses a `NetworkResolution` message.
/// message NetworkResolution { repeated string tags = 1; Instance network_client = 2; }
fn parse_network_resolution_message_proto(
    mut data: &[u8], // Slice representing the NetworkResolution message
    results: &mut Vec<ExtractedInfo>,
) -> Result<(), String> {
    let mut current_tags_for_resolution: Vec<String> = Vec::new();
    let mut network_client_message_bytes_opt: Option<&[u8]> = None;

    while !data.is_empty() {
        let (field_number, wire_type) = read_tag(&mut data)?;
        match field_number {
            1 => { // tags (repeated string)
                if wire_type != WIRE_TYPE_LENGTH_DELIMITED {
                     return Err(format!("NetworkResolution.tags: Expected wire type {}, got {}", WIRE_TYPE_LENGTH_DELIMITED, wire_type));
                }
                let tag_bytes = read_length_delimited(&mut data)?;
                current_tags_for_resolution.push(String::from_utf8(tag_bytes.to_vec())
                    .map_err(|e| format!("NetworkResolution.tags: Invalid UTF-8 string for tag: {}", e))?);
            }
            2 => { // network_client (Instance message)
                if wire_type != WIRE_TYPE_LENGTH_DELIMITED {
                    return Err(format!("NetworkResolution.network_client: Expected wire type {}, got {}", WIRE_TYPE_LENGTH_DELIMITED, wire_type));
                }
                network_client_message_bytes_opt = Some(read_length_delimited(&mut data)?);
            }
            _ => skip_field(&mut data, wire_type)
                .map_err(|e| format!("NetworkResolution: Error skipping field {}: {}", field_number, e))?,
        }
    }

    if let Some(client_bytes) = network_client_message_bytes_opt {
        // Only proceed if there are tags associated, as per the problem's interest.
        if !current_tags_for_resolution.is_empty() {
            parse_instance_message_proto(client_bytes, &current_tags_for_resolution, results)
                .map_err(|e| format!("NetworkResolution: Error parsing nested Instance (network_client) message: {}", e))?;
        }
    }
    Ok(())
}

/// Parses the root `ConfigurationFile` message.
/// message ConfigurationFile { ... repeated NetworkResolution network_resolution = 3; ... }
fn parse_configuration_file_proto(mut data: &[u8]) -> Result<Vec<ExtractedInfo>, String> {
    let mut results = Vec::new();

    while !data.is_empty() {
        let (field_number, wire_type) = read_tag(&mut data)?;
        match field_number {
            // Fields we are interested in:
            3 => { // network_resolution (repeated NetworkResolution message)
                if wire_type != WIRE_TYPE_LENGTH_DELIMITED {
                    return Err(format!("ConfigurationFile.network_resolution: Expected wire type {}, got {}", WIRE_TYPE_LENGTH_DELIMITED, wire_type));
                }
                let network_resolution_bytes = read_length_delimited(&mut data)?;
                parse_network_resolution_message_proto(network_resolution_bytes, &mut results)
                    .map_err(|e| format!("ConfigurationFile: Error parsing nested NetworkResolution message: {}", e))?;
            }
            // Fields to ignore (gateway = 1, config = 2, initial_sysresources = 4):
            1 | 2 | 4 => {
                skip_field(&mut data, wire_type)
                    .map_err(|e| format!("ConfigurationFile: Error skipping field {}: {}", field_number, e))?;
            }
            _ => { // Any other unknown field
                skip_field(&mut data, wire_type)
                    .map_err(|e| format!("ConfigurationFile: Error skipping unknown field {}: {}", field_number, e))?;
            }
        }
    }
    Ok(results)
}


// ---------------
// DNS Protocol Constants and Data Structures
// ---------------
const QTYPE_A: u16 = 1;    // DNS A record type (IPv4 address)
const QTYPE_TXT: u16 = 16;   // DNS TXT record type (text strings)
const QCLASS_IN: u16 = 1;  // DNS INternet class

// DNS Header Flags (for responses)
const FLAG_QR_RESPONSE: u16 = 0x8000; // Query/Response: 1 for response
const FLAG_AA: u16 = 0x0400;          // Authoritative Answer: 1 (our server is authoritative for its configured names)

// DNS Response Codes (RCODE)
const RCODE_NO_ERROR: u16 = 0;        // No error condition
// const RCODE_FORMAT_ERROR: u16 = 1; // Not fully used for sending, but could be
const RCODE_SERVER_FAILURE: u16 = 2;
const RCODE_NXDOMAIN: u16 = 3;        // Non-Existent Domain
// const RCODE_NOT_IMPLEMENTED: u16 = 4; // Query type not implemented

/// Represents a parsed DNS question from a query packet.
#[derive(Debug)]
struct DnsQuestion {
    qname: String, // Decoded domain name (e.g., "service-alpha" or "host.example.com")
    qtype: u16,    // Query type (e.g., A, TXT)
    qclass: u16,   // Query class (e.g., IN)
}

/// Holds information parsed from an incoming DNS query packet.
#[derive(Debug)]
struct DnsQueryInfo {
    transaction_id: u16, // Copied to the response
    question: DnsQuestion,
    // client_flags: u16, // Could store original flags if needed for complex logic
}

// ---------------
// DNS Byte and Name Formatting Helper Functions
// ---------------

/// Converts a u16 to a 2-byte array in big-endian (network byte order).
fn u16_to_bytes_be(val: u16) -> [u8; 2] { val.to_be_bytes() }

/// Converts a u32 to a 4-byte array in big-endian.
fn u32_to_bytes_be(val: u32) -> [u8; 4] { val.to_be_bytes() }

/// Converts the first 2 bytes of a slice to a u16 in big-endian.
fn bytes_to_u16_be(bytes: &[u8]) -> Result<u16, String> {
    if bytes.len() < 2 { return Err("Byte slice too short for u16 conversion".to_string()); }
    Ok(u16::from_be_bytes(bytes[0..2].try_into()
        .map_err(|e| format!("Failed to convert slice to [u8; 2]: {:?}", e))?))
}

/// Parses a DNS QNAME from a packet slice starting at `start_offset`.
/// Returns the decoded name string and the number of bytes read for the QNAME.
/// This simplified version does not handle DNS name compression pointers.
fn parse_qname_from_dns_packet(packet_data: &[u8], start_offset: usize) -> Result<(String, usize), String> {
    let mut qname_parts: Vec<String> = Vec::new();
    let mut current_pos_in_packet = start_offset;
    let mut total_qname_bytes_read_from_offset = 0;

    loop {
        if current_pos_in_packet >= packet_data.len() {
            return Err("Buffer too short while reading QNAME label length".to_string());
        }
        let label_len_byte = packet_data[current_pos_in_packet];

        // Check for DNS name compression pointer (MSB two bits are 11)
        if (label_len_byte & 0xC0) == 0xC0 {
            // This basic implementation does not support compression pointers in questions.
            // A production server would need to handle this, potentially by looking up the name
            // from an earlier offset in the original packet_data.
            return Err("DNS name compression pointers in QNAME are not supported by this parser.".to_string());
            // If we were to handle it (partially, just skipping the pointer):
            // if current_pos_in_packet + 1 >= packet_data.len() { return Err("Buffer too short for QNAME compression pointer offset".to_string()); }
            // total_qname_bytes_read_from_offset += 2; // Pointer is 2 bytes
            // break; // A pointer always terminates the current name part.
        }

        current_pos_in_packet += 1; // Advance past the length byte
        total_qname_bytes_read_from_offset += 1;

        if label_len_byte == 0 { // End of QNAME (null label)
            break;
        }

        if label_len_byte > 63 { // Max label length in DNS
            return Err(format!("QNAME label too long: {} bytes (max 63)", label_len_byte));
        }
        if current_pos_in_packet + (label_len_byte as usize) > packet_data.len() {
            return Err("Buffer too short while reading QNAME label data".to_string());
        }

        let label_bytes = &packet_data[current_pos_in_packet .. current_pos_in_packet + (label_len_byte as usize)];
        let label_str = std::str::from_utf8(label_bytes)
            .map_err(|_| "QNAME label contains invalid UTF-8 characters".to_string())?;
        qname_parts.push(label_str.to_string());

        current_pos_in_packet += label_len_byte as usize;
        total_qname_bytes_read_from_offset += label_len_byte as usize;
    }
    
    // If qname_parts is empty, it means the QNAME was just a single null byte (e.g. for root "."),
    // otherwise, join parts with dots.
    if qname_parts.is_empty() && total_qname_bytes_read_from_offset == 1 { // Only a single 0x00 byte for root.
        Ok((".".to_string(), total_qname_bytes_read_from_offset))
    } else {
        Ok((qname_parts.join("."), total_qname_bytes_read_from_offset))
    }
}

/// Formats a domain name string (e.g., "host.example.com" or "my-tag")
/// into the DNS label-sequence format (e.g., \x04host\x07example\x03com\x00).
fn format_name_for_dns_packet(name: &str) -> Vec<u8> {
    let mut encoded_name: Vec<u8> = Vec::new();
    if name == "." || name.is_empty() { // Root domain special case
        encoded_name.push(0); // Single null byte for root
        return encoded_name;
    }

    for label in name.split('.') {
        // Each label should not be empty unless it's an artifact of "foo..bar"
        // which is technically invalid. We assume valid input labels.
        if label.len() > 63 {
            // For simplicity, panic on invalid input. A robust server might return an error.
            panic!("DNS label '{}' is too long (max 63 characters)", label);
        }
        if label.is_empty() { 
            // This can happen if name is "foo." - the last "" part after split
            // or if name is ".foo" or "foo..bar". Generally, we expect clean labels.
            // If the original name ended with '.', the final 0x00 will handle it.
            continue;
        }
        encoded_name.push(label.len() as u8); // Length byte
        encoded_name.extend_from_slice(label.as_bytes()); // Label characters
    }
    encoded_name.push(0); // Null byte to terminate the QNAME
    encoded_name
}


// ---------------
// DNS Packet Parsing and Building Logic
// ---------------

/// Parses an incoming DNS query packet.
fn parse_dns_query_packet(packet_bytes: &[u8]) -> Result<DnsQueryInfo, String> {
    if packet_bytes.len() < 12 { // DNS header is 12 bytes
        return Err("DNS packet too short (less than 12 bytes for header)".to_string());
    }

    let transaction_id = bytes_to_u16_be(&packet_bytes[0..2])?;
    let flags = bytes_to_u16_be(&packet_bytes[2..4])?;
    let qd_count = bytes_to_u16_be(&packet_bytes[4..6])?; // Question count
    // ANCOUNT, NSCOUNT, ARCOUNT are at offsets 6, 8, 10 respectively. Ignored for parsing a query.

    // QR bit (bit 15 of flags): 0 for query, 1 for response.
    if (flags & FLAG_QR_RESPONSE) != 0 { // 0x8000
        return Err("Received packet is not a DNS query (QR bit is set to 1)".to_string());
    }
    // Opcode (bits 14-11 of flags): Should be 0 for a standard query (QUERY).
    let opcode = (flags >> 11) & 0x0F;
    if opcode != 0 {
        // We only support standard queries. Could respond with FORMERR.
        return Err(format!("Unsupported DNS Opcode: {}. Only Opcode 0 (QUERY) is supported.", opcode));
    }
    if qd_count == 0 {
        return Err("DNS query contains no questions (QDCOUNT is 0)".to_string());
    }
    if qd_count > 1 {
        // This simple server only handles one question per query.
        return Err("Multiple questions in a single DNS query are not supported.".to_string());
    }

    let mut current_offset_in_packet = 12; // Questions start after the 12-byte header

    // Parse QNAME (the domain name being queried)
    let (qname_str, qname_bytes_len) = parse_qname_from_dns_packet(packet_bytes, current_offset_in_packet)
        .map_err(|e| format!("Failed to parse QNAME from DNS query: {}", e))?;
    current_offset_in_packet += qname_bytes_len;

    // Ensure there's enough data left for QTYPE and QCLASS (2 bytes each)
    if packet_bytes.len() < current_offset_in_packet + 4 {
        return Err("DNS packet too short after QNAME (missing QTYPE/QCLASS)".to_string());
    }
    let qtype = bytes_to_u16_be(&packet_bytes[current_offset_in_packet .. current_offset_in_packet + 2])?;
    current_offset_in_packet += 2;
    let qclass = bytes_to_u16_be(&packet_bytes[current_offset_in_packet .. current_offset_in_packet + 2])?;
    // current_offset_in_packet += 2; // Not needed for further parsing in this simple case

    if qclass != QCLASS_IN {
        // We only support Internet class queries.
        return Err(format!("Unsupported DNS query class: {}. Only QCLASS IN (1) is supported.", qclass));
    }

    Ok(DnsQueryInfo {
        transaction_id,
        question: DnsQuestion {
            qname: qname_str,
            qtype,
            qclass,
        },
        // client_flags: flags, // Could store this if needed
    })
}

/// Builds a DNS response packet based on the parsed query and configured data.
fn build_dns_response_packet(
    query_info: &DnsQueryInfo,
    // HashMap mapping: normalized_tag_string -> (IPv4Address, port_number)
    dns_data_map: &HashMap<String, (Ipv4Addr, u16)>,
) -> Vec<u8> {
    let mut response_bytes_vec: Vec<u8> = Vec::new();
    let mut answer_record_count: u16 = 0;
    let mut response_code = RCODE_NO_ERROR; // Assume success initially
    let mut answer_section_payload_bytes: Vec<u8> = Vec::new();

    // Normalize the queried name for lookup in our map (lowercase, strip trailing dot)
    let lookup_qname_key = query_info.question.qname
        .strip_suffix('.') // DNS FQDNs often end with a dot
        .unwrap_or(&query_info.question.qname)
        .to_lowercase(); // DNS names are case-insensitive

    if let Some((ip_address, port_number)) = dns_data_map.get(&lookup_qname_key) {
        // Name found in our data. Now check QTYPE.
        let qname_bytes_for_rr = format_name_for_dns_packet(&query_info.question.qname); // Use original QNAME from query for the RR
        let ttl_value: u32 = 60; // Time-To-Live for the record (e.g., 60 seconds)

        match query_info.question.qtype {
            QTYPE_A => {
                answer_record_count = 1;
                answer_section_payload_bytes.extend_from_slice(&qname_bytes_for_rr); // NAME
                answer_section_payload_bytes.extend_from_slice(&u16_to_bytes_be(QTYPE_A));  // TYPE
                answer_section_payload_bytes.extend_from_slice(&u16_to_bytes_be(QCLASS_IN)); // CLASS
                answer_section_payload_bytes.extend_from_slice(&u32_to_bytes_be(ttl_value));   // TTL
                answer_section_payload_bytes.extend_from_slice(&u16_to_bytes_be(4));       // RDLENGTH (4 bytes for an IPv4 address)
                answer_section_payload_bytes.extend_from_slice(&ip_address.octets());      // RDATA (the IP address bytes)
            }
            QTYPE_TXT => {
                let txt_record_data_string = format!("{}:{}", ip_address, port_number);
                // A single character-string in a TXT RDATA can be max 255 bytes long.
                if txt_record_data_string.len() > 255 {
                    // If data is too long, we can't form a valid single-string TXT record.
                    // A more complex server might split it into multiple character-strings.
                    // For simplicity, we'll respond as if the type isn't implemented or an error.
                    answer_record_count = 0;
                    response_code = RCODE_SERVER_FAILURE; // Or RCODE_NOT_IMPLEMENTED
                } else {
                    answer_record_count = 1;
                    answer_section_payload_bytes.extend_from_slice(&qname_bytes_for_rr);    // NAME
                    answer_section_payload_bytes.extend_from_slice(&u16_to_bytes_be(QTYPE_TXT)); // TYPE
                    answer_section_payload_bytes.extend_from_slice(&u16_to_bytes_be(QCLASS_IN));// CLASS
                    answer_section_payload_bytes.extend_from_slice(&u32_to_bytes_be(ttl_value));  // TTL
                    
                    let txt_payload_as_bytes = txt_record_data_string.as_bytes();
                    // RDATA for TXT: one or more <character-string>, where <character-string> is <1_byte_length><characters>
                    let rdata_length_for_txt = 1 + txt_payload_as_bytes.len(); // 1 byte for string length + string bytes
                    answer_section_payload_bytes.extend_from_slice(&u16_to_bytes_be(rdata_length_for_txt as u16)); // RDLENGTH
                    answer_section_payload_bytes.push(txt_payload_as_bytes.len() as u8); // The <1_byte_length>
                    answer_section_payload_bytes.extend_from_slice(txt_payload_as_bytes);   // The <characters>
                }
            }
            _ => {
                // Queried name exists, but for a type we don't serve (e.g., AAAA, MX).
                // RFC 2308 (sec 2.2, 7.1) suggests responding with NOERROR and ANCOUNT=0 for known names but unsupported types.
                answer_record_count = 0;
                response_code = RCODE_NO_ERROR; // Not RCODE_NOT_IMPLEMENTED, to allow negative caching for this QNAME/QTYPE.
            }
        }
    } else {
        // Name not found in our configured data.
        response_code = RCODE_NXDOMAIN;
    }

    // Construct the DNS Header (12 bytes)
    response_bytes_vec.extend_from_slice(&u16_to_bytes_be(query_info.transaction_id)); // Transaction ID
    let response_flags = FLAG_QR_RESPONSE | FLAG_AA | (response_code & 0x000F); // QR=1, AA=1, RCODE
    response_bytes_vec.extend_from_slice(&u16_to_bytes_be(response_flags));
    response_bytes_vec.extend_from_slice(&u16_to_bytes_be(1)); // QDCOUNT (Question Count) = 1 (echoing the question)
    response_bytes_vec.extend_from_slice(&u16_to_bytes_be(answer_record_count)); // ANCOUNT (Answer Record Count)
    response_bytes_vec.extend_from_slice(&u16_to_bytes_be(0)); // NSCOUNT (Authority Record Count) = 0
    response_bytes_vec.extend_from_slice(&u16_to_bytes_be(0)); // ARCOUNT (Additional Record Count) = 0

    // Append Question Section (echoed from the query)
    let qname_bytes_original_query = format_name_for_dns_packet(&query_info.question.qname);
    response_bytes_vec.extend_from_slice(&qname_bytes_original_query);
    response_bytes_vec.extend_from_slice(&u16_to_bytes_be(query_info.question.qtype));
    response_bytes_vec.extend_from_slice(&u16_to_bytes_be(query_info.question.qclass));

    // Append Answer Section (if any records were added)
    response_bytes_vec.extend(answer_section_payload_bytes);

    response_bytes_vec // Return the complete response packet
}


// ---------------
// DNS Server Logic
// ---------------

/// Starts the UDP DNS server.
fn start_dns_server(config_data_from_protobuf: Vec<ExtractedInfo>) -> std::io::Result<()> {
    // Prepare a map for efficient DNS record lookup: tag_string -> (IpAddr, Port)
    let mut dns_records_map: HashMap<String, (Ipv4Addr, u16)> = HashMap::new();

    for config_item in config_data_from_protobuf {
        let ip_addr_obj = match config_item.ip.parse::<Ipv4Addr>() {
            Ok(ip) => ip,
            Err(e) => {
                eprintln!(
                    "Invalid IP address '{}' found for tags {:?}: {}. Skipping this entry.",
                    config_item.ip, config_item.tags, e
                );
                continue; // Skip this problematic entry
            }
        };
        let port_number_u16 = config_item.port as u16; // DNS SRV records use u16 for port. For TXT, it's part of string.

        for tag_string_from_config in config_item.tags {
            // Normalize the tag for use as a HashMap key (DNS is case-insensitive, strip trailing dot).
            let normalized_dns_key = tag_string_from_config
                .strip_suffix('.')
                .unwrap_or(&tag_string_from_config)
                .to_lowercase();
            
            if dns_records_map.contains_key(&normalized_dns_key) {
                // Log a warning if a tag is being redefined. The last definition will take precedence.
                println!(
                    "Warning: DNS tag '{}' is being redefined. The latest configuration for this tag will be used.",
                    normalized_dns_key
                );
            }
            dns_records_map.insert(normalized_dns_key, (ip_addr_obj, port_number_u16));
        }
    }

    if dns_records_map.is_empty() {
        println!("No valid DNS records configured after processing the protobuf file. The DNS server will start but resolve no names.");
    } else {
        println!("DNS server will serve the following records:");
        for (tag_key, (ip_val, port_val)) in &dns_records_map {
            println!("  Tag: '{}' -> A: {}, TXT: {}:{}", tag_key, ip_val, ip_val, port_val);
        }
    }

    let listen_address = "0.0.0.0:53"; // Listen on all interfaces, UDP port 53
    let udp_socket = UdpSocket::bind(listen_address)?; // This may require root/administrator privileges
    println!("DNS server listening on {}", listen_address);

    // Buffer for receiving incoming UDP packets. DNS over UDP is typically limited to 512 bytes
    // unless EDNS is used (which this server does not implement).
    let mut incoming_packet_buffer = [0u8; 512];

    loop { // Main server loop: receive query, process, send response
        match udp_socket.recv_from(&mut incoming_packet_buffer) {
            Ok((number_of_bytes_received, client_source_address)) => {
                let received_dns_packet_slice = &incoming_packet_buffer[..number_of_bytes_received];
                
                // Uncomment for verbose logging of raw packets:
                // println!("Received DNS packet from {}: {:02X?}", client_source_address, received_dns_packet_slice);

                match parse_dns_query_packet(received_dns_packet_slice) {
                    Ok(parsed_dns_query) => {
                        // Uncomment for verbose logging of parsed queries:
                        // println!("Parsed DNS query from {}: {:?}", client_source_address, parsed_dns_query.question);
                        
                        let response_packet_bytes = build_dns_response_packet(&parsed_dns_query, &dns_records_map);
                        
                        // Uncomment for verbose logging of raw response packets:
                        // println!("Sending DNS response to {}: {:02X?}", client_source_address, response_packet_bytes);
                        
                        if let Err(e) = udp_socket.send_to(&response_packet_bytes, client_source_address) {
                            eprintln!("Error sending DNS response to {}: {}", client_source_address, e);
                        }
                    }
                    Err(e) => {
                        // Log errors during query parsing. A more robust server might try to send
                        // a FORMERR DNS response if it can at least parse the Transaction ID.
                        eprintln!(
                            "Error parsing DNS query from {}: {}. Raw packet: {:02X?}",
                            client_source_address, e, received_dns_packet_slice
                        );
                    }
                }
            }
            Err(e) => {
                // Errors on recv_from could be network issues or socket errors.
                eprintln!("Error receiving UDP packet: {}", e);
                // Depending on the error, might need to decide if it's fatal or recoverable.
                // For a simple server, we'll just log and continue.
            }
        }
    }
    // The server loop is infinite, so Ok(()) would not normally be reached here.
    // If the loop could terminate, `Ok(())` would be appropriate.
}


// ---------------
// Main Application Entry Point
// ---------------
pub fn main() {
    // --- Part 1: Read and Parse the Protobuf Configuration File ---
    let config_file_path_str = "/__config__"; // Standard path
    let config_file_path = Path::new(config_file_path_str); 
    
    let mut config_file_bytes = Vec::new();
    match File::open(config_file_path) {
        Ok(mut file_handle) => {
            if let Err(e) = file_handle.read_to_end(&mut config_file_bytes) {
                eprintln!(
                    "Error reading content from configuration file '{}': {}",
                    config_file_path.display(), e
                );
                std::process::exit(1); // Exit on critical error
            }
        }
        Err(e) => {
            eprintln!(
                "Error opening configuration file '{}': {}",
                config_file_path.display(), e
            );
            if e.kind() == ErrorKind::NotFound {
                 eprintln!(
                    "Please ensure the configuration file exists at the specified path."
                );
            }
            std::process::exit(1); // Exit on critical error
        }
    }

    if config_file_bytes.is_empty() {
        println!(
            "Configuration file '{}' is empty. The DNS server will start with no custom records.",
            config_file_path.display()
        );
        // Allow proceeding with empty config; parse_configuration_file_proto should handle it (return Ok(Vec::new())).
    }

    let extracted_network_info_list = match parse_configuration_file_proto(&config_file_bytes) {
        Ok(info_items) => {
            if info_items.is_empty() && !config_file_bytes.is_empty() {
                println!(
                    "No relevant network information (tags, IP, port) was extracted from the non-empty configuration file."
                );
            } else if !info_items.is_empty() {
                println!("Successfully extracted network information from configuration:");
                for info_group_item in &info_items {
                    println!(
                        "  Tags: {:?}, IP: {}, Port: {}",
                        info_group_item.tags, info_group_item.ip, info_group_item.port
                    );
                }
            }
            info_items // Pass the (possibly empty) list to the DNS server
        }
        Err(e) => {
            eprintln!("Error parsing the Protobuf configuration file: {}", e);
            std::process::exit(1); // Exit on critical parsing error
        }
    };

    // --- Part 2: Start the DNS Server with the Extracted Information ---
    if let Err(e) = start_dns_server(extracted_network_info_list) {
        eprintln!("DNS server encountered a fatal error: {}", e);
        std::process::exit(1); // Exit on critical server error
    }
}
