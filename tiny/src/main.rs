use std::collections::BTreeMap;
use std::fs;
use std::os::unix::ffi::OsStrExt;

use rand::seq::SliceRandom;
use warp::Filter;

// The environment variables this service declares (`envs` in its service.json). The
// orchestrator passes some of them and leaves one unset, and /env reports what arrived,
// through both paths the node uses: the process environment, and `__config__`.
const DECLARED_ENVS: [&str; 3] = ["DEMO_ENV_GIVEN", "DEMO_ENV_EMPTY", "DEMO_ENV_UNSET"];
const CONFIG_FILE: &str = "/__config__";

// ---------------------------------------------------------------------------
// A minimal protobuf reader, for ConfigurationFile.config.environment_variables:
//   ConfigurationFile { Configuration config = 2; }
//   Configuration     { repeated BytesKeyValue environment_variables = 1; }
//   BytesKeyValue     { string key = 1; optional bytes value = 2; }
// ---------------------------------------------------------------------------
fn read_varint(buf: &mut &[u8]) -> Option<u64> {
    let mut value: u64 = 0;
    for i in 0..10 {
        let byte = *buf.get(i)?;
        value |= ((byte & 0x7f) as u64) << (7 * i);
        if byte & 0x80 == 0 {
            *buf = &buf[i + 1..];
            return Some(value);
        }
    }
    None
}

/// The length-delimited fields of one message, as (field number, payload). Fields of
/// the other wire types are skipped.
fn len_fields(mut buf: &[u8]) -> Option<Vec<(u64, &[u8])>> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        let tag = read_varint(&mut buf)?;
        match tag & 7 {
            0 => {
                read_varint(&mut buf)?;
            }
            1 => buf = buf.get(8..)?,
            2 => {
                let len = read_varint(&mut buf)? as usize;
                let payload = buf.get(..len)?;
                buf = &buf[len..];
                out.push((tag >> 3, payload));
            }
            5 => buf = buf.get(4..)?,
            _ => return None,
        }
    }
    Some(out)
}

fn config_envs(file: &[u8]) -> Option<BTreeMap<String, Vec<u8>>> {
    let mut envs = BTreeMap::new();
    for (field, config) in len_fields(file)? {
        if field != 2 {
            continue;
        }
        for (field, entry) in len_fields(config)? {
            if field != 1 {
                continue;
            }
            let mut key = String::new();
            let mut value = Vec::new();
            for (field, payload) in len_fields(entry)? {
                match field {
                    1 => key = String::from_utf8_lossy(payload).into_owned(),
                    2 => value = payload.to_vec(),
                    _ => {}
                }
            }
            envs.insert(key, value);
        }
    }
    Some(envs)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// What this instance received for its declared variables. The values are hex, so
/// that the orchestrator compares the exact bytes. An absent variable is null.
fn env_report() -> String {
    let process: Vec<String> = DECLARED_ENVS
        .iter()
        .map(|name| match std::env::var_os(name) {
            Some(v) => format!("\"{}\":\"{}\"", name, hex(v.as_bytes())),
            None => format!("\"{}\":null", name),
        })
        .collect();
    let (readable, config) = match fs::read(CONFIG_FILE).ok().as_deref().map(config_envs) {
        Some(Some(envs)) => (
            true,
            envs.iter()
                .map(|(k, v)| format!("\"{}\":\"{}\"", json_escape(k), hex(v)))
                .collect::<Vec<_>>(),
        ),
        _ => (false, Vec::new()),
    };
    format!(
        "{{\"service\":\"tiny\",\"declared\":[{}],\"process_env\":{{{}}},\"config_readable\":{},\"config_env\":{{{}}}}}",
        DECLARED_ENVS.iter().map(|n| format!("\"{}\"", n)).collect::<Vec<_>>().join(","),
        process.join(","),
        readable,
        config.join(",")
    )
}

#[tokio::main]
async fn main() {
    // Define listas de adjetivos y nombres
    let adjectives = vec![
        "clever", "brave", "mystic", "stoic", "eager", "happy", "bold", "calm", "daring", "frosty",
        "furious", "gentle", "jolly", "keen", "lively", "proud", "quirky", "sharp", "silent", "vibrant",
    ];

    let names = vec![
        "einstein", "curie", "newton", "tesla", "lovelace", "darwin", "galileo", "copernicus", "fermat", "archimedes",
        "turing", "bohr", "kepler", "hawking", "pasteur", "heisenberg", "maxwell", "nash", "noether", "poincare",
    ];

    // Define la ruta que retorna un nombre al estilo Docker
    let random_name = warp::path::end().map(move || {
        // Genera un nombre aleatorio combinando un adjetivo y un nombre
        let mut rng = rand::thread_rng();
        let adjective = adjectives.choose(&mut rng).unwrap_or(&"mysterious");
        let name = names.choose(&mut rng).unwrap_or(&"unknown");

        // Retorna el nombre combinado
        format!("{}-{}", adjective, name)
    });

    // Identity endpoint — lets an orchestrator verify that the dependency it
    // requested (TINY) is the dependency that actually ran, via a fixed,
    // service-specific signature.
    let whoami = warp::path("whoami").map(|| {
        warp::reply::with_header(
            "{\"service\":\"tiny\",\"identity\":\"celaut-demo-tiny\",\"role\":\"random-name-generator\"}",
            "content-type", "application/json",
        )
    });

    // The declared environment variables, as this instance received them.
    let env = warp::path("env").and(warp::path::end()).map(|| {
        warp::reply::with_header(env_report(), "content-type", "application/json")
    });

    // Inicia el servidor en el puerto 3030
    let routes = whoami.or(env).or(random_name);
    warp::serve(routes).run(([0, 0, 0, 0], 3030)).await;
}
