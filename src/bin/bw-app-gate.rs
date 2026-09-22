use anyhow::{anyhow, bail, Context, Result};
use bw_app_gate::{socket_path, Request, Response};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use zeroize::Zeroizing;

const USAGE: &str = "\
Usage: bw-app-gate get NAME...
       bw-app-gate forget [NAME...]

NAME is an item name, meaning its login password, or ITEM/FIELD where FIELD is
username, notes, totp or a custom field name. Escape '/' and '\\' in names
with a backslash.

get: one NAME prints the value exactly, with no trailing newline. Several
print a JSON object from NAME to value.

forget: drops the calling application's approval for each NAME, or for all
of its secrets when no NAME is given, so the next get prompts again. Other
applications keep theirs.";

fn request(request: &Request) -> Result<Response> {
    let mut stream = UnixStream::connect(socket_path()).with_context(|| {
        format!(
            "failed to connect to {}; is bw-app-gate-agent running?",
            socket_path().display()
        )
    })?;
    let mut line = serde_json::to_vec(request)?;
    line.push(b'\n');
    stream.write_all(&line)?;

    let mut line = Zeroizing::new(String::new());
    BufReader::new(stream).read_line(&mut line)?;
    match serde_json::from_str::<Response>(&line)? {
        Response::Error(error) => Err(anyhow!(error)),
        response => Ok(response),
    }
}

fn get(names: &[String]) -> Result<()> {
    let values: Vec<Zeroizing<String>> = match request(&Request::Get(names.to_vec()))? {
        Response::Secrets(values) => values.into_iter().map(Zeroizing::new).collect(),
        _ => bail!("unexpected response to get"),
    };
    let mut stdout = std::io::stdout().lock();
    if let [value] = values.as_slice() {
        stdout.write_all(value.as_bytes())?;
    } else {
        let object: BTreeMap<&str, &str> = names
            .iter()
            .map(String::as_str)
            .zip(values.iter().map(|value| value.as_str()))
            .collect();
        let mut json = Zeroizing::new(serde_json::to_vec(&object)?);
        json.push(b'\n');
        stdout.write_all(&json)?;
    }
    stdout.flush()?;
    Ok(())
}

fn forget(names: &[String]) -> Result<()> {
    match request(&Request::Forget(names.to_vec()))? {
        Response::Forgot(count) => {
            println!("forgot {count} secret{}", if count == 1 { "" } else { "s" });
            Ok(())
        }
        Response::Secrets(mut values) => {
            values.iter_mut().for_each(zeroize::Zeroize::zeroize);
            bail!("unexpected response to forget")
        }
        Response::Error(error) => Err(anyhow!(error)),
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.split_first() {
        Some((command, names)) if command == "get" && !names.is_empty() => get(names),
        Some((command, names)) if command == "forget" => forget(names),
        Some((flag, [])) if flag == "-h" || flag == "--help" => {
            println!("{USAGE}");
            Ok(())
        }
        _ => {
            eprintln!("{USAGE}");
            std::process::exit(2);
        }
    }
}
