use anyhow::{anyhow, bail, Context, Result};
use bw_app_gate::{socket_path, Item, Request, Response};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::Command;
use zeroize::Zeroizing;

const USAGE: &str = "\
Usage: bw-app-gate get NAME...
       bw-app-gate type [--keyboard] NAME
       bw-app-gate list ITEM
       bw-app-gate search WORD...
       bw-app-gate mail-otp --to ADDRESS [--from DOMAIN]... [--print] [--keyboard] [--wait SECS]
       bw-app-gate forget [NAME...]
       bw-app-gate login

NAME is an item name, meaning its login password, or ITEM/FIELD where FIELD is
username, notes, totp or a custom field name. Escape '/' and '\\' in names
with a backslash.

get: one NAME prints the value exactly, with no trailing newline. Several
print a JSON object from NAME to value.

type: types the value into the focused text field of the focused window and
prints where it went, never the value. A login password is only typed into a
field that says it is a password field. --keyboard types key by key through a
virtual keyboard, for apps whose fields are not reported to input methods
(Electron apps). It checks the window, not the field, and only types printable
ASCII. Approving a type does not allow a get.

list: prints the gate name ITEM[username] of every item named ITEM, one per
line, followed by a tab, its URIs separated by spaces, a tab and its folder.

search: the same for every item where each WORD appears, ignoring case, in its
name, a URI, the username, the folder, a custom field name or a text custom
field's value. Notes and hidden fields are not searched.

The first list or search asks for the master password; after that, the same
application's queries only need Approve for 15 minutes of idle time.

mail-otp: waits for a one-time code in the Gmail inbox of ADDRESS and types
it into the focused field, like type. ADDRESS is the username of the Google
login item that holds the inbox's app password. --print prints it instead. A message counts when
Gmail saw a passing DKIM signature aligned with its From domain, and when it
arrived at most 2 minutes before the request. --from DOMAIN, repeatable, takes
the newest such message from DOMAIN or its subdomains; without --from exactly
one message with a code may arrive. The code is the one number next to a word
like 'code'; several numbers are an error, not a guess. --wait defaults to 120
seconds, at most 600. Prints the sender domain. Asks for the master password
every time.

forget: drops the calling application's approval for each NAME, or for all
of its secrets when no NAME is given, so the next get prompts again. Other
applications keep theirs.

login: runs `rbw login`, then `rbw lock` whatever the login did. rbw login
leaves rbw-agent unlocked, and an unlocked rbw-agent gives any secret to any
process of this user, around the gate.";

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

/// Zeroes any values in a response that was not the expected kind, then fails.
fn unexpected(response: Response, command: &str) -> Result<()> {
    match response {
        Response::Secrets(mut values) => values.iter_mut().for_each(zeroize::Zeroize::zeroize),
        Response::MailCode {
            code: Some(mut code),
            ..
        } => zeroize::Zeroize::zeroize(&mut code),
        _ => {}
    }
    bail!("unexpected response to {command}")
}

fn forget(names: &[String]) -> Result<()> {
    match request(&Request::Forget(names.to_vec()))? {
        Response::Forgot(count) => {
            println!("forgot {count} secret{}", if count == 1 { "" } else { "s" });
            Ok(())
        }
        response => unexpected(response, "forget"),
    }
}

fn type_secret(name: &str, keyboard: bool) -> Result<()> {
    match request(&Request::Type {
        name: name.to_string(),
        keyboard,
    })? {
        Response::Typed(outcome) => {
            println!("{outcome}");
            Ok(())
        }
        response => unexpected(response, "type"),
    }
}

fn print_items(query: &Request) -> Result<()> {
    let items: Vec<Item> = match request(query)? {
        Response::Items(items) => items,
        response => return unexpected(response, "list or search"),
    };
    if items.is_empty() {
        bail!("no items found; run `rbw sync` if one is new");
    }
    for item in items {
        println!(
            "{}\t{}\t{}",
            item.name,
            item.uris.join(" "),
            item.folder.unwrap_or_default()
        );
    }
    Ok(())
}

fn mail_otp(args: &[String]) -> Result<()> {
    let mut to = None;
    let mut from = Vec::new();
    let mut print = false;
    let mut keyboard = false;
    let mut wait_secs = bw_app_gate::mail::DEFAULT_WAIT.as_secs();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--from" => from.push(
                args.next()
                    .ok_or_else(|| anyhow!("--from needs a domain"))?
                    .to_ascii_lowercase(),
            ),
            "--to" => {
                to = Some(
                    args.next()
                        .ok_or_else(|| anyhow!("--to needs a mail address"))?
                        .clone(),
                )
            }
            "--print" => print = true,
            "--keyboard" => keyboard = true,
            "--wait" => {
                wait_secs = args
                    .next()
                    .ok_or_else(|| anyhow!("--wait needs a number of seconds"))?
                    .parse()
                    .context("--wait needs a number of seconds")?
            }
            _ => bail!("unknown mail-otp argument '{arg}'\n\n{USAGE}"),
        }
    }
    let to = to.ok_or_else(|| anyhow!("mail-otp needs --to ADDRESS, the inbox to read"))?;
    if print && keyboard {
        bail!("--print and --keyboard do not go together");
    }
    match request(&Request::MailOtp {
        to,
        from,
        print,
        keyboard,
        wait_secs,
    })? {
        Response::MailCode {
            sender,
            code: Some(code),
            ..
        } => {
            let code = Zeroizing::new(code);
            eprintln!("code from {sender}");
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(code.as_bytes())?;
            stdout.flush()?;
            Ok(())
        }
        Response::MailCode {
            sender,
            typed_into: Some(window),
            ..
        } => {
            println!("typed a code from {sender} into {window}");
            Ok(())
        }
        response => unexpected(response, "mail-otp"),
    }
}

extern "C" fn ignore_signal(_: libc::c_int) {}

fn login() -> Result<()> {
    // A handler, not SIG_IGN: exec resets handled signals to their default, so rbw login still stops on Ctrl-C, while this process lives on to lock.
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
        unsafe { libc::signal(signal, ignore_signal as *const () as libc::sighandler_t) };
    }
    let login = Command::new("rbw").arg("login").status();
    let lock = Command::new("rbw")
        .arg("lock")
        .status()
        .context("failed to run rbw lock; run it now, rbw-agent may be unlocked")?;
    if !lock.success() {
        bail!("rbw lock failed ({lock}); run it now, rbw-agent may be unlocked");
    }
    eprintln!("rbw-agent locked");
    let login = login.context("failed to run rbw login")?;
    if !login.success() {
        bail!("rbw login failed ({login})");
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.split_first() {
        Some((command, names)) if command == "get" && !names.is_empty() => get(names),
        Some((command, names)) if command == "forget" => forget(names),
        Some((command, [name])) if command == "type" => type_secret(name, false),
        Some((command, [flag, name])) if command == "type" && flag == "--keyboard" => {
            type_secret(name, true)
        }
        Some((command, [item])) if command == "list" => print_items(&Request::List(item.clone())),
        Some((command, words)) if command == "search" && !words.is_empty() => {
            print_items(&Request::Search(words.join(" ")))
        }
        Some((command, args)) if command == "mail-otp" => mail_otp(args),
        Some((command, [])) if command == "login" => login(),
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
