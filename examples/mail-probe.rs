//! Live check of `mail` without the agent: waits for a code and prints its sender and length, never the code.
//! The app password is read from stdin, so it stays out of argv:
//! `bw-broker get 'google.com[you@gmail.com]/bw-broker-imap' | cargo run --example mail-probe -- you@gmail.com [--from DOMAIN]... [--wait SECS]`
use anyhow::{anyhow, Context};
use bw_broker::mail::{self, Login};
use std::io::Read;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let user = args
        .next()
        .ok_or_else(|| anyhow!("usage: mail-probe USER [--from DOMAIN]... [--wait SECS]"))?;
    let mut from = Vec::new();
    let mut wait = mail::DEFAULT_WAIT;
    while let Some(flag) = args.next() {
        let value = args.next().ok_or_else(|| anyhow!("{flag} needs a value"))?;
        match flag.as_str() {
            "--from" => from.push(value),
            "--wait" => wait = Duration::from_secs(value.parse().context("--wait")?),
            _ => anyhow::bail!("unknown argument {flag}"),
        }
    }
    let mut password = Zeroizing::new(String::new());
    std::io::stdin().read_to_string(&mut password)?;
    let login = Login {
        user: Zeroizing::new(user),
        password: Zeroizing::new(password.trim().to_string()),
    };
    let since = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64
        - mail::GRACE.as_secs() as i64;
    let found = mail::wait_for_code(&login, &from, since, Instant::now() + wait).await?;
    println!("code from {}, {} digits", found.sender, found.code.len());
    Ok(())
}
