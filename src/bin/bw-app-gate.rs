use anyhow::{anyhow, Result};
use bw_app_gate::{socket_path, GetSecretRequest, SecretResponse};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

async fn request_secret(secret_name: &str) -> Result<String> {
    let mut stream = UnixStream::connect(socket_path()).await?;
    let request = serde_json::to_string(&GetSecretRequest {
        secret_name: secret_name.to_string(),
    })?;
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(b"\n").await?;

    let (reader, _) = stream.into_split();
    let mut line = String::new();
    BufReader::new(reader).read_line(&mut line).await?;
    let response: SecretResponse = serde_json::from_str(&line)?;
    match (response.secret_value, response.error) {
        (Some(secret), None) => Ok(secret),
        (_, Some(error)) => Err(anyhow!(error)),
        _ => Err(anyhow!("daemon returned an invalid response")),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 || matches!(args[1].as_str(), "-h" | "--help") {
        eprintln!("Usage: bw-app-gate SECRET_NAME");
        std::process::exit(if args.len() == 2 { 0 } else { 1 });
    }
    println!("{}", request_secret(&args[1]).await?);
    Ok(())
}
