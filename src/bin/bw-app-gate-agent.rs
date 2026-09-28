use anyhow::{anyhow, bail, Context, Result};
use bw_app_gate::cache::{Cache, Grant};
use bw_app_gate::process::{self, app_label, tilde, Requester};
use bw_app_gate::prompt::Approval;
use bw_app_gate::secret_ref::{Field, SecretRef};
use bw_app_gate::typing::{self, Desktop, Window};
use bw_app_gate::vault::{self, UnlockError, UnlockedVault};
use bw_app_gate::{
    socket_path, Item, Request, Response, MAX_REQUEST_BYTES, MAX_SECRETS_PER_REQUEST,
};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

const USAGE: &str = "Usage: bw-app-gate-agent [--pinentry PROGRAM]";

/// Wrong master passwords accepted in one prompt before the request fails.
const PASSWORD_ATTEMPTS: usize = 3;

const READ_TIMEOUT: Duration = Duration::from_secs(5);
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

struct Agent {
    pinentry: String,
    cache: Mutex<Cache>,
    /// Held while a prompt is open, so only one dialog shows at a time. The cache lock is not held during the prompt.
    prompt: Mutex<()>,
    /// Held while a `type` runs, so two values are never typed at once.
    typing: Mutex<()>,
}

/// Seconds on `CLOCK_BOOTTIME`, which unlike `Instant` keeps counting through suspend, so an idle timer also runs out while the machine sleeps.
fn now() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let result = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) };
    assert_eq!(result, 0, "CLOCK_BOOTTIME is unavailable");
    time.tv_sec as u64
}

impl Agent {
    /// Returns the values in request order, and the secrets that needed approval, empty when all came from the cache. `wants` turns the secrets that need approval into the prompt's lines.
    async fn serve(
        &self,
        requester: &Requester,
        secrets: &[SecretRef],
        grant: Grant,
        wants: impl Fn(&[SecretRef]) -> Vec<String>,
    ) -> Result<(Vec<Zeroizing<String>>, Vec<SecretRef>)> {
        let instance = requester.instance;

        if self
            .cache
            .lock()
            .await
            .missing(instance, secrets, grant, now())
            .is_empty()
        {
            return Ok((
                self.read_cached(requester, secrets, grant).await?,
                Vec::new(),
            ));
        }

        let _prompt = self.prompt.lock().await;
        // Another request from the same instance may have filled the cache while this one waited for the prompt lock.
        let missing = self
            .cache
            .lock()
            .await
            .missing(instance, secrets, grant, now());
        if !missing.is_empty() {
            let fetch_missing = missing.clone();
            let values = self
                .approve(requester, wants(&missing), move |vault| {
                    vault.fetch(&fetch_missing)
                })
                .await?;
            let mut cache = self.cache.lock().await;
            let now = now();
            for (secret, value) in missing.iter().cloned().zip(values) {
                cache.insert(instance, secret, value, grant, now);
            }
        }
        Ok((self.read_cached(requester, secrets, grant).await?, missing))
    }

    /// Shows the prompt for `wants` and runs `with_vault` on the vault the password unlocks. The caller holds the prompt lock.
    async fn approve<T: Send + 'static>(
        &self,
        requester: &Requester,
        wants: Vec<String>,
        with_vault: impl FnOnce(&UnlockedVault) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let pinentry = self.pinentry.clone();
        let app = app_label(&requester.exe);
        let pid = requester.instance.pid;
        let cwd = requester.cwd.as_deref().map(tilde);
        let parent = requester.parent.as_deref().map(app_label);
        tokio::task::spawn_blocking(move || {
            let approval = Approval {
                pinentry: &pinentry,
                app: &app,
                pid,
                cwd: cwd.as_deref(),
                parent: parent.as_deref(),
                wants: &wants,
            };
            with_vault(&unlock(&approval)?)
        })
        .await?
    }

    async fn get(
        &self,
        requester: &Requester,
        names: &[String],
    ) -> Result<(Vec<Zeroizing<String>>, Vec<SecretRef>)> {
        if names.is_empty() || names.len() > MAX_SECRETS_PER_REQUEST {
            bail!("a request must name between 1 and {MAX_SECRETS_PER_REQUEST} secrets");
        }
        let secrets = names
            .iter()
            .map(|name| SecretRef::parse(name))
            .collect::<Result<Vec<_>>>()?;
        self.serve(requester, &secrets, Grant::Read, |missing| {
            missing.iter().map(ToString::to_string).collect()
        })
        .await
    }

    /// Types one secret into the focused field. Returns the window it went to and whether it needed approval.
    async fn type_secret(
        &self,
        requester: &Requester,
        name: &str,
        keyboard: bool,
    ) -> Result<(Window, bool)> {
        let secret = SecretRef::parse(name)?;
        let _typing = self.typing.lock().await;
        let target = tokio::task::spawn_blocking(|| {
            Desktop::connect()?
                .focused()
                .ok_or_else(|| anyhow!("no window has focus"))
        })
        .await??;
        let how = if keyboard {
            " with the keyboard, no field check"
        } else {
            ""
        };
        let (mut values, approved) = self
            .serve(
                requester,
                std::slice::from_ref(&secret),
                Grant::Type,
                |_| vec![format!("type {secret} into {target}{how}")],
            )
            .await?;
        let value = values.pop().expect("one secret was requested");
        let password = secret.field == Field::Password;
        let typed_into = target.clone();
        tokio::task::spawn_blocking(move || {
            let mut desktop = Desktop::connect()?;
            desktop.wait_for_focus(&typed_into, typing::FOCUS_RETURN)?;
            if keyboard {
                desktop.press_keys(&typed_into, value.as_bytes())
            } else {
                desktop.commit(&typed_into, &value, password)
            }
        })
        .await??;
        Ok((target, !approved.is_empty()))
    }

    /// `list` and `search`: metadata only, approved per request and never cached.
    async fn find_items(&self, requester: &Requester, request: &Request) -> Result<Vec<Item>> {
        let _prompt = self.prompt.lock().await;
        match request {
            Request::List(item) => {
                let item = item.clone();
                self.approve(
                    requester,
                    vec![format!("the usernames of the items named '{item}'")],
                    move |vault| Ok(vault.list(&item)),
                )
                .await
            }
            Request::Search(query) => {
                let query = query.clone();
                self.approve(
                    requester,
                    vec![format!(
                        "a search of names, URIs, usernames, folders and text fields for '{query}'"
                    )],
                    move |vault| vault.search(&query),
                )
                .await
            }
            _ => unreachable!("find_items only serves list and search"),
        }
    }

    /// Drops the requester's own entries: the named ones, or all when `names` is empty. No prompt, since it only takes access away.
    async fn forget(&self, requester: &Requester, names: &[String]) -> Result<usize> {
        if names.len() > MAX_SECRETS_PER_REQUEST {
            bail!("a request may name at most {MAX_SECRETS_PER_REQUEST} secrets");
        }
        let secrets = names
            .iter()
            .map(|name| SecretRef::parse(name))
            .collect::<Result<Vec<_>>>()?;
        Ok(self
            .cache
            .lock()
            .await
            .forget(requester.instance, &secrets, now()))
    }

    /// Serves one request and writes its outcome to the audit log, which is stderr and so the journal. Names only, never values.
    async fn handle(&self, requester: &Requester, request: Request) -> Response {
        let who = describe(requester);
        match request {
            Request::Get(names) => match self.get(requester, &names).await {
                Ok((values, approved)) => {
                    let how = if approved.is_empty() {
                        "all cached".to_string()
                    } else {
                        format!("approved {}", join(&approved))
                    };
                    eprintln!("{who} got {} ({how})", join(&names));
                    Response::Secrets(values.iter().map(|value| value.to_string()).collect())
                }
                Err(error) => {
                    eprintln!("{who} was refused {}: {error:#}", join(&names));
                    Response::Error(format!("{error:#}"))
                }
            },
            Request::Forget(names) => match self.forget(requester, &names).await {
                Ok(count) => {
                    let which = if names.is_empty() {
                        "all".to_string()
                    } else {
                        join(&names)
                    };
                    eprintln!("{who} forgot {which} ({count} cached)");
                    Response::Forgot(count)
                }
                Err(error) => {
                    eprintln!("{who} failed to forget {}: {error:#}", join(&names));
                    Response::Error(format!("{error:#}"))
                }
            },
            Request::Type { name, keyboard } => {
                match self.type_secret(requester, &name, keyboard).await {
                    Ok((window, approved)) => {
                        let how = if approved { "approved" } else { "cached" };
                        eprintln!("{who} typed {name} into {window} ({how})");
                        Response::Typed(format!("typed {name} into {window}"))
                    }
                    Err(error) => {
                        eprintln!("{who} was refused typing {name}: {error:#}");
                        Response::Error(format!("{error:#}"))
                    }
                }
            }
            Request::List(_) | Request::Search(_) => {
                let what = match &request {
                    Request::List(item) => format!("listed '{item}'"),
                    Request::Search(query) => format!("searched for '{query}'"),
                    _ => unreachable!(),
                };
                match self.find_items(requester, &request).await {
                    Ok(items) => {
                        eprintln!("{who} {what} ({} items)", items.len());
                        Response::Items(items)
                    }
                    Err(error) => {
                        eprintln!("{who} was refused, {what}: {error:#}");
                        Response::Error(format!("{error:#}"))
                    }
                }
            }
        }
    }

    async fn read_cached(
        &self,
        requester: &Requester,
        secrets: &[SecretRef],
        grant: Grant,
    ) -> Result<Vec<Zeroizing<String>>> {
        let mut cache = self.cache.lock().await;
        let now = now();
        secrets
            .iter()
            .map(|secret| {
                cache
                    .get(requester.instance, secret, grant, now)
                    .ok_or_else(|| {
                        anyhow!("'{secret}' expired while the request was waiting; retry")
                    })?
                    .reveal()
            })
            .collect()
    }
}

/// The requester as the audit log names it: `claude-code/.claude-wrapped (pid 42, in ~/src)`.
fn describe(requester: &Requester) -> String {
    let cwd = requester
        .cwd
        .as_deref()
        .map(|cwd| format!(", in {}", tilde(cwd)))
        .unwrap_or_default();
    format!(
        "{} (pid {}{cwd})",
        app_label(&requester.exe),
        requester.instance.pid
    )
}

fn join(names: &[impl std::fmt::Display]) -> String {
    names
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Shows the prompt and unlocks the vault with the password. Blocking: runs pinentry and the KDF.
fn unlock(approval: &Approval) -> Result<UnlockedVault> {
    let mut error = None;
    for _ in 0..PASSWORD_ATTEMPTS {
        let password = approval
            .ask(error)?
            .ok_or_else(|| anyhow!("denied by the user"))?;
        match vault::unlock(&password) {
            Ok(vault) => return Ok(vault),
            Err(UnlockError::WrongPassword) => error = Some("Wrong master password"),
            Err(UnlockError::Other(error)) => return Err(error),
        }
    }
    bail!("wrong master password {PASSWORD_ATTEMPTS} times")
}

async fn read_request(stream: &mut UnixStream) -> Result<Request> {
    let mut line = Vec::new();
    let reader = BufReader::new(stream).take(MAX_REQUEST_BYTES as u64 + 1);
    tokio::pin!(reader);
    tokio::time::timeout(READ_TIMEOUT, reader.read_until(b'\n', &mut line))
        .await
        .context("timed out reading the request")??;
    if line.len() > MAX_REQUEST_BYTES {
        bail!("request is longer than {MAX_REQUEST_BYTES} bytes");
    }
    serde_json::from_slice(&line).context("invalid request")
}

async fn handle_connection(agent: &Agent, mut stream: UnixStream) -> Result<()> {
    let credentials = stream.peer_cred()?;
    if credentials.uid() != unsafe { libc::getuid() } {
        bail!("connection from another user (uid {})", credentials.uid());
    }
    let peer_pid = credentials
        .pid()
        .ok_or_else(|| anyhow!("peer PID is unavailable"))?;

    let response = match process::find_requester(peer_pid as u32) {
        Ok(requester) => match read_request(&mut stream).await {
            Ok(request) => agent.handle(&requester, request).await,
            Err(error) => {
                eprintln!("{} sent a bad request: {error:#}", describe(&requester));
                Response::Error(format!("{error:#}"))
            }
        },
        Err(error) => {
            eprintln!("refused process {peer_pid}, requester unknown: {error:#}");
            Response::Error(format!(
                "could not identify the requesting application: {error:#}"
            ))
        }
    };

    let mut line = Zeroizing::new(serde_json::to_vec(&response)?);
    if let Response::Secrets(mut values) = response {
        values.iter_mut().for_each(zeroize::Zeroize::zeroize);
    }
    line.push(b'\n');
    stream.write_all(&line).await?;
    Ok(())
}

fn disable_tracing() -> Result<()> {
    const PR_SET_DUMPABLE: i32 = 4;
    if unsafe { libc::prctl(PR_SET_DUMPABLE, 0) } != 0 {
        bail!(
            "failed to disable debugger attachment: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

/// Binds the socket, refusing to take it over from an agent that is still running.
fn bind_socket() -> Result<UnixListener> {
    let path = socket_path();
    if std::os::unix::net::UnixStream::connect(&path).is_ok() {
        bail!(
            "another bw-app-gate-agent is already listening on {}",
            path.display()
        );
    }
    match std::fs::remove_file(&path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
        _ => {}
    }
    // umask makes the socket 0600 from the moment it exists, with no window before set_permissions.
    let old_umask = unsafe { libc::umask(0o077) };
    let listener = UnixListener::bind(&path);
    unsafe { libc::umask(old_umask) };
    let listener = listener.with_context(|| format!("failed to bind {}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

fn parse_args() -> Result<String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => Ok("pinentry".to_string()),
        [flag, program] if flag == "--pinentry" => Ok(program.clone()),
        [flag] if flag == "-h" || flag == "--help" => {
            println!("{USAGE}");
            std::process::exit(0);
        }
        _ => Err(anyhow!("{USAGE}")),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    disable_tracing()?;
    let pinentry = parse_args()?;
    let listener = bind_socket()?;
    let agent = Arc::new(Agent {
        pinentry,
        cache: Mutex::new(Cache::default()),
        prompt: Mutex::new(()),
        typing: Mutex::new(()),
    });

    let sweeper = agent.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(SWEEP_INTERVAL);
        loop {
            interval.tick().await;
            sweeper.cache.lock().await.sweep(now(), process::is_alive);
        }
    });

    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    eprintln!("bw-app-gate-agent listening on {}", socket_path().display());
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let agent = agent.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_connection(&agent, stream).await {
                        eprintln!("request failed: {error:#}");
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => break,
            _ = terminate.recv() => break,
        }
    }
    let _ = std::fs::remove_file(socket_path());
    Ok(())
}
