//! `mail-otp`: waits for a one-time code in the Gmail inbox, over IMAP.
//!
//! A message counts only when Gmail's own `Authentication-Results` header, the topmost one, has a passing DKIM signature from a domain aligned with the `From` domain. The code is the one number next to a word like "code"; anything else is a failure, not a guess. See the mail-otp section in `docs/decisions.md`.

use anyhow::{anyhow, bail, Context, Result};
use async_imap::types::Fetch;
use futures_util::TryStreamExt;
use mail_parser::{HeaderName, MessageParser};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

const HOST: &str = "imap.gmail.com";
const PORT: u16 = 993;
/// The authserv-id Gmail writes in the `Authentication-Results` header it adds on receipt.
const GMAIL_AUTHSERV_ID: &str = "mx.google.com";

/// How far before the request a message may have arrived and still count, because the code is often sent while the approval prompt is open.
pub const GRACE: Duration = Duration::from_secs(120);
pub const DEFAULT_WAIT: Duration = Duration::from_secs(120);
pub const MAX_WAIT: Duration = Duration::from_secs(600);
const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Per IMAP command, so a stalled connection fails instead of holding the request until the deadline and beyond.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Words a code sits next to, lowercase. Matched as substrings, so `kod` also covers `engångskod` and `verifieringskod`, except the short ones marked `true`, which must stand as their own word: "shopping" contains "pin".
const KEYWORDS: &[(&str, bool)] = &[
    ("code", false),
    ("kod", false),
    ("verif", false),
    ("one-time", false),
    ("bekräft", false),
    ("otp", true),
    ("pin", true),
];
/// Characters between a keyword and a code, counted from the end of the keyword forward, or from the code forward to the keyword.
const NEAR_AFTER: usize = 150;
const NEAR_BEFORE: usize = 50;

pub struct Login {
    pub user: Zeroizing<String>,
    pub password: Zeroizing<String>,
}

pub struct Found {
    /// The `From` domain, authenticated by an aligned DKIM signature.
    pub sender: String,
    pub code: Zeroizing<String>,
}

#[derive(Debug, PartialEq)]
enum Extracted {
    None,
    One(Zeroizing<String>),
    /// This many distinct codes sit next to keywords.
    Ambiguous(usize),
}

struct Candidate {
    arrived: i64,
    sender: String,
    code: Extracted,
}

/// Waits until `deadline` for the message with the code. Without `from`, exactly one message with a code may have arrived since `since` (unix seconds); with `from`, the newest one from those domains wins.
pub async fn wait_for_code(
    login: &Login,
    from: &[String],
    since: i64,
    deadline: Instant,
) -> Result<Found> {
    let mut session = connect(login).await?;
    let mut seen = HashSet::new();
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut unauthenticated = 0;
    loop {
        let query = format!("SINCE {}", imap_date(since - 86_400));
        let uids = timed(session.uid_search(&query)).await?;
        let new: Vec<String> = uids
            .into_iter()
            .filter(|uid| seen.insert(*uid))
            .map(|uid| uid.to_string())
            .collect();
        if !new.is_empty() {
            let fetches: Vec<Fetch> = timed(async {
                session
                    .uid_fetch(new.join(","), "(INTERNALDATE BODY.PEEK[])")
                    .await?
                    .try_collect()
                    .await
            })
            .await?;
            for fetch in &fetches {
                let arrived = fetch
                    .internal_date()
                    .map(|date| date.timestamp())
                    .unwrap_or(i64::MIN);
                if arrived < since {
                    continue;
                }
                let Some(body) = fetch.body() else { continue };
                match read_message(body) {
                    Some((sender, code)) => {
                        if (from.is_empty() || from.iter().any(|domain| within(&sender, domain)))
                            && code != Extracted::None
                        {
                            candidates.push(Candidate {
                                arrived,
                                sender,
                                code,
                            });
                        }
                    }
                    None => unauthenticated += 1,
                }
            }
        }

        if let Some(found) = choose(&mut candidates, from)? {
            let _ = timed(session.logout()).await;
            return Ok(found);
        }
        if Instant::now() >= deadline {
            let _ = timed(session.logout()).await;
            let senders = if from.is_empty() {
                "any sender".to_string()
            } else {
                from.join(", ")
            };
            bail!("no message with a code from {senders} arrived in time ({unauthenticated} new messages without a passing, aligned DKIM signature were skipped)");
        }
        tokio::time::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(Instant::now())))
            .await;
        timed(session.noop()).await?;
    }
}

/// The decision over the messages seen so far. `Ok(None)` means keep waiting.
fn choose(candidates: &mut Vec<Candidate>, from: &[String]) -> Result<Option<Found>> {
    let chosen = if from.is_empty() {
        match candidates.len() {
            0 => return Ok(None),
            1 => candidates.remove(0),
            n => {
                let senders: Vec<&str> = candidates.iter().map(|c| c.sender.as_str()).collect();
                bail!(
                    "{n} messages with a code arrived, from {}; name the sender with --from",
                    senders.join(", ")
                );
            }
        }
    } else {
        let Some(newest) = candidates
            .iter()
            .enumerate()
            .max_by_key(|(_, candidate)| candidate.arrived)
            .map(|(index, _)| index)
        else {
            return Ok(None);
        };
        candidates.remove(newest)
    };
    match chosen.code {
        Extracted::One(code) => Ok(Some(Found {
            sender: chosen.sender,
            code,
        })),
        Extracted::Ambiguous(n) => bail!(
            "the message from {} has {n} numbers next to words like 'code'; not guessing which",
            chosen.sender
        ),
        Extracted::None => unreachable!("messages without a code are not candidates"),
    }
}

/// The authenticated sender domain and the code of one raw message, or `None` when Gmail did not see a passing DKIM signature aligned with the `From` domain.
fn read_message(raw: &[u8]) -> Option<(String, Extracted)> {
    let message = MessageParser::default().parse(raw)?;
    // The topmost Authentication-Results header is the one Gmail added. Headers further down came with the message and anyone can write them. mail-parser's `header_raw` returns the last one, so it is not used here.
    let results = message
        .headers()
        .iter()
        .find(|header| header.name == HeaderName::AuthenticationResults)?;
    let results = std::str::from_utf8(
        message
            .raw_message()
            .get(results.offset_start as usize..results.offset_end as usize)?,
    )
    .ok()?;
    let from = message.from()?.first()?.address()?;
    let from_domain = from.rsplit_once('@')?.1.trim().to_ascii_lowercase();
    let signed = dkim_pass_domains(results)?;
    if !signed.iter().any(|domain| aligned(domain, &from_domain)) {
        return None;
    }
    let mut text = Zeroizing::new(message.subject().unwrap_or_default().to_string());
    for index in 0..message.text_body_count() {
        if let Some(body) = message.body_text(index) {
            text.push('\n');
            text.push_str(&body);
        }
    }
    Some((from_domain, extract_code(&text)))
}

/// The domains of the `dkim=pass` results in a Gmail `Authentication-Results` header value, or `None` when the header is not Gmail's.
fn dkim_pass_domains(results: &str) -> Option<Vec<String>> {
    let without_comments = strip_comments(results);
    let mut parts = without_comments.split(';');
    let authserv_id = parts.next()?.split_whitespace().next()?;
    if !authserv_id.eq_ignore_ascii_case(GMAIL_AUTHSERV_ID) {
        return None;
    }
    let mut domains = Vec::new();
    for part in parts {
        let mut words = part.split_whitespace();
        if !words
            .next()
            .is_some_and(|result| result.eq_ignore_ascii_case("dkim=pass"))
        {
            continue;
        }
        for word in words {
            let Some((key, value)) = word.split_once('=') else {
                continue;
            };
            let domain = match key.to_ascii_lowercase().as_str() {
                "header.d" => value,
                "header.i" => value.rsplit_once('@').map_or(value, |(_, domain)| domain),
                _ => continue,
            };
            domains.push(domain.trim_matches('"').to_ascii_lowercase());
        }
    }
    Some(domains)
}

/// Removes `(comments)`, which may nest, from a structured header value.
fn strip_comments(value: &str) -> String {
    let mut depth = 0usize;
    value
        .chars()
        .filter(|&c| {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth = depth.saturating_sub(1);
                    return false;
                }
                _ => {}
            }
            depth == 0
        })
        .collect()
}

/// Whether `domain` is `parent` or a subdomain of it.
fn within(domain: &str, parent: &str) -> bool {
    let parent = parent.trim_start_matches('.').to_ascii_lowercase();
    domain == parent || domain.ends_with(&format!(".{parent}"))
}

/// Relaxed alignment without a public suffix list: one domain is the other or a subdomain of it. A signature for a public suffix such as `co.uk` cannot exist, since nobody can publish its key.
fn aligned(signed: &str, from: &str) -> bool {
    within(signed, from) || within(from, signed)
}

/// The one code next to a keyword. Candidates are 4 to 8 digit numbers standing alone, or two groups of 3 or 4 digits joined by a space or hyphen. Numbers that look like years are skipped.
fn extract_code(text: &str) -> Extracted {
    let lower = Zeroizing::new(text.to_lowercase());
    let lower: &str = &lower;
    let letter_at = |c: Option<char>| c.is_some_and(char::is_alphabetic);
    let keywords: Vec<(usize, usize)> = KEYWORDS
        .iter()
        .flat_map(|&(keyword, whole_word)| {
            lower
                .match_indices(keyword)
                .map(|(start, found)| (start, start + found.len()))
                .filter(move |&(start, end)| {
                    !whole_word
                        || !(letter_at(lower[..start].chars().next_back())
                            || letter_at(lower[end..].chars().next()))
                })
                .collect::<Vec<_>>()
        })
        .collect();
    let near = |start: usize, end: usize| {
        keywords.iter().any(|&(kw_start, kw_end)| {
            (kw_end <= start && start - kw_end <= NEAR_AFTER)
                || (end <= kw_start && kw_start - end <= NEAR_BEFORE)
        })
    };

    let mut codes: Vec<Zeroizing<String>> = Vec::new();
    for (start, end, code) in numbers(lower) {
        if near(start, end) && !codes.iter().any(|known| **known == *code) {
            codes.push(code);
        }
    }
    match codes.len() {
        0 => Extracted::None,
        1 => Extracted::One(codes.pop().expect("one code")),
        n => Extracted::Ambiguous(n),
    }
}

/// Byte ranges and digits of the code-like numbers in `text`.
fn numbers(text: &str) -> Vec<(usize, usize, Zeroizing<String>)> {
    let bytes = text.as_bytes();
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_digit() {
            let start = index;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            runs.push((start, index));
        } else {
            index += 1;
        }
    }
    // A run is standalone when no letter, digit or number punctuation touches it: 12.50, 3,000, 10:30, #4411 and G-123 are not codes.
    let standalone = |start: usize, end: usize| {
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        let bad_before = |c: char| {
            c.is_alphanumeric()
                || matches!(
                    c,
                    '.' | ',' | ':' | '/' | '#' | '-' | '+' | '$' | '€' | '£' | '_' | '@'
                )
        };
        let bad_after = |c: char| {
            c.is_alphanumeric()
                || matches!(c, ',' | ':' | '/' | '-' | '%' | '_' | '@')
                || (c == '.'
                    && text[end + 1..]
                        .chars()
                        .next()
                        .is_some_and(|n| n.is_ascii_digit()))
        };
        !before.is_some_and(bad_before) && !after.is_some_and(bad_after)
    };

    let mut found = Vec::new();
    let mut run = 0;
    while run < runs.len() {
        let (start, end) = runs[run];
        // Two groups joined by one space or hyphen: 123 456, 1234-5678.
        if let Some(&(next_start, next_end)) = runs.get(run + 1) {
            let joiner = &text[end..next_start];
            let group = |len: usize| (3..=4).contains(&len);
            if (joiner == " " || joiner == "-")
                && group(end - start)
                && end - start == next_end - next_start
                && standalone_edges(text, start, next_end)
            {
                let mut code = Zeroizing::new(String::with_capacity(8));
                code.push_str(&text[start..end]);
                code.push_str(&text[next_start..next_end]);
                found.push((start, next_end, code));
                run += 2;
                continue;
            }
        }
        let len = end - start;
        let year =
            len == 4 && (text[start..end].starts_with("19") || text[start..end].starts_with("20"));
        if (4..=8).contains(&len) && !year && standalone(start, end) {
            found.push((start, end, Zeroizing::new(text[start..end].to_string())));
        }
        run += 1;
    }
    found
}

/// The standalone check for a joined pair, on its outer edges only.
fn standalone_edges(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(|c| {
        c.is_alphanumeric() || matches!(c, '.' | ',' | ':' | '/' | '#' | '-' | '+')
    }) && !after.is_some_and(|c| c.is_alphanumeric() || matches!(c, ',' | ':' | '/' | '-' | '%'))
}

type Session = async_imap::Session<tokio_rustls::client::TlsStream<TcpStream>>;

async fn connect(login: &Login) -> Result<Session> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = timed(TcpStream::connect((HOST, PORT)))
        .await
        .with_context(|| format!("failed to connect to {HOST}:{PORT}"))?;
    let tls = timed(TlsConnector::from(Arc::new(config)).connect(HOST.try_into()?, tcp)).await?;
    let mut client = async_imap::Client::new(tls);
    timed(async {
        client
            .read_response()
            .await?
            .ok_or_else(|| anyhow!("{HOST} closed the connection before its greeting"))
    })
    .await?;
    // The LOGIN command is formatted into a String inside async-imap that is not zeroed; accepted with the other library copies, see the decisions.
    let mut session = tokio::time::timeout(
        COMMAND_TIMEOUT,
        client.login(login.user.as_str(), login.password.as_str()),
    )
    .await
    .context("IMAP login timed out")?
    .map_err(|(error, _)| anyhow!("IMAP login to {HOST} failed: {error}"))?;
    // EXAMINE opens the inbox read-only, so nothing is marked as read.
    timed(session.examine("INBOX")).await?;
    Ok(session)
}

async fn timed<T, E: Into<anyhow::Error>>(
    future: impl std::future::Future<Output = std::result::Result<T, E>>,
) -> Result<T> {
    tokio::time::timeout(COMMAND_TIMEOUT, future)
        .await
        .context("IMAP command timed out")?
        .map_err(Into::into)
}

/// An IMAP date, `28-Sep-2026`, in UTC.
fn imap_date(unix: i64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    // Howard Hinnant's civil_from_days.
    let z = unix.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{day}-{}-{year}", MONTHS[(month - 1) as usize])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(code: &str) -> Extracted {
        Extracted::One(Zeroizing::new(code.to_string()))
    }

    #[test]
    fn code_next_to_a_keyword() {
        assert_eq!(
            extract_code("Your verification code is 483920."),
            one("483920")
        );
        assert_eq!(
            extract_code("Din engångskod:\n\n  4839 \n\nGäller i 10 minuter."),
            one("4839")
        );
        assert_eq!(extract_code("Code: 123 456"), one("123456"));
        assert_eq!(extract_code("Your code\n1234-5678\n"), one("12345678"));
        // The same code in the subject and the body is one code.
        assert_eq!(
            extract_code("483920 is your code\nYour code is 483920"),
            one("483920")
        );
    }

    #[test]
    fn uncertain_codes_are_not_guessed() {
        assert_eq!(
            extract_code("Your order 58213 has shipped"),
            Extracted::None
        );
        assert_eq!(extract_code("Happy shopping! Order 58213"), Extracted::None);
        assert_eq!(extract_code("Your PIN: 5821"), one("5821"));
        assert_eq!(
            extract_code("Code 111111 or code 222222"),
            Extracted::Ambiguous(2)
        );
        // Prices, times, dates, amounts and years are not codes.
        assert_eq!(
            extract_code("Code expires 10:30 on 2026-09-28, price 12.50, total 3,000, © 2026"),
            Extracted::None
        );
        assert_eq!(extract_code("Your code is G-123456"), Extracted::None);
        // Far from any keyword.
        let far = format!("Your code is below.{}\n555123", " ".repeat(200));
        assert_eq!(extract_code(&far), Extracted::None);
    }

    const GMAIL: &str = "mx.google.com;\r\n       dkim=pass header.i=@github.com header.s=pf2023 header.b=abc;\r\n       spf=pass (google.com: domain of noreply@github.com designates 1.2.3.4 as permitted sender) smtp.mailfrom=noreply@github.com;\r\n       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=github.com";

    #[test]
    fn dkim_domains_come_from_gmail_only() {
        assert_eq!(dkim_pass_domains(GMAIL).unwrap(), ["github.com"]);
        assert!(dkim_pass_domains("evil.example; dkim=pass header.d=github.com").is_none());
        assert_eq!(
            dkim_pass_domains("mx.google.com; dkim=fail header.i=@github.com; dkim=pass header.d=\"Mail.Example.com\"").unwrap(),
            ["mail.example.com"]
        );
    }

    fn message(headers: &str, body: &str) -> Vec<u8> {
        format!("{headers}Subject: Sign in\r\nContent-Type: text/plain\r\n\r\n{body}\r\n")
            .into_bytes()
    }

    #[test]
    fn message_needs_gmails_aligned_dkim_pass() {
        let good = message(
            &format!("Authentication-Results: {GMAIL}\r\nFrom: GitHub <noreply@github.com>\r\n"),
            "Your code is 483920",
        );
        let (sender, code) = read_message(&good).unwrap();
        assert_eq!(sender, "github.com");
        assert_eq!(code, one("483920"));

        // Signed by the sender's own domain, but claiming another From.
        let unaligned = message(
            "Authentication-Results: mx.google.com; dkim=pass header.i=@attacker.example\r\nFrom: GitHub <noreply@github.com>\r\n",
            "Your code is 483920",
        );
        assert!(read_message(&unaligned).is_none());

        // A forged header below Gmail's does not count; Gmail's own says fail.
        let forged = message(
            &format!("Authentication-Results: mx.google.com; dkim=fail header.i=@github.com\r\nFrom: noreply@github.com\r\nAuthentication-Results: {GMAIL}\r\n"),
            "Your code is 483920",
        );
        assert!(read_message(&forged).is_none());

        let subdomain = message(
            "Authentication-Results: mx.google.com; dkim=pass header.i=@github.com\r\nFrom: noreply@mail.github.com\r\n",
            "Your code is 483920",
        );
        assert_eq!(read_message(&subdomain).unwrap().0, "mail.github.com");
    }

    fn candidate(arrived: i64, sender: &str, code: &str) -> Candidate {
        Candidate {
            arrived,
            sender: sender.to_string(),
            code: one(code),
        }
    }

    #[test]
    fn choosing_among_messages() {
        let mut none = Vec::new();
        assert!(choose(&mut none, &[]).unwrap().is_none());

        let mut two = vec![
            candidate(1, "a.example", "1111"),
            candidate(2, "b.example", "2222"),
        ];
        let error = choose(&mut two, &[]).err().unwrap().to_string();
        assert!(error.contains("a.example, b.example"), "{error}");

        let mut two = vec![
            candidate(1, "a.example", "1111"),
            candidate(2, "a.example", "2222"),
        ];
        let found = choose(&mut two, &["a.example".to_string()])
            .unwrap()
            .unwrap();
        assert_eq!(*found.code, "2222");

        let mut ambiguous = vec![Candidate {
            arrived: 1,
            sender: "a.example".into(),
            code: Extracted::Ambiguous(2),
        }];
        assert!(choose(&mut ambiguous, &[]).is_err());
    }

    #[test]
    fn domain_matching() {
        assert!(within("mail.github.com", "github.com"));
        assert!(within("github.com", ".GitHub.com"));
        assert!(!within("notgithub.com", "github.com"));
        assert!(aligned("github.com", "mail.github.com"));
        assert!(aligned("mail.github.com", "github.com"));
        assert!(!aligned("attacker.example", "github.com"));
    }

    #[test]
    fn imap_dates() {
        assert_eq!(imap_date(0), "1-Jan-1970");
        assert_eq!(imap_date(1_790_553_600), "28-Sep-2026");
        assert_eq!(imap_date(951_782_400), "29-Feb-2000");
    }
}
