//! Live check of `typing` without the vault: types a dummy string into the focused field.
//! `cargo run --example type-probe -- [--password|--keyboard] TEXT`
use bw_broker::typing::Desktop;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mode, text) = match args.as_slice() {
        [mode, text] => (mode.as_str(), text.as_str()),
        [text] => ("", text.as_str()),
        _ => anyhow::bail!("usage: type-probe [--password|--keyboard] TEXT"),
    };
    let mut desktop = Desktop::connect()?;
    let target = desktop
        .focused()
        .ok_or_else(|| anyhow::anyhow!("no window has focus"))?;
    match mode {
        "--keyboard" => desktop.press_keys(&target, text.as_bytes())?,
        "--password" => desktop.commit(&target, text, true)?,
        _ => desktop.commit(&target, text, false)?,
    }
    println!("typed into {target}");
    Ok(())
}
