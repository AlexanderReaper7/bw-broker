//! Typing a value into the focused text field, for `bw-app-gate type`.
//!
//! The default is a short-lived Wayland input method. The compositor tells an input method when a text field gains or loses focus and what the field is for, so a password is only sent to a field that says it is a password field, and a click that moves focus shows up as `deactivate`. The value goes in one `commit_string`, which the compositor delivers to the focused field only.
//!
//! The fallback is the virtual keyboard, for apps without text-input-v3, such as Electron without `--enable-wayland-ime`. It sees windows, not fields: the focused toplevel is compared with the target before every key and after the last.
//!
//! The reasons, and what neither catches, are in `docs/decisions.md` under 2026-09-28.

use anyhow::{anyhow, bail, Context, Result};
use cosmic_protocols::toplevel_info::v1::client::{
    zcosmic_toplevel_handle_v1::{self, ZcosmicToplevelHandleV1},
    zcosmic_toplevel_info_v1::{self, ZcosmicToplevelInfoV1},
};
use std::fmt;
use std::io::Write;
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};
use wayland_client::globals::{registry_queue_init, GlobalListContents};
use wayland_client::protocol::{wl_registry::WlRegistry, wl_seat::WlSeat};
use wayland_client::{
    delegate_noop, event_created_child, Connection, Dispatch, EventQueue, Proxy, QueueHandle, WEnum,
};
use wayland_protocols::ext::foreign_toplevel_list::v1::client::{
    ext_foreign_toplevel_handle_v1::{self, ExtForeignToplevelHandleV1},
    ext_foreign_toplevel_list_v1::{self, ExtForeignToplevelListV1},
};
use wayland_protocols::wp::text_input::zv3::client::zwp_text_input_v3::ContentPurpose;
use wayland_protocols_misc::zwp_input_method_v2::client::{
    zwp_input_method_manager_v2::ZwpInputMethodManagerV2,
    zwp_input_method_v2::{self, ZwpInputMethodV2},
};
use wayland_protocols_misc::zwp_virtual_keyboard_v1::client::{
    zwp_virtual_keyboard_manager_v1::ZwpVirtualKeyboardManagerV1,
    zwp_virtual_keyboard_v1::ZwpVirtualKeyboardV1,
};

/// `zcosmic_toplevel_handle_v1.state` value for the focused window.
const STATE_ACTIVATED: u32 = 2;

/// How long the focus may take to come back to the target after the prompt closes.
pub const FOCUS_RETURN: Duration = Duration::from_secs(3);

/// How long a new input method waits to be told about the focused field.
const FIELD_WAIT: Duration = Duration::from_millis(500);

/// Pause between keys in keyboard mode. Some pages drop keys that arrive faster.
const KEY_INTERVAL: Duration = Duration::from_millis(5);

/// `zwp_virtual_keyboard_v1.keymap` format for an XKB text keymap.
const KEYMAP_FORMAT_XKB_V1: u32 = 1;

/// The printable ASCII characters in order from 0x20, as xkb keysym names. Character `0x20 + i` is on evdev key `1 + i`.
const KEYSYMS: [&str; 95] = [
    "space",
    "exclam",
    "quotedbl",
    "numbersign",
    "dollar",
    "percent",
    "ampersand",
    "apostrophe",
    "parenleft",
    "parenright",
    "asterisk",
    "plus",
    "comma",
    "minus",
    "period",
    "slash",
    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    "colon",
    "semicolon",
    "less",
    "equal",
    "greater",
    "question",
    "at",
    "A",
    "B",
    "C",
    "D",
    "E",
    "F",
    "G",
    "H",
    "I",
    "J",
    "K",
    "L",
    "M",
    "N",
    "O",
    "P",
    "Q",
    "R",
    "S",
    "T",
    "U",
    "V",
    "W",
    "X",
    "Y",
    "Z",
    "bracketleft",
    "backslash",
    "bracketright",
    "asciicircum",
    "underscore",
    "grave",
    "a",
    "b",
    "c",
    "d",
    "e",
    "f",
    "g",
    "h",
    "i",
    "j",
    "k",
    "l",
    "m",
    "n",
    "o",
    "p",
    "q",
    "r",
    "s",
    "t",
    "u",
    "v",
    "w",
    "x",
    "y",
    "z",
    "braceleft",
    "bar",
    "braceright",
    "asciitilde",
];

/// A toplevel as the prompt and the replies name it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Window {
    /// `ext_foreign_toplevel_handle_v1.identifier`, unique per toplevel for the session. Two windows with the same title are still told apart.
    pub identifier: String,
    pub app_id: String,
    pub title: String,
}

impl Window {
    /// Whether the title or the app id contains `needle`, ignoring case. The same rule as `computer-use activate --title`, so one string names the window for both.
    pub fn matches(&self, needle: &str) -> bool {
        let needle = needle.to_lowercase();
        self.title.to_lowercase().contains(&needle) || self.app_id.to_lowercase().contains(&needle)
    }
}

impl fmt::Display for Window {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} \"{}\"", self.app_id, self.title)
    }
}

struct Toplevel {
    ext: ExtForeignToplevelHandleV1,
    cosmic: Option<ZcosmicToplevelHandleV1>,
    window: Window,
    activated: bool,
}

/// The input method's view of the focused field. Events stage changes and `done` applies them.
#[derive(Clone, Copy, Default)]
struct Field {
    active: bool,
    purpose: Option<ContentPurpose>,
}

struct State {
    seat: WlSeat,
    toplevel_info: ZcosmicToplevelInfoV1,
    toplevels: Vec<Toplevel>,
    pending: Field,
    /// Whether the pending batch has an `activate` or `deactivate`, which means focus entered or left a field.
    pending_moved: bool,
    field: Field,
    /// `done` events received, which `commit` has to quote back.
    dones: u32,
    /// Batches that moved focus between fields.
    field_moves: u32,
    unavailable: bool,
}

impl State {
    fn focused(&self) -> Option<&Window> {
        self.toplevels
            .iter()
            .find(|toplevel| toplevel.activated)
            .map(|toplevel| &toplevel.window)
    }
}

/// One connection to the compositor, used for one `type` request.
pub struct Desktop {
    /// Held because dropping it closes the connection.
    _connection: Connection,
    queue: EventQueue<State>,
    qh: QueueHandle<State>,
    input_methods: Option<ZwpInputMethodManagerV2>,
    keyboards: Option<ZwpVirtualKeyboardManagerV1>,
    state: State,
}

impl Desktop {
    pub fn connect() -> Result<Self> {
        let connection = Connection::connect_to_env().context(
            "cannot reach the Wayland compositor; is WAYLAND_DISPLAY set for the agent?",
        )?;
        let (globals, queue) = registry_queue_init::<State>(&connection)?;
        let qh = queue.handle();
        let missing = |what: &str| anyhow!("the compositor has no {what}");
        let seat: WlSeat = globals
            .bind(&qh, 1..=9, ())
            .map_err(|_| missing("wl_seat"))?;
        let toplevel_info: ZcosmicToplevelInfoV1 = globals
            .bind(&qh, 2..=3, ())
            .map_err(|_| missing("zcosmic_toplevel_info_v1 (only COSMIC is supported)"))?;
        let _list: ExtForeignToplevelListV1 = globals
            .bind(&qh, 1..=1, ())
            .map_err(|_| missing("ext_foreign_toplevel_list_v1"))?;
        let input_methods = globals.bind(&qh, 1..=1, ()).ok();
        let keyboards = globals.bind(&qh, 1..=1, ()).ok();

        let mut desktop = Desktop {
            _connection: connection,
            queue,
            qh,
            input_methods,
            keyboards,
            state: State {
                seat,
                toplevel_info,
                toplevels: Vec::new(),
                pending: Field::default(),
                pending_moved: false,
                field: Field::default(),
                dones: 0,
                field_moves: 0,
                unavailable: false,
            },
        };
        // The first roundtrip lists the toplevels and asks for their cosmic handles. cosmic-comp sends the states on its next refresh rather than in reply, so wait a little for one to say it is focused.
        desktop.roundtrip()?;
        let deadline = Instant::now() + Duration::from_millis(300);
        while desktop.state.focused().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
            desktop.roundtrip()?;
        }
        Ok(desktop)
    }

    fn roundtrip(&mut self) -> Result<()> {
        self.queue
            .roundtrip(&mut self.state)
            .context("lost the Wayland connection")?;
        Ok(())
    }

    /// The focused toplevel, as of the last roundtrip.
    pub fn focused(&self) -> Option<Window> {
        self.state.focused().cloned()
    }

    fn focus_name(&self) -> String {
        self.state
            .focused()
            .map_or_else(|| "no window".to_string(), ToString::to_string)
    }

    /// Waits for `target` to have focus again, as it should once the prompt closes.
    pub fn wait_for_focus(&mut self, target: &Window, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            self.roundtrip()?;
            if self.state.focused() == Some(target) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!(
                    "focus did not return to {target} after the prompt; it is on {}. Nothing was typed",
                    self.focus_name()
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Sends `text` to the focused field of `target` through an input method. With `password`, refuses unless the field says it is a password field.
    pub fn commit(&mut self, target: &Window, text: &str, password: bool) -> Result<()> {
        let manager = self
            .input_methods
            .clone()
            .ok_or_else(|| anyhow!("the compositor has no zwp_input_method_manager_v2"))?;
        let input_method = manager.get_input_method(&self.state.seat, &self.qh, ());
        let result = self.commit_with(&input_method, target, text, password);
        input_method.destroy();
        let _ = self.roundtrip();
        result
    }

    fn commit_with(
        &mut self,
        input_method: &ZwpInputMethodV2,
        target: &Window,
        text: &str,
        password: bool,
    ) -> Result<()> {
        let deadline = Instant::now() + FIELD_WAIT;
        loop {
            self.roundtrip()?;
            if self.state.unavailable {
                bail!("another input method is running on this seat; nothing was typed");
            }
            if self.state.field.active || Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if self.state.focused() != Some(target) {
            bail!(
                "focus moved from {target} to {}; nothing was typed",
                self.focus_name()
            );
        }
        if !self.state.field.active {
            bail!(
                "no text field in {target} has focus, or the app does not support text-input-v3; nothing was typed. Click the field and retry, or use --keyboard for apps without text-input-v3"
            );
        }
        if password && self.state.field.purpose != Some(ContentPurpose::Password) {
            bail!(
                "the focused field in {target} is not a password field ({}); nothing was typed",
                self.state
                    .field
                    .purpose
                    .map_or_else(|| "no purpose given".to_string(), |p| format!("{p:?}"))
            );
        }

        let moves = self.state.field_moves;
        // wayland-client takes the text as a String and drops it without zeroing. See the decisions.
        input_method.commit_string(text.to_string());
        input_method.commit(self.state.dones);
        // A roundtrip is a sync: every event the compositor sent before it handled the commit has arrived when it returns.
        self.roundtrip()?;
        if self.state.field_moves != moves || self.state.focused() != Some(target) {
            bail!(
                "focus moved while typing; the value may have gone to the field that now has focus in {}",
                self.focus_name()
            );
        }
        Ok(())
    }

    /// Types `text` key by key through a virtual keyboard with a fixed ASCII keymap, checking before each key and after the last that `target` still has focus.
    pub fn press_keys(&mut self, target: &Window, text: &[u8]) -> Result<()> {
        if let Some(position) = text.iter().position(|&byte| !(0x20..=0x7e).contains(&byte)) {
            bail!(
                "character {} is not printable ASCII, which is all keyboard mode can type; nothing was typed",
                position + 1
            );
        }
        let manager = self
            .keyboards
            .clone()
            .ok_or_else(|| anyhow!("the compositor has no zwp_virtual_keyboard_manager_v1"))?;
        let keyboard = manager.create_virtual_keyboard(&self.state.seat, &self.qh, ());
        let result = self.press_keys_with(&keyboard, target, text);
        keyboard.destroy();
        let _ = self.roundtrip();
        result
    }

    fn press_keys_with(
        &mut self,
        keyboard: &ZwpVirtualKeyboardV1,
        target: &Window,
        text: &[u8],
    ) -> Result<()> {
        let (keymap, size) = keymap()?;
        keyboard.keymap(KEYMAP_FORMAT_XKB_V1, keymap.as_fd(), size);
        keyboard.modifiers(0, 0, 0, 0);
        let start = Instant::now();
        for (index, &byte) in text.iter().enumerate() {
            self.roundtrip()?;
            if self.state.focused() != Some(target) {
                bail!(
                    "stopped after {index} of {} characters: focus moved from {target} to {}, which may have received part of the value",
                    text.len(),
                    self.focus_name()
                );
            }
            let key = u32::from(byte - 0x20) + 1;
            let time = start.elapsed().as_millis() as u32;
            keyboard.key(time, key, 1);
            keyboard.key(time, key, 0);
            std::thread::sleep(KEY_INTERVAL);
        }
        self.roundtrip()?;
        if self.state.focused() != Some(target) {
            bail!(
                "focus moved from {target} to {} during the last key; it may have received part of the value",
                self.focus_name()
            );
        }
        Ok(())
    }
}

/// The fixed keymap in a sealed memfd. The same for every value, so the app that receives it learns nothing about which characters a value uses.
fn keymap() -> Result<(OwnedFd, u32)> {
    let mut text =
        String::from("xkb_keymap {\nxkb_keycodes \"bw\" {\nminimum = 8;\nmaximum = 255;\n");
    for index in 0..KEYSYMS.len() {
        text += &format!("<K{index}> = {};\n", index + 9);
    }
    text += "};\nxkb_types \"bw\" { include \"complete\" };\nxkb_compatibility \"bw\" { include \"complete\" };\nxkb_symbols \"bw\" {\n";
    for (index, keysym) in KEYSYMS.iter().enumerate() {
        text += &format!("key <K{index}> {{ [ {keysym} ] }};\n");
    }
    text += "};\n};\n";
    let mut bytes = text.into_bytes();
    bytes.push(0);

    let fd = unsafe { libc::memfd_create(c"bw-app-gate-keymap".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("memfd_create");
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    std::fs::File::from(fd.try_clone()?).write_all(&bytes)?;
    Ok((fd, bytes.len() as u32))
}

impl Dispatch<ExtForeignToplevelListV1, ()> for State {
    fn event(
        state: &mut Self,
        _: &ExtForeignToplevelListV1,
        event: ext_foreign_toplevel_list_v1::Event,
        _: &(),
        _: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        if let ext_foreign_toplevel_list_v1::Event::Toplevel { toplevel } = event {
            let cosmic = state.toplevel_info.get_cosmic_toplevel(&toplevel, qh, ());
            state.toplevels.push(Toplevel {
                ext: toplevel,
                cosmic: Some(cosmic),
                window: Window {
                    identifier: String::new(),
                    app_id: String::new(),
                    title: String::new(),
                },
                activated: false,
            });
        }
    }

    event_created_child!(State, ExtForeignToplevelListV1, [
        ext_foreign_toplevel_list_v1::EVT_TOPLEVEL_OPCODE => (ExtForeignToplevelHandleV1, ())
    ]);
}

impl Dispatch<ExtForeignToplevelHandleV1, ()> for State {
    fn event(
        state: &mut Self,
        handle: &ExtForeignToplevelHandleV1,
        event: ext_foreign_toplevel_handle_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        let Some(toplevel) = state.toplevels.iter_mut().find(|t| &t.ext == handle) else {
            return;
        };
        match event {
            ext_foreign_toplevel_handle_v1::Event::Title { title } => toplevel.window.title = title,
            ext_foreign_toplevel_handle_v1::Event::AppId { app_id } => {
                toplevel.window.app_id = app_id
            }
            ext_foreign_toplevel_handle_v1::Event::Identifier { identifier } => {
                toplevel.window.identifier = identifier
            }
            ext_foreign_toplevel_handle_v1::Event::Closed => {
                state.toplevels.retain(|t| &t.ext != handle);
            }
            _ => {}
        }
    }
}

impl Dispatch<ZcosmicToplevelInfoV1, ()> for State {
    fn event(
        _: &mut Self,
        _: &ZcosmicToplevelInfoV1,
        _: zcosmic_toplevel_info_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        // The `toplevel` event is deprecated since version 2; the list comes from ext_foreign_toplevel_list. The child declaration has to exist anyway, since an unexpected new_id aborts the dispatch.
    }

    event_created_child!(State, ZcosmicToplevelInfoV1, [
        zcosmic_toplevel_info_v1::EVT_TOPLEVEL_OPCODE => (ZcosmicToplevelHandleV1, ())
    ]);
}

impl Dispatch<ZcosmicToplevelHandleV1, ()> for State {
    fn event(
        state: &mut Self,
        handle: &ZcosmicToplevelHandleV1,
        event: zcosmic_toplevel_handle_v1::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let zcosmic_toplevel_handle_v1::Event::State { state: states } = event {
            let activated = states
                .as_chunks::<4>()
                .0
                .iter()
                .any(|&chunk| u32::from_ne_bytes(chunk) == STATE_ACTIVATED);
            if let Some(toplevel) = state
                .toplevels
                .iter_mut()
                .find(|t| t.cosmic.as_ref() == Some(handle))
            {
                toplevel.activated = activated;
            }
        }
    }
}

impl Dispatch<ZwpInputMethodV2, ()> for State {
    fn event(
        state: &mut Self,
        _: &ZwpInputMethodV2,
        event: zwp_input_method_v2::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            zwp_input_method_v2::Event::Activate => {
                // A new activation starts from a clean field, per the protocol.
                state.pending = Field {
                    active: true,
                    purpose: None,
                };
                state.pending_moved = true;
            }
            zwp_input_method_v2::Event::Deactivate => {
                state.pending = Field::default();
                state.pending_moved = true;
            }
            zwp_input_method_v2::Event::ContentType { purpose, .. } => {
                state.pending.purpose = match purpose {
                    WEnum::Value(purpose) => Some(purpose),
                    WEnum::Unknown(_) => None,
                };
            }
            zwp_input_method_v2::Event::Done => {
                state.field = state.pending;
                state.dones += 1;
                if std::mem::take(&mut state.pending_moved) {
                    state.field_moves += 1;
                }
            }
            zwp_input_method_v2::Event::Unavailable => state.unavailable = true,
            // Surrounding text is the field's content, which is not needed and not kept.
            _ => {}
        }
    }
}

impl Dispatch<WlRegistry, GlobalListContents> for State {
    fn event(
        _: &mut Self,
        _: &WlRegistry,
        _: <WlRegistry as Proxy>::Event,
        _: &GlobalListContents,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

delegate_noop!(State: ignore WlSeat);
delegate_noop!(State: ignore ZwpInputMethodManagerV2);
delegate_noop!(State: ignore ZwpVirtualKeyboardManagerV1);
delegate_noop!(State: ignore ZwpVirtualKeyboardV1);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keysyms_cover_printable_ascii_in_order() {
        assert_eq!(KEYSYMS.len(), 0x7f - 0x20);
        for (index, keysym) in KEYSYMS.iter().enumerate() {
            let c = char::from(0x20 + index as u8);
            if c.is_ascii_alphanumeric() {
                assert_eq!(*keysym, c.to_string());
            }
        }
        assert_eq!(KEYSYMS[usize::from(b'@' - 0x20)], "at");
        assert_eq!(KEYSYMS[usize::from(b'~' - 0x20)], "asciitilde");
    }

    #[test]
    fn a_window_matches_part_of_its_title_or_app_id_in_any_case() {
        let teams = Window {
            identifier: "1".to_string(),
            app_id: "teams-for-linux".to_string(),
            title: "Sign in to your account".to_string(),
        };
        assert!(teams.matches("Teams"));
        assert!(teams.matches("sign in"));
        assert!(!teams.matches("T3 Code"));
        assert!(!teams.matches("teams-for-linux Sign"));
    }
}
