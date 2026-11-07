//! Windows: `SendInput` with `KEYEVENTF_UNICODE`, which types any character whatever the keyboard
//! layout. Windows doesn't let a normal app type into one running as administrator; `SendInput`
//! then sends nothing, and that's reported.

use std::path::Path;

use windows::Win32::Foundation::{CloseHandle, HWND};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, DESKTOP_CONTROL_FLAGS, DESKTOP_READOBJECTS, GetUserObjectInformationW,
    OpenInputDesktop, UOI_NAME,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBD_EVENT_FLAGS, KEYBDINPUT,
    KEYEVENTF_KEYUP, KEYEVENTF_UNICODE, SendInput, VIRTUAL_KEY, VK_CONTROL, VK_LWIN, VK_MENU,
    VK_RETURN, VK_RWIN, VK_SHIFT, VK_TAB,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId, IsIconic, SW_RESTORE,
    SetForegroundWindow, ShowWindow,
};
use windows::core::PWSTR;

use crate::engine::{Backend, Permission, Platform, PlatformError, PlatformResult};
use crate::sequence::Key;
use crate::window::FocusedWindow;

pub struct WindowsPlatform;

impl Platform for WindowsPlatform {
    fn backend(&self) -> Backend {
        Backend::SendInput
    }

    fn permission(&self) -> Permission {
        Permission::Granted
    }

    /// The input desktop is `Default` while the user is signed in and the screen isn't locked;
    /// the lock screen and UAC prompts are other desktops, which a normal app can't open.
    fn screen_locked(&self) -> bool {
        let Ok(desktop) =
            (unsafe { OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_READOBJECTS) })
        else {
            return true;
        };
        let mut name = [0u16; 64];
        let mut needed = 0;
        let read = unsafe {
            GetUserObjectInformationW(
                windows::Win32::Foundation::HANDLE(desktop.0),
                UOI_NAME,
                Some(name.as_mut_ptr().cast()),
                std::mem::size_of_val(&name) as u32,
                Some(&mut needed),
            )
        };
        unsafe {
            let _ = CloseDesktop(desktop);
        }
        if read.is_err() {
            return true;
        }
        let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        !String::from_utf16_lossy(&name[..len]).eq_ignore_ascii_case("Default")
    }

    fn focused_window(&self) -> PlatformResult<Option<FocusedWindow>> {
        let hwnd = unsafe { GetForegroundWindow() };
        if hwnd.is_invalid() {
            return Ok(None);
        }
        let mut pid = 0;
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
        let mut title = [0u16; 512];
        let len = unsafe { GetWindowTextW(hwnd, &mut title) };
        let title = String::from_utf16_lossy(&title[..len.max(0) as usize]);
        let exe = executable(pid).unwrap_or_default();
        let stem = Path::new(&exe)
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_default();
        Ok(Some(FocusedWindow {
            pid,
            app_name: stem.clone(),
            app_id: stem.to_lowercase(),
            title,
            url: None,
            handle: hwnd.0 as u64,
        }))
    }

    fn activate(&self, window: &FocusedWindow) -> PlatformResult<()> {
        let hwnd = HWND(window.handle as *mut _);
        unsafe {
            if IsIconic(hwnd).as_bool() {
                let _ = ShowWindow(hwnd, SW_RESTORE);
            }
            if !SetForegroundWindow(hwnd).as_bool() {
                return Err(PlatformError(format!(
                    "couldn't bring {} to the front",
                    window.describe()
                )));
            }
        }
        Ok(())
    }

    fn modifiers_held(&self) -> bool {
        [VK_SHIFT, VK_CONTROL, VK_MENU, VK_LWIN, VK_RWIN]
            .into_iter()
            .any(|key| unsafe { GetAsyncKeyState(i32::from(key.0)) } as u16 & 0x8000 != 0)
    }

    fn type_char(&self, c: char) -> PlatformResult<()> {
        let mut units = [0u16; 2];
        let inputs: Vec<INPUT> = c
            .encode_utf16(&mut units)
            .iter()
            .flat_map(|&unit| {
                [
                    key_input(VIRTUAL_KEY(0), unit, KEYEVENTF_UNICODE),
                    key_input(VIRTUAL_KEY(0), unit, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP),
                ]
            })
            .collect();
        send(&inputs)
    }

    fn press(&self, key: Key) -> PlatformResult<()> {
        let vk = match key {
            Key::Tab => VK_TAB,
            Key::Enter => VK_RETURN,
        };
        send(&[
            key_input(vk, 0, KEYBD_EVENT_FLAGS(0)),
            key_input(vk, 0, KEYEVENTF_KEYUP),
        ])
    }
}

fn key_input(vk: VIRTUAL_KEY, scan: u16, flags: KEYBD_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: scan,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn send(inputs: &[INPUT]) -> PlatformResult<()> {
    let sent = unsafe { SendInput(inputs, std::mem::size_of::<INPUT>() as i32) };
    if sent as usize == inputs.len() {
        Ok(())
    } else {
        Err(PlatformError(
            "Windows blocked the keystrokes. Apps running as administrator can't be typed into."
                .into(),
        ))
    }
}

fn executable(pid: u32) -> Option<String> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut path = [0u16; 1024];
    let mut len = path.len() as u32;
    let read = unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(path.as_mut_ptr()),
            &mut len,
        )
    };
    unsafe {
        let _ = CloseHandle(process);
    }
    read.ok()?;
    Some(String::from_utf16_lossy(&path[..len as usize]))
}
