---
title: Languages
description: Octa Pass apps come in English and Arabic, laid out right to left in Arabic. They follow your system language, or the one you choose for each device.
status: beta
sidebar:
  order: 15
---

The web vault, the browser extension, the desktop app and the phone apps come in **English** and **Arabic**. In Arabic everything is laid out right to left. The website and these docs are in both languages too, except the changelog, which is in English.

## Choosing a language

Octa Pass uses your system or browser language when it has it, and English otherwise. To pick one yourself, go to **Settings → Appearance → Language** and choose **System**, **English** or **العربية**.

The choice is for that device only. Your vault doesn't store it, so a shared laptop can show Arabic while your phone shows English.

| App | Where the language comes from |
|---|---|
| **Web vault** | The language in Settings, or your browser's languages, in order |
| **Browser extension** | Settings in the Octa Pass tab, or your browser's languages. The save prompts and suggestion menu on websites follow the same choice. |
| **Desktop app** | The vault window's Settings, or your system language. The quick-access window and the whole menu bar follow it, the standard Edit and Window menus included. |
| **iPhone and Android** | The app's Settings, or your phone's language. AutoFill screens and the system unlock prompt use the phone's language. |
| **Safari's Octa Pass app** | Your Mac's, iPhone's or iPad's language: the small screen that shows where to turn the extension on follows the system. The extension itself follows its own Settings. |

## Right to left

In Arabic, the layout is mirrored: the sidebar is on the right, back arrows and chevrons point the other way, and lists read from the right.

Some things stay left to right in every language, so they read the way you type them:

- Passwords, one-time codes, recovery codes and your Secret Key
- Email addresses, website addresses and phone numbers
- Card numbers and expiry dates

Item titles and notes keep the direction of what you wrote. A title like “Wi-Fi (5G)” stays whole inside an Arabic screen, and an Arabic note in an English screen reads right to left.

Numbers use Western digits (0–9) in Arabic too, the same digits as your passwords and codes. Counts use Arabic's plural forms: يوم واحد، يومان، 3 أيام، 11 يومًا.

## Fonts

Arabic text uses **Noto Sans Arabic**, and Latin text keeps the brand font, Mona Sans. Both ship with the apps. Nothing is loaded from a font service, so choosing a language doesn't tell any third party which one you use.

## Helping with translations

Each app keeps its words in one file per language:

| Strings | English | Arabic |
|---|---|---|
| Web vault (also used by the other apps) | `apps/web/src/i18n/en.ts` | `apps/web/src/i18n/ar.ts` |
| Browser extension | `apps/extension/src/i18n.ts` | same file |
| Desktop app | `apps/desktop/src/i18n.ts`, `src-tauri/src/menu.rs` | same files |
| Phone apps | `apps/web/src/i18n/phone.ts` | same file |
| Android AutoFill | `android/*/src/main/res/values/strings.xml` | `values-ar/strings.xml` |
| iPhone AutoFill | the English text in `apps/ios/AutoFill/*.swift` | `apps/ios/AutoFill/ar.lproj/Localizable.strings` |

A test checks every catalog: each English message needs an Arabic one with the same `{placeholders}`, counted messages need all six Arabic plural forms (zero, one, two, few, many, other), and nothing may be left in English by mistake. Product names like Octa Pass, Touch ID and Windows Hello stay in Latin letters.

More languages come through community translation in Weblate. See [translations](/docs/contributing/translations/).
