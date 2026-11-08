---
title: One-time codes on a watch
description: Show your one-time codes on Apple Watch or Wear OS. Your phone makes the codes and sends the next 15 minutes; the secrets never leave the phone.
status: in-progress
sidebar:
  order: 5
---

:::note[In progress]
The Apple Watch and Wear OS apps are written and their logic is tested, but they haven't been tried on a real paired watch yet. The Apple Watch app builds on its own but isn't bundled with the iPhone app yet, so it can't be installed with it.
:::

Octa Pass can show your [one-time codes](/docs/features/totp/) on an Apple Watch or a Wear OS watch, for when your phone is in a pocket. It's off until you turn it on.

## Turning it on

1. Install the watch app: on Apple Watch it will come with the iPhone app; on Wear OS, install Octa Pass from the watch's Play Store.
2. On your phone, go to **Settings → Security** and turn on **Show codes on Apple Watch** or **Show codes on Wear OS**. Octa Pass asks for your device lock or master password first, because this shows codes somewhere new.
3. Unlock Octa Pass on the phone. Open the app on the watch.

The setting belongs to that phone. It doesn't sync to your other devices, and turning it off clears the watch.

## How it works

**The phone makes the codes; the watch only shows them.** While Octa Pass is unlocked on your phone, it computes the next 15 minutes of codes for up to 50 items, favourites first, and sends them to the watch.

| | |
|---|---|
| What reaches the watch | Each item's name, how long a code lasts, and the codes for the next 15 minutes |
| What never reaches the watch | The secret behind the codes, the `otpauth://` link, usernames, websites, passwords and anything else in the item |
| Where it's kept | Apple Watch: in the app's memory, plus the system's protected copy of the phone's last message. Wear OS: in memory only |

This means two things you'll notice:

- **The phone must have been unlocked recently.** Codes run out 15 minutes after the phone last sent them. After that the watch says to open Octa Pass on your phone. When the vault locks, or you sign out, the phone tells the watch to forget everything straight away. If the watch is out of range at that moment, its codes still run out on time.
- **The watch can't work on its own.** Without your phone it shows what it has, then nothing.

## Why it's built this way

A code lasts seconds; the secret behind it lasts for years. If a watch is stolen, the most it can give away is a few minutes of codes, and only past its passcode. There's no secret on it to copy, and none travelling to it.

It also keeps one code generator for all of Octa Pass, in the audited core that runs on the phone.

Item names do reach the watch, so a name you find sensitive will be on your wrist. On Apple Watch they travel over Watch Connectivity, Apple's encrypted link between a paired iPhone and watch.

Wear OS's link can also go through Google's servers when the watch isn't near the phone. Octa Pass doesn't use that route: it sends only to a watch connected nearby, and asks only a nearby phone. Away from your phone, a Wear OS watch keeps what it has until it runs out.

## A watch needs a lock

The watch app refuses to show codes on a watch with no passcode or screen lock, and says so. Otherwise anyone who picked it up could read them. On Apple Watch the codes are hidden when your wrist is down, and Wear OS leaves the app when the screen dims. On Wear OS, screenshots of the app are blocked.

## Limits

- 50 items at a time. Favourites come first, then the rest by name. Mark the codes you want on your watch as favourites if you have more than that.
- Time-based codes only. [Counter-based codes](/docs/features/totp/#supported-formats) aren't sent, because using one changes it.
- A code with a period under 15 seconds runs out earlier than 15 minutes.
- Wear OS needs Google Play services on the phone and the watch.
- A watch doesn't count as using Octa Pass: asking for codes never keeps your vault unlocked.
