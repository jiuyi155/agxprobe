# AGXProbe — CVE-2026-64747 trigger probe

Target: **iPhone 13 (A15) on iOS 26.5.2**. This app hammers the AGXG14P GPU
command-queue paths that plausibly feed a per-queue **count bitmask**
(`count >= 0x400` → OOB 0x40-byte slot write → kernel heap corruption).

## What we know (reversed, 2026-08-10)

- Vulnerable fn `0xfffffff008003a8c` (26.5.2): `x1` = 32-bit count mask.
  For each set bit `n` it copies a **0x40-byte fixed template**
  (`00 00 00 00` + `FF`×60) into `obj+0x1040+n*0x40` and `obj+0x1540+n*0x40`.
  26.6 fix: reject `count >= 0x400` (i.e. any bit ≥ 10). Legal slots 0..9.
- The mask is OR-accumulated across a submitted batch from each command's
  `[cmd+0x14]` field (wrapper `0xfffffff00800c9d0`). The batch slot arrays
  (10 slots × 0x40) live at object offsets 0x1040 / 0x1540.
- `count` is **not reachable via any static call/literal** — the fn is
  reached through a runtime-built dispatch table (indirect PAC call).
- Unknown: which userland knob feeds `[cmd+0x14]` (or the mask). That is
  exactly what this probe tries to discover empirically.

## Trigger hypothesis

A submitted batch where some command's 0x14 field (or the OR across the
batch) sets a bit ≥ 10. This probe therefore floods every plausible surface
with **high-bit values**: shared-event signal values `1<<k` (k=0..31),
dense masks (0x3FF|0x400..0xFFFFFFFF), 256-buffer single batches, fences,
render + compute + blit, 32 queues.

If the probe triggers the bug, the expected symptoms are, in increasing
severity:

1. The app is killed by the system mid-run (userland-side effect of a
   corrupted queue).
2. The whole device **reboots** (kernel panic from the OOB heap write
   hitting a live object). ← strongest signal.
3. Nothing happens (count not controllable through these APIs → need a
   different trigger surface; report back the log).

## Build (requires a Mac — any Mac, free Apple ID is fine)

1. Open `AGXProbe.xcodeproj` in Xcode (16.x).
2. In the project → target **AGXProbe** → Signing & Capabilities:
   - check **Automatically manage signing**,
   - select your Team (your free Apple ID / personal team),
   - change `PRODUCT_BUNDLE_IDENTIFIER` (e.g. `com.you.agxprobe1`) to
     anything unique so signing succeeds.
3. Connect the iPhone 13 (iOS 26.5.2), select it as the run destination
   (Device, not a simulator).
4. Cmd-R. If you get a "preferred signer" / provisioning error, click
   **Enable Development** on the device when prompted, then retry.

## Run

1. Launch the app. It prints the GPU device name on screen — confirm it
   shows an A15 GPU (e.g. "Apple A15 GPU") and not a simulator.
2. Press **START**. Watch the green console log.
3. Phases cycle automatically every 200 iterations:
   `eventStorm → inFlight → fenceStorm → multiQueue → computeHeavy →
   chainedEvents → mixed → (repeat)`.
4. Let it run for several minutes. Keep the device awake (disable
   auto-lock: Settings → Display & Brightness → Auto-Lock → Never).

## Reading the result

- **Device reboots on its own** → the probe tripped the OOB. Now grab the
  panic log (below) — this both confirms the trigger and gives us the crash
  site to aim the heap feng shui.
- **App killed by system** (home screen flashes, "AGXProbe quit") → likely a
  partial hit; also collect the log.
- **Still running after 5+ minutes** → count likely not reachable via these
  exact APIs. Save the on-device log (`agxprobe.log` in the app's Documents,
  reachable via Files app because `UIFileSharingEnabled` is on) and send it
  back.

### Getting the panic log

If it panicked:
Settings → Privacy & Security → Analytics & Improvements →
Analytics Data → find the newest `panic-full-<date>` (or `JetsamEvent` /
`ipa-log-<timestamp>` for a killed app) → Share / AirDrop / copy the tail.

The first lines after `"panic(cpu ...)"` show the crashing kernel function —
send those back.
