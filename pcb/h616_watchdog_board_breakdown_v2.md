# H616 “watchdog” board — Scenario 2 (factory SMT/BGA + you hand‑solder connectors)
**Version:** v2 (adds 8GB storage sizing + board layout guidance)  
**Goal:** Low-cost, portable, single-purpose networking device built around **Allwinner H616 + 512MB DDR3 + 8GB eMMC**, with **Ethernet**, **2× USB‑A**, **USB‑C power**, **SPI TFT**, and **8 buttons**.

> This doc assumes you want the “easy soldering” path: the factory assembles all **SMT/BGA** parts, and you only solder **through‑hole / chunky connectors**.

---

## 0) Non‑negotiables vs flexible knobs

### Non‑negotiables (locked in)
- **SoC:** Allwinner **H616** (quad Cortex‑A53). Boot ROM supports SD/eMMC among other media.  
  Ref: H616 user manual excerpt listing SD/eMMC boot support.  
- **RAM:** **512MB DDR3/DDR3L** (minimum; 1GB is optional).  
- **Storage:** **8GB eMMC (soldered)** — kept intentionally.  
- **Ethernet:** 10/100 Ethernet with an RJ45 MagJack.  
- **USB power:** **USB‑C (5V sink)**.  
- **2× USB‑A host ports** on the PCB.  
- **Display:** SPI TFT (your current code supports ST7735; plan around that class).  
- **Buttons:** 8 buttons.  
- **Wi‑Fi:** single “basic” interface via **USB Wi‑Fi dongle** plugged into USB‑A (keeps PCB cost and risk down).

### Flexible knobs (safe to change later)
- DDR3/eMMC *vendor* (package + electrical compatibility must remain).
- Ethernet PHY (RMII PHY choices are common).
- USB hub IC (USB2 hubs are interchangeable if you match pinout/requirements).
- Power tree implementation (PMIC vs discrete buck+LDO).
- Display choice (module with headers vs raw panel+FPC).
- Connector brands and exact footprints.

---

## 1) Storage sizing: will 8GB be enough?

### Yes — for a CLI/Lite-style image, 8GB is workable with plenty of space for reports/keys
You said you will **flash the OS once and ship**, and you’re **not planning big update churn**. That changes the storage math in your favor.

**Concrete reference points:**
- Raspberry Pi OS Lite (arm64) image file is **~423MB compressed** for the 2025‑05‑13 Bookworm arm64 Lite release.  
  Source: official download index shows `2025-05-13-raspios-bookworm-arm64-lite.img.xz 423M`.
- Raspberry Pi docs recommend **16GB for Lite** (their recommendation is conservative headroom for general users).  
  Source: Raspberry Pi documentation (“Recommended SD cards… For Raspberry Pi OS Lite, we recommend at least 16 GB.”).
- A real df -h example for Pi OS Lite arm64 at first login shows **~2.1GB used** on root, with the standard ~510MB boot partition.  
  Source: Peter Moulding’s measured `df -h` output for 2025‑05‑13 Lite.

**What that means on an 8GB eMMC:**
- “8GB” eMMC typically yields ~7.4GiB usable-ish (binary units) after formatting/overhead (varies).
- If your Lite-style root is ~2.1GB initially, you can still keep **multiple GiB free**.
- Your stated needs (40MB binary + room for report files + WPA config/keys) are tiny compared to that.
- If you reserve **512MB–1GB** for logs/reports explicitly, you’ll still be fine.

### Recommended partitioning for your shipping device
Keep it boring and robust:

- **BOOT:** 256–512MB FAT32 (U‑Boot + kernel + DTBs)
- **ROOTFS:** 5.5–6.0GB ext4 (OS + your app)
- **DATA:** 0.8–1.5GB ext4 (reports, captures, configs, “stuff the user writes”)

Why a separate DATA partition?
- Lets you wipe/upgrade ROOTFS without nuking user data.
- Lets you mount DATA with different options (e.g., `noatime`) and apply quotas later if you want.

### “But I said Raspbian CLI 64-bit”
Important nuance: **Raspberry Pi OS (Raspbian) is built for Raspberry Pi hardware** and usually won’t boot “as-is” on H616 boards.  
Your *target* is better described as: **Debian/Ubuntu arm64 minimal rootfs with your software**, which is operationally similar to “Pi OS Lite.”

If you want an off-the-shelf base image for H616-class boards, **Armbian Minimal** is a common choice; their arm64 minimal images are published around the sub‑1GB compressed range (varies by build).  
Source: Armbian ARM64 downloads show “Minimal / IOT” sizes around ~895MB for Feb 2026 builds.

---

## 2) Scenario 2: what you hand‑solder vs what the factory delivers

### You hand‑solder (easy, “dumb” parts)
- **RJ45 MagJack** (through‑hole + shield tabs)
- **2× USB‑A receptacles** (choose through‑hole style)
- **2.54mm headers** (display module, UART/debug, optional GPIO)

### Factory assembles (SMT/BGA, must be machine)
- H616 SoC (BGA)
- DDR3/DDR3L (BGA)
- eMMC (BGA) — typically implies X‑ray in assembly workflows
- Ethernet PHY (QFN/QFP)
- USB hub IC
- all passives, ESD, crystals, regulators, sequencing glue

### What you receive from the factory
- A PCB that has **all critical silicon and support circuitry** assembled and reflowed.
- Unpopulated footprints for the through‑hole connectors you’ll solder.
- Ideally a manufacturing-level inspection (depends on vendor tier; for BGA you usually want X‑ray).

---

## 3) Ballpark BOM (parts + costs) for the board

Below are **component** ballparks for ~10 units, excluding shipping/import/VAT and excluding PCB/assembly labor until Section 4.

> Prices move constantly; treat these as “order-of-magnitude” and use them for design trade-offs, not accounting.

### Core compute + memory
- **H616 SoC:** ~$8–$12 each at modest volume (varies wildly by channel)
- **DDR3/DDR3L 512MB (4Gb x16):** ~$1.5–$2.5 each
- **eMMC 8GB:** ~$5.5–$7.5 each (BGA‑153 class parts are common)

### Ethernet + USB
- **RMII PHY (LAN8720A class):** ~$0.5–$0.8
- **RJ45 MagJack:** ~$1.0–$1.5
- **USB2 hub (FE1.1S class):** ~$0.35–$0.60
- **USB‑A connectors (x2):** ~$0.08–$0.20 total
- **USB‑C receptacle + CC resistors:** ~$0.10–$0.30

### UI
- **8 tact switches (if SMT):** ~$0.10–$0.30 total
- **SPI TFT module:** ~$2.5–$4.0

### “Everything else” bucket (do not ignore)
- regulators/bucks/LDOs, ESD, crystals, inductors, ferrites, passives, LEDs  
  **Budget:** ~$3–$6 (depends on power tree and ESD discipline)

---

## 4) PCB fabrication + PCBA (assembly): what you pay and why

### The “Big Three” files PCBA expects
Most assembly houses (including JLCPCB’s turnkey flow) expect:
1) **Gerbers** (fab)
2) **BOM** (what parts)
3) **CPL / centroid / pick‑and‑place** (where parts go)

JLCPCB explicitly calls out these three as required for assembly orders.

### Scenario 2 cost behavior
Scenario 2 gets cheaper because:
- you avoid **manual through‑hole labor fees**
- you reduce the “unique parts” complexity in assembly
- you keep the factory doing what it’s good at: SMT/BGA reflow and inspection

But you still pay:
- stencil + setup
- per‑placement fees
- possibly BGA X‑ray (especially with eMMC/DDR)

**Rule of thumb:** for 10 units, your per-board “manufacturing overhead” is often in the **high single digits to low teens USD** once you include setup amortization.

---

## 5) What you must provide to the fab/assembly plant (deliverables)

### For bare PCB fab
- Gerber RS‑274X (all copper/mask/silk/paste layers)
- NC drill files
- Board outline (Edge.Cuts)

### For PCBA (assembly)
- Gerber zip
- BOM (.csv/.xlsx) including MPNs (and house part numbers if using their library)
- CPL/centroid (.csv/.txt) with X/Y/rotation/side
- Assembly drawings (PDF top/bottom with polarity/orientation)
- “DNP list” (explicitly: RJ45/USB‑A/headers NOT assembled)
- Notes: which parts are customer‑supplied vs house‑supplied

---

## 6) Board layout: where things should go (and why)

### Golden rule: make three “zones”
1) **High‑speed digital core** (H616 + DDR + eMMC)  
2) **I/O edges** (RJ45, USB‑A, USB‑C, headers)  
3) **Power entry + regulators** (near USB‑C, but close to consumers via short rails)

This reduces rework and makes EMI/bring‑up survivable.

---

### 6.1 H616 + DDR3 + eMMC placement
**Place DDR3 as physically close to the SoC as possible** and keep those routes short and clean. DDR is the “layout boss fight.”

General DDR3 routing rules you should plan around:
- Match DQ/DQS/DM within byte lanes tightly.
- Keep address/command matched to clock within small skew budgets.
- Avoid routing clock close to address lines.

(These rules are captured in widely used DDR3 layout guidance; Intel’s DDR3 routing section is a good public summary, and similar constraints exist in other vendors’ guides.)

**Practical layout moves:**
- Put **SoC + DDR + eMMC all on the same side** (top side) in one tight cluster.
- Reserve inner layers for **solid reference planes**.
- Budget a **6‑layer stackup** early. Two-layer is a fantasy for DDR.

---

### 6.2 Ethernet placement (RJ45 + PHY)
Follow Microchip’s “front-end hygiene” approach:
- Keep **Ethernet differential pairs** (magnetics ↔ RJ45 and PHY ↔ magnetics) as controlled‑impedance differential routing (100Ω).
- Keep other noisy signals out of the Ethernet “front end.”
- Consider plane clear-outs under the magnetics-to-RJ45 diff pairs to reduce coupling.

Microchip’s LAN8720 QFN routing checklist explicitly calls out:
- differential routing for the TX/RX pairs and 100Ω impedance
- routing the magnetics-to-RJ45 diff pairs on the component side and clearing planes under those traces
- keeping unrelated signals away from the Ethernet front end

**Placement order (board edge):**
RJ45 at the edge → magnetics (in MagJack or discrete) → PHY → SoC RMII.

If using an integrated MagJack (HR911105A-style), you still route PHY MDI pairs to the jack pins; keep that section tight and clean.

---

### 6.3 USB placement (USB‑C power + USB hub + USB‑A)
USB2 routing is forgiving compared to DDR, but still wants discipline:
- Route D+/D‑ as a differential pair.
- Keep a continuous reference plane under the pair.
- Avoid stubs; minimize vias; keep the pair short.
- Keep skew between D+ and D‑ small (many app notes recommend ≤50 mil mismatch for HS).

Microchip’s USB implementation guidelines emphasize:
- careful length matching
- avoid 90° corners
- keep pairs short
- route over unbroken planes
- minimize vias

**Placement tips:**
- Put the **USB hub IC** close to the H616’s USB2 host pins.
- Put the **USB‑A connectors on an edge**, with ESD parts close to the connector.
- Put **USB‑C power input near the power section** (and keep the 5V high-current path wide and short).

---

### 6.4 Power layout (USB‑C 5V → rails)
This is where boards either feel professional or feel haunted.

- Put your **primary buck converter(s)** close to where 5V enters (USB‑C).
- Keep **switching loops** tight (short high‑di/dt paths).
- Keep switching nodes away from:
  - DDR region
  - Ethernet front end
  - display SPI lines

Then distribute rails to SoC/DDR/eMMC with:
- short routes
- plenty of local decoupling at each IC power pin group
- wide pours where current is high

---

### 6.5 Display + buttons placement
Keep UI away from the “angry” zones:
- Place the display header/module connector near the side where the screen sits mechanically.
- Keep SPI lines away from Ethernet MDI and DDR region when possible.
- Buttons: if SMT switches, place near the edge for ergonomics; route GPIOs with pull‑ups/ESD as needed.

---

## 7) What can be “cheap” without hurting you much

Safe places to economize:
- connector brands (as long as footprints match)
- passive vendors (keep specs/tolerances sane)
- display module vendor (as long as ST7735-ish behavior is compatible)
- DDR3 and eMMC vendor (as long as the electrical and package constraints are satisfied)

Do **not** cheap out on:
- ESD on USB and Ethernet
- power integrity (regulator selection, decoupling, layout)
- DDR layout stackup discipline

---

## 8) What to do next (recommended follow-up docs)
These are large enough that they deserve their own design docs:

1) **Power Tree + rail current budget + sequencing**
2) **DDR3 routing constraints + 6‑layer stackup proposal**
3) **Boot + provisioning flow (SD→eMMC or factory eMMC programming)**
4) **Manufacturing test plan (power/UART/USB/Eth/display/buttons)**

---

## References (key sources used)
- Raspberry Pi OS Lite arm64 image size (official index):  
  https://downloads.raspberrypi.org/raspios_lite_arm64/images/raspios_lite_arm64-2025-05-13/
- Raspberry Pi documentation recommended card sizes (Lite 16GB):  
  https://www.raspberrypi.com/documentation/installation/windows/
- Pi OS Lite installed size example (`df -h`, ~2.1GB used):  
  https://petermoulding.com/raspberry_pi_os_disk_space_usage_2025
- Armbian arm64 minimal image sizes (Feb 2026 builds):  
  https://www.armbian.com/uefi-arm64/
- H616 boot ROM supports SD/eMMC (user manual excerpt):  
  https://www.scribd.com/document/644281480/h616-user-manual-v1-0-pdf
- DDR3 layout/routing summary (public guidelines):  
  https://www.intel.com/content/www/us/en/docs/programmable/683385/17-0/layout-guidelines-for-ddr3-sdram-interfaces.html
- Microchip LAN8720 routing checklist (Ethernet front-end layout):  
  https://ww1.microchip.com/downloads/aemDocuments/documents/OTH/ProductDocuments/SupportingCollateral/LAN8720_QFN_Rev_A_Routing_Checklist.pdf
- USB implementation/layout guidelines (Microchip AN26.2):  
  https://ww1.microchip.com/downloads/en/Appnotes/AN26.2-Application-Note-DS00001876C.pdf
- PCBA required files (Gerber + BOM + CPL) — JLCPCB:  
  https://api.jlcpcb.com/blog/printed-circuit-board-assembly
