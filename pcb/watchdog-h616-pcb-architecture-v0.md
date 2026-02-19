# KeyCAD / KiCad Architecture Document — H616 Rustyjack Prototype PCB (v0)

> **Intent:** this is the **architectural spec** for a *first-spin bring‑up / debugging* PCB built around **Allwinner H616**, sized and scoped like a purpose-built “Pi Zero 2 W‑class appliance,” but implemented as a custom SBC‑style PCB.  
> **Non‑intent:** this document does **not** contain detailed schematic capture or layout instructions. Each subsystem below points to a **future low-level reference doc** you’ll create next.

---

## 0) What we’re building

### 0.1 Product goal (prototype-first)
A single-purpose embedded Linux board that can run the existing watchdog Rust project (currently proven on Raspberry Pi Zero 2 W), with:

- **SoC:** Allwinner **H616**
- **RAM:** **512 MB DDR3 or DDR3L**
- **Boot storage:** **8 GB eMMC** (primary)
- **Recovery / reprovisioning:** **microSD slot** (for boot/recovery and for re-flashing eMMC images)
- **Networking:**  
  - **Ethernet** (10/100) via RJ45 MagJack  
  - **Integrated Wi‑Fi** (basic connectivity only) via an on-board module  
  - **2× USB‑A host** so a user can plug in an external USB Wi‑Fi dongle if they want different/stronger capabilities
- **Power:** **USB‑C 5 V input** (simple sink, no PD negotiation required)
- **UI I/O:** SPI TFT + **8 buttons** (to preserve the existing UI contract)

### 0.2 Baseline “known-good” references (what we steal shamelessly)
We aren’t starting from vibes. We reuse battle-tested integration patterns:

- **Orange Pi Zero2 (H616)** schematic set as the primary reference for:
  - H616 integration patterns (boot straps, UART debug, SD/eMMC usage)
  - DDR3 topology
  - Wi‑Fi module connected via SDIO
  - USB‑C 5 V input circuitry patterns
- **Raspberry Pi Zero 2 W** as the “behavioral/performance target” for your software and UX (512 MB-class usage, low power UI device).  
  *Important:* we’re not copying their silicon, only matching the “this feels fast enough” profile.

### 0.3 Board philosophy: “instrumented bring-up board”
This first PCB revision should be *friendly to real engineering*:

- lots of **test points** on rails and critical buses,
- **jumpers / 0Ω links** to isolate subsystems,
- easy access to **UART console** and **boot/recovery straps**,
- a microSD recovery path that doesn’t require exotic jigs.

You can always delete debug affordances for a production board later.

---

## 1) Locked specs vs adjustable knobs

### 1.1 Locked specs (must match the project brief)
- Allwinner **H616** compute core.
- **512 MB** external DRAM (DDR3 or DDR3L).
- **8 GB eMMC** as the primary storage device.
- **Ethernet** (10/100) via MagJack.
- **2× USB‑A host** ports.
- **USB‑C** connector used as a **5 V power input**.
- **Basic integrated Wi‑Fi**, plus ability to use an external USB Wi‑Fi dongle.
- **microSD** socket for recovery / provisioning and re-flashing eMMC.
- **SPI TFT + 8 buttons** (UI contract).

### 1.2 Adjustable knobs (choose for risk reduction / sourcing)
- DDR vendor and exact part (Micron/Samsung/etc.), as long as it matches the electrical + package constraints.
- PMIC vs discrete power tree (prototype-friendly is fine; repeatable is better).
- Ethernet PHY choice (RMII 10/100 PHY family, widely available).
- USB topology (direct host ports vs USB2 hub + fanout).
- Integrated Wi‑Fi module choice (SDIO module with certified radio vs chip + RF layout).

---

## 2) High-level architecture blocks

### 2.1 System block view
**Power entry (USB‑C 5V)** → power tree (core rails, DRAM rail, I/O rails) → H616  
H616 connects to:

- **DDR3/DDR3L** (external DRAM)
- **eMMC** (SMHC2 recommended)
- **microSD** (SMHC0 recommended, boot/recovery/provisioning)
- **Ethernet** (EMAC0 → RMII PHY → MagJack)
- **USB** (2× USB‑A host, plus optional OTG access for recovery)
- **Wi‑Fi** (SDIO/SDC1 → module)
- **UI** (SPI TFT + GPIO buttons)
- **Debug** (UART0 console + recovery straps + test points)

---

## 3) Subsystem architecture specs (broad, implementation-free)

Each subsystem has:
- **Purpose**
- **Top-level requirements**
- **Recommended reference to clone**
- **Bring-up / debug affordances**
- **Low-level doc to write next**

### 3.1 Compute core: Allwinner H616 integration

**Purpose:** run embedded Linux reliably, with predictable boot and debug access.

**Top-level requirements**
- Correct H616 package/library mapping (symbol ↔ footprint ↔ ball map must be perfect).
- 24 MHz reference clock (crystal) and required decoupling.
- Reset and boot strap signals accessible in *some* form (pads, header, or jumpers).

**Recommended reference to clone**
- Orange Pi Zero2 H616 schematic pages for SoC + debug block.
- Your internal doc: *Integrating the Allwinner H616 SoC into a KiCad PCB Design*.

**Bring-up / debug affordances**
- Always-accessible **UART0 console** header (3.3 V TTL level).
- A **RESET** button (or at least pads) and a clean reset supervisor strategy.
- Access to **FEL** / boot straps via test pads or jumpers so you can force recovery paths.

**Low-level doc to write next**
- `REF_SOC_H616.md`  
  Includes: pin mux plan, clocks, reset strategy, boot strap truth table, JTAG decision (if used), KiCad net naming conventions.

---

### 3.2 DRAM: 512 MB DDR3 vs DDR3L (selection strategy)

**Purpose:** external RAM for H616 (board must be stable under temperature, supply droop, and real workloads).

**Top-level requirements**
- **Capacity:** 512 MB total.
- **Bus width/topology:** prefer the same topology as a known-good H616 board (e.g., Orange Pi uses a “x16 ×2” style arrangement for a 32-bit bus).
- **Voltage:** H616 supports DRAM supply choices for DDR3 (1.5 V) and DDR3L (1.35 V). The board must provide the chosen rail cleanly.

**Recommended selection strategy (minimize risk + maximize sourcing flexibility)**
- Prefer **DDR3L parts that are backward compatible with 1.5 V** operation. This gives you a sourcing escape hatch:
  - If DDR3L pricing/availability is good, run at **1.35 V**.
  - If you want to clone Orange Pi’s rail plan exactly on the first spin, you can still run that DDR3L at **1.5 V** (many Micron DDR3L devices explicitly support 1.5 V “compatible mode”).
- Rationale: you don’t want your first hardware risk to be “our power tree was clever.” You want it to be boring.

**Bring-up / debug affordances**
- Test points for **VCC_DRAM** and any DRAM reference rails (VREF if present in your design approach).
- Optional 0Ω links or shunt locations in the DRAM rail path for current measurement during stress testing.

**Low-level doc to write next**
- `REF_DDR3_DDR3L.md`  
  Includes: exact memory topology options for 512 MB, stack-up assumptions, routing constraint plan, decoupling strategy, and a “choose DDR3 vs DDR3L” decision table based on availability + rail complexity.

---

### 3.3 Boot storage: eMMC (primary)

**Purpose:** robust storage for a device that will be power-cycled and carried around.

**Top-level requirements**
- **Primary boot and rootfs storage:** 8 GB eMMC, soldered.
- Use the H616’s SD/eMMC controller interface recommended by references (commonly **SMHC2** for eMMC on H616 designs).
- Design for conservative signal integrity (keep traces short, well referenced, no weird stubs).

**Bring-up / debug affordances**
- Test pads for key eMMC lines (CLK/CMD/DAT[0..7]/RST/DS if used) *only if they don’t compromise routing*.
- Ability to disable eMMC (0Ω link in series with CLK or a “DNP strap” scheme) so you can prove microSD boot independently if needed.

**Low-level doc to write next**
- `REF_EMMC.md`  
  Includes: bus width decision (4-bit vs 8-bit), voltage mode (3.3 vs 1.8 I/O), boot partition strategy, and how to image/flash safely.

---

### 3.4 Recovery / provisioning: microSD slot (secondary)

**Purpose:** easy reflashing and “I bricked it” recovery without special tools.

**Top-level requirements**
- Add a **microSD socket** connected to the SoC’s SD controller used for SD boot/recovery (commonly **SMHC0**).
- The recovery flow should support:
  1) booting a known-good image from microSD, and
  2) writing a new eMMC image from userspace (or via scripted tooling).

**Bring-up / debug affordances**
- Card detect pin (optional but helpful).
- Physical access: place the microSD socket so it can be used while the board is inside your prototype enclosure (or at least during bench testing).

**Low-level doc to write next**
- `REF_MICROSD_RECOVERY.md`  
  Includes: boot priority plan, recovery image format, and a reproducible “flash eMMC from SD” procedure.

---

### 3.5 Ethernet: 10/100 wired networking

**Purpose:** reliable baseline networking, independent of Wi‑Fi.

**Top-level requirements**
- Use **H616 EMAC0** → **RMII 10/100 PHY** → **RJ45 MagJack**.
- Use conservative EMI/ESD practice at the connector edge (ESD diodes, “magnetics keepout” discipline, clean grounding strategy).

**Recommended reference to clone**
- Your internal doc: *Self‑Soldered USB‑A and Ethernet IO Implementation…*
- Orange Pi Zero2 is gigabit-capable, but its “connector-zone” patterns still matter.

**Bring-up / debug affordances**
- PHY reset accessible (test pad or jumper).
- PHY strap pins easy to verify (series resistors/0Ω links where appropriate).
- LEDs wired in a way you can interpret quickly (link/activity).

**Low-level doc to write next**
- `REF_ETHERNET_RMII.md`  
  Includes: PHY candidate shortlist, RMII clocking plan (50 MHz source), RJ45 shield/chassis grounding plan, and layout keepouts.

---

### 3.6 USB: two USB‑A host ports (and optional hub)

**Purpose:** easy external accessory support; also a “escape hatch” for external Wi‑Fi dongles.

**Top-level requirements**
- Exactly **2× USB‑A female** ports on the PCB edge (hand-solderable connectors are fine).
- Each port must have:
  - USB2 D+/D− integrity (short, matched differential routing)
  - ESD protection at the connector
  - **controlled VBUS power** (current-limited power switch per port is strongly recommended)

**Topology choice**
- **Option A (simplest):** route two native H616 host ports directly to the two USB‑A connectors.
- **Option B (common SBC pattern):** use one upstream host port into a USB2 hub, then fan out to the two USB‑A connectors.

The final choice depends on how many host ports you need for other internal purposes; for a first spin, pick the simplest path that matches the known-good reference patterns.

**Bring-up / debug affordances**
- Fault flags from power switches to a GPIO (optional but very useful).
- Jumpers/0Ω links on VBUS so you can isolate a port if a peripheral is misbehaving.

**Low-level doc to write next**
- `REF_USB_HOST.md`  
  Includes: topology selection, per-port power switch options, ESD part options, and routing rules encoded as KiCad constraints.

---

### 3.7 Integrated Wi‑Fi: “basic and boring”

**Purpose:** onboard connectivity without requiring a dongle.

**Top-level requirements**
- Integrated Wi‑Fi should support only routine connectivity (STA/AP as needed), not specialized radio behavior.
- Avoid raw RF design in the first revision if you can:
  - Prefer a **pre-certified Wi‑Fi module** (SDIO interface) with an integrated antenna or a u.FL connector.

**Recommended reference to clone**
- Orange Pi Zero2 schematic shows an on-board Wi‑Fi/BT module wired via **SDIO (SDC1)** and includes explicit “Wi‑Fi IO voltage (1.8 V vs 3.3 V)” configuration with resistors.
- Your internal doc: *Integrating an On‑Board Wi‑Fi Subsystem into the H616 Watchdog PCB…*

**Bring-up / debug affordances**
- Ability to power-gate the Wi‑Fi module (enable pin, or at least a 0Ω link).
- Test pad for module enable/reset signals.

**Low-level doc to write next**
- `REF_WIFI_SDIO.md`  
  Includes: module shortlist, SDIO pin mapping, IO voltage plan (1.8 vs 3.3), antenna keepout rules, and a minimal “bring-up checklist” in Linux (device tree expectations).

---

### 3.8 UI: SPI TFT + 8 buttons

**Purpose:** preserve your existing user interaction model (already proven on Pi Zero 2 W).

**Top-level requirements**
- SPI connection for TFT (SCLK/MOSI/CS + DC/RESET/backlight control).
- Exactly **8 buttons** available as GPIO inputs (active-low with pull-ups is a good default).
- Optional status LED output.

**Prototype-friendly approach**
- Use a connector/header compatible with your existing TFT module wiring, OR define a clear pin mapping that your device tree and config can adopt.
- Do not hide these lines under “mystery FPC pinouts” on the first spin unless you already have a proven mechanical plan.

**Low-level doc to write next**
- `REF_UI_SPI_GPIO.md`  
  Includes: minimum display spec (128×128 class), signal list, debounce strategy (HW/SW), ESD considerations for user buttons, and the mapping contract for software.

---

### 3.9 Debug & test instrumentation (prototype emphasis)

**Purpose:** make bring-up fast and failures diagnosable.

**Minimum debug interface**
- **UART0 console header** (3-pin or 4-pin with 3.3 V reference).
- Boot strap access (pads/jumpers) for:
  - FEL and/or boot select behavior (so you can enter recovery without desoldering)
- Clear reset access (button + pads).

**Strongly recommended prototype features**
- Test points for every rail:
  - 5V_IN, 3V3, 1V8, VDD_CPU, VDD_SYS, VCC_DRAM, Wi‑Fi rail(s), PHY rail
- Optional current-sense footprints:
  - 0Ω → swap to shunt later, or use a removable jumper
- “Isolation links” (0Ω resistors) so you can disable:
  - Wi‑Fi module
  - Ethernet PHY
  - USB VBUS per port
  - (optionally) eMMC clock line

**Low-level doc to write next**
- `REF_DEBUG_BRINGUP.md`  
  Includes: a bring-up sequence checklist, measurement points, expected rail voltages, and failure triage flowcharts.

---

### 3.10 Manufacturing and DFM assumptions

**Build model (Scenario 2)**
- Factory assembles **all SMT/BGA** (H616, RAM, eMMC, PHY/module, passives).
- You hand-solder **through-hole / chunky connectors**:
  - RJ45 MagJack
  - 2× USB‑A
  - headers (UART, buttons/display connector if through-hole)

**Prototype-friendly board requirements**
- Prefer a stack-up suitable for DDR (often 6 layers) rather than forcing a 4-layer board into DDR sadness.
- Place connectors on edges with mechanical reinforcement (through-hole tabs).
- Use generous courtyards around hand-soldered connectors.

**Low-level doc to write next**
- `REF_DFM_ASSEMBLY.md`  
  Includes: recommended stack-up, assembly notes for BGA, connector soldering approach, and DNP strategy for optional parts.

---

## 4) Decisions to lock early (to prevent thrash)

These are the “if we change this later we regret it” decisions:

1) **microSD is included** (recovery/provisioning), not “maybe later.”  
2) Choose **DDR strategy**:
   - (Preferred for first spin) follow Orange Pi’s DDR3 rail plan, but select DDR3L parts that tolerate 1.5 V, so sourcing is flexible.
3) Choose **USB topology** (direct vs hub).  
4) Choose **Wi‑Fi module interface** (SDIO module is preferred over raw RF chip).  
5) Choose **Ethernet PHY** and RMII clock source approach (make this boring and repeatable).  
6) Decide whether you expose **USB OTG** (for FEL/USB recovery) beyond microSD + UART.  
   - For a first prototype, microSD + UART is usually enough.

---

## 5) Reference-doc map (what you’ll write next)

This architecture doc is the “table of contents” for detailed implementation docs:

- `REF_SOC_H616.md`
- `REF_DDR3_DDR3L.md`
- `REF_EMMC.md`
- `REF_MICROSD_RECOVERY.md`
- `REF_ETHERNET_RMII.md`
- `REF_USB_HOST.md`
- `REF_WIFI_SDIO.md`
- `REF_UI_SPI_GPIO.md`
- `REF_DEBUG_BRINGUP.md`
- `REF_DFM_ASSEMBLY.md`

Each reference doc should end with:
- a “KiCad implementation checklist”
- a “test / validation checklist”
- a “risk register” section (what can go wrong and how we detect it)

---

## 6) Appendix — quick “must-have signals” list (for schematic planning only)

> This is not a map. It’s a reminder list so nothing gets forgotten in hierarchy planning.

- Power: 5V_IN, 3V3, 1V8, VDD_CPU, VDD_SYS, VCC_DRAM, Wi‑Fi rails, PHY rail
- Boot/recovery: FEL / BOOT_SEL / RESET access
- Debug: UART0 TX/RX/GND
- Storage: eMMC (CLK/CMD/DAT), microSD (CLK/CMD/DAT + optional DET)
- Ethernet: RMII + MDC/MDIO + PHY reset + MagJack LED lines
- USB: 2× D+/D− pairs + per-port VBUS control
- Wi‑Fi: SDIO (CLK/CMD/DAT0..3) + enable/reset
- UI: SPI TFT (SCLK/MOSI/CS/DC/RESET/BL) + 8 GPIO inputs + optional LED

---

## 7) Sources used (internal docs)

- `h616_watchdog_board_breakdown_v2.md`
- `H616 Watchdog Board KiCad Design Document.md`
- `H616 Watchdog PCB Architecture Deep Dive for KiCad Memory and Boot Storage Subsystem.md`
- `DDR3 vs DDR3L on an Allwinner H616 Watchdog Board Selection Architecture and KiCad Implementation Guide.md`
- `Self‑Soldered USB‑A and Ethernet IO Implementation for the H616 Watchdog PCB in KiCad.md`
- `Integrating an On‑Board Wi‑Fi Subsystem into the H616 Watchdog PCB in KiCad.md`
- `Integrating the Allwinner H616 SoC into a KiCad PCB Design.md`
- `pcb_info.md`
- `h616_custom_board_bom_and_fab_breakdown.md`

## 8) Sources used (external reference boards and datasheets)
- Orange Pi Zero2 H616 schematic set (for known-good H616 patterns)
- Allwinner H616 datasheet (boot modes, interface availability)
- Raspberry Pi Zero 2 W product page (performance/UX baseline)
- USB‑C UFP sink guidance (Rd on CC pins)
- Micron DDR3L datasheet (1.35 V and 1.5 V compatible mode guidance)

