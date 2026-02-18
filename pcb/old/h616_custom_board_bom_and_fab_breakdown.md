# H616 “watchdog” board — parts breakdown, what gets hand‑soldered, and what you send the fab

This doc assumes you’re going with **Scenario 2**: **the factory does all SMT/BGA**, and you **hand‑solder only the big through‑hole / chunky connectors** (RJ45, USB‑A, headers). It also assumes you want to keep your current project’s UI hardware expectations:

- Display backend includes **ST7735 over SPI** (`/dev/spidev0.0`) and uses GPIO **DC=25, RST=27, BL=24** in your current codebase.
- **8 buttons** (Up/Down/Left/Right/Select/Key1/Key2/Key3) are currently mapped to Linux GPIO lines **6,19,5,26,13,21,20,16** by default in your UI crate.

(Those pin numbers can be changed later via device‑tree / gpiod mapping; the point is: your board needs *at least* these signals exposed somehow.)

---

## 0) Non‑negotiables vs flexible knobs

### Non‑negotiables (locked in for this doc)
- **SoC:** Allwinner **H616** (quad Cortex‑A53). The linux-sunxi page summarizes memory support and the fact you get multiple USB2 hosts + Ethernet MAC(s). 
- **RAM:** **512MB DDR3/DDR3L** (minimum viable for your project; you previously said 512MB–1GB). H616 supports DDR3/DDR3L.  
- **Soldered storage:** **8GB eMMC** (BGA).  
- **Ethernet:** at least **10/100** with an RJ45 MagJack. (H616 has MACs; you still need PHY + magnetics.)  
- **USB-C power input:** 5V in (no PD negotiation required if you just want “dumb” 5V).  
- **2× USB‑A host ports** on the PCB.  
- **Display:** ST7735-class SPI TFT (your code explicitly supports ST7735).  
- **Buttons:** 8 total (your project uses 8).  
- **Wi‑Fi (single interface):** simplest cost path is **external USB Wi‑Fi dongle** (you plug it into your USB‑A).

### Flexible knobs (you can swap these without changing the whole architecture)
- DDR3/DDR3L *brand* and *speed bin* (as long as the package + timing works).
- eMMC vendor / package-compatible alternate.
- Ethernet PHY vendor (RMII PHY choices are common).
- USB hub controller (there are several USB2 hub ICs).
- Power tree implementation (PMIC vs discrete bucks + LDOs).
- Mechanical choices: connector brands, shielding cans, mounting holes, case integration.
- Display: either a bare panel+FPC (more complex) or a cheap **module** with 2.54mm header (simpler).

---

## 1) “What am I actually soldering?” (Scenario 2)

### You hand‑solder (through‑hole / big pins)
These are the classic “dumb parts” where hand soldering is totally realistic:

- **RJ45 MagJack** (8 pins + tabs; mechanically chunky)  
  Example: HR911105A price tiers: **$1.289 @10+**, **$0.9828 @93+**. citeturn1search0  
- **2× USB‑A receptacles** (through‑hole style is easiest)  
  LCSC example for a cheap Type‑A TH connector shows **~$0.0467 @10+**, **~$0.0372 @100+**. citeturn2search2turn2search8  
- **Headers** (2.54mm) for:
  - ST7735 display module (if you use a module instead of a raw panel)
  - optional UART/debug header
  - optional GPIO expansion header

### Factory (SMT/BGA) must do
- **H616 SoC** itself (TFBGA) citeturn2search7turn0search6  
- **DDR3/DDR3L BGA**  
- **eMMC BGA** (and it typically triggers **X‑ray inspection**) citeturn1search7turn3search0  
- Ethernet PHY (QFN/QFP)
- USB hub IC
- all the “sand” (passives, decoupling, terminations, ESD, etc.)
- all power ICs (bucks/LDOs) and the sequencing glue
- crystals/oscillators

### Pitfalls of Scenario 2 (the real ones)
- **Connector alignment & mechanical stress:** USB‑A + RJ45 take plug/unplug force. Use:
  - footprints with **through‑hole shell tabs**
  - **stitching vias** to ground around the connector area
  - **mechanical keepouts** so the connector sits flush
- **Thermal mass:** those metal shells wick heat. Use a chisel tip, lots of flux, and preheat if you can.
- **Bridging is still possible:** especially on USB‑C (if you ever hand‑solder a Type‑C). But you can avoid that by having the factory place the Type‑C (it’s SMT anyway).
- **ESD:** if you omit ESD parts to save pennies, you buy reliability problems. Keep ESD at USB and the RJ45 side.

Bottom line: you do **not** need machine precision, but you do need **clean joints** and **mechanical stability**.

---

## 2) Recommended “minimum viable” architecture (hardware blocks)

**Power (USB‑C 5V in)**
- USB‑C receptacle + CC resistors (advertise as a sink; simplest “5V only” design)
- 5V rail feeds:
  - 5V USB‑A VBUS (through current limit switch)
  - buck/LDO rails for the SoC + DDR + PHY + eMMC

**Compute**
- H616 + DDR3/DDR3L (512MB target)
- eMMC 8GB (boot + rootfs)

**USB**
- H616 USB2 host → USB hub IC (FE1.1S class) → 2× USB‑A ports
- Wi‑Fi dongle plugs into one of those ports

**Ethernet**
- H616 MAC ↔ RMII PHY ↔ RJ45 MagJack

**UI**
- SPI display header/module (ST7735)
- 8 button inputs (either:
  - 8 SMD tact switches on the PCB, or
  - a small connector to an external button board)

---

## 3) Ballpark BOM (component costs) — with real price references where possible

These are *component* costs only. They exclude shipping/import/VAT, and they exclude your PCB fab/assembly charges until the next section.

### Core silicon + memory (big cost drivers)

| Block | Example part | Why | Unit price ballpark |
|---|---|---|---|
| SoC | Allwinner **H616** (LCSC listing example) | Your chosen platform | **$11.11 @10+**, **$8.15 @952+** citeturn0search6 |
| RAM | Micron **MT41K256M16…** (4Gbit x16) | 512MB when paired appropriately / configured | LCSC shows **~$1.96 @10+**, **~$1.55 @100+** citeturn5search8 |
| eMMC | KIOXIA **THGBMJG6C1LBAIL** (8GB, BGA‑153) | Soldered storage; common and supported | **$7.23 @10+**, **$5.71 @100+** citeturn1search1turn1search7 |

Notes:
- eMMC BGA parts often require **X‑ray inspection** in assembly flows. citeturn1search7turn3search0  
- H616 supports DDR3/DDR3L/LPDDR variants (so you have sourcing flexibility). citeturn2search7  

### Ethernet + USB (the “ports” you care about)

| Block | Example part | Unit price ballpark |
|---|---|---|
| Ethernet PHY | Microchip **LAN8720A** | **$0.615 @10+**, **$0.538 @100+** citeturn0search3 |
| RJ45 MagJack | HanRun **HR911105A** | **$1.289 @10+**, **$0.983 @93+** citeturn1search0 |
| USB2 hub | Terminus **FE1.1S** | **$0.511 @10+**, **$0.3545 @100+** citeturn1search4 |
| USB‑A connectors (x2) | cheap TH Type‑A | **~$0.0467 @10+**, **~$0.0372 @100+** citeturn2search2turn2search8 |
| USB‑C receptacle | HC‑TYPE‑C‑16P‑01A class | **~$0.0666 @50+**, **~$0.0528 @1000+** citeturn2search5 |

### UI parts (buttons + display)

| Block | Example part | Unit price ballpark |
|---|---|---|
| 8 tactile switches | TS‑1187A‑B‑A‑B (SMD) | **~$0.0198 each @1+**, cheaper in volume citeturn3search5 |
| ST7735 display module | 1.44" 128×128 ST7735 | **~$2.80 each** (example listing) citeturn1search6 |

### Optional: microSD instead of eMMC (if you ever want it)
- microSD socket TF‑01A shows **~$0.138 @50+** range. citeturn2search0  
But: for a “disposable tool” that gets power-cycled and tossed in bags, eMMC tends to be more reliable than microSD in practice.

### Wi‑Fi dongle cost (external USB)
Cheapest path is plugging in a USB adapter. Generic AR9271 examples show prices like **$9.99**. citeturn6search2  
(You already know why you’d pick a chipset with strong Linux monitor-mode support; I’m not going to write “how to attack people’s Wi‑Fi” instructions here.)

---

## 4) “What do I pay per unit?” — realistic *first* cost model

Below is a **sanity-check** cost model. Any line marked **ESTIMATE** is the part you tune by picking specific regulators/ESD/crystals and by shrinking the PCB.

### A) Component subtotal (10 units, very typical first run)
Using the cited price tiers above + a conservative “misc power + passives” allowance:

- Core silicon + memory (SoC + DDR + eMMC): ~ **$11.11 + $1.96 + $7.23 = $20.30**
- Ethernet + USB silicon + connectors: ~ **$0.62 + $0.51 + $1.29 + $0.07 + $0.09 = $2.58**
- Buttons (8): ~ **$0.16**
- **Misc passives / ESD / crystals / regulators**: **$4.00 (ESTIMATE)**

**Component subtotal ≈ $27.0 – $30.0** (depending on your power-tree choices).

### B) PCB fabrication & assembly (what the fab charges you)

#### PCB fab
JLCPCB states a **6‑layer 100×100mm** board “begins at **$35.1 (5 pcs)**”. citeturn4search0  
That’s ~$7/board at prototype quantities *before* shipping.

#### Assembly fees
JLCPCB’s official pricing breakdown includes:
- setup fee (economic) **$8**
- stencil **$1.5**
- SMT per-joint pricing
- **X‑ray inspection fee** (for BGA/hidden joints), e.g. **$1.57/pc for 1–10 pcs** citeturn3search0  

So for 10 boards with multiple BGAs, you should expect:
- fixed fees amortized across 10
- per-board x‑ray
- per-joint placement cost (BGAs have lots of “joints”)

**Rule of thumb:** assembly overhead ends up in the **$3–$7 per board** range for small runs, depending on your part library mix and how many “extended” parts you use. citeturn3search0turn3search2  

### C) Total “board-only” and “complete device”
Putting it together:

- **Board-only (no Wi‑Fi dongle, no display module):** typically **~$35–$45** for a 10‑unit run  
- **Complete device** (add ST7735 module + Wi‑Fi dongle): typically **~$45–$60** for a 10‑unit run citeturn1search6turn6search2  

At **~100 units**, the BOM drops and the fab/assembly overhead amortizes better; seeing **~$30 board-only** becomes plausible if you keep the PCB compact and the assembly “basic parts” heavy.

---

## 5) What you must send the fab (files + formats)

### Minimum to order **bare PCBs**
- **Gerbers** (all copper, mask, silkscreen, paste layers)
- **NC drill** files
- **Board outline** (Edge.Cuts)

### Minimum for **PCBA (assembly)**
JLCPCB’s assembly flow expects **Gerbers + BOM + CPL (pick‑and‑place)** as the core trio. citeturn0search5  

You should also include (highly recommended):
- **Assembly drawings** (PDF): top/bottom, polarity marks, refdes visibility
- **Fab drawing** (PDF): stackup notes, impedance targets, controlled impedance callouts if any
- **Programming/test notes**: how you want boards tested (even if it’s “power + UART log”)

### Recommended project output folder structure (so you don’t go insane)
Inside your KiCad repo:

```
hw/
  watchdog-h616/
    kicad/
      watchdog-h616.kicad_pro
      watchdog-h616.kicad_sch
      watchdog-h616.kicad_pcb
      sym-lib/              # custom symbols
      fp-lib/               # custom footprints
      3d/                   # STEP/WRL models
    manufacturing/
      v0.1/
        fab/
          gerbers/
          drill/
          fab_drawing.pdf
          stackup_impedance.pdf
        assembly/
          bom.csv
          cpl.csv
          assembly_drawing_top.pdf
          assembly_drawing_bot.pdf
          readme_pcba_notes.md
    docs/
      bringup/
      test/
```

Naming scheme suggestion:
- `watchdog-h616_v0.1_<date>_fab.zip`
- `watchdog-h616_v0.1_<date>_pcba.zip`

---

## 6) What comes back from the fab vs what you must buy yourself

### If you choose “factory SMT/BGA only; you hand-solder connectors”
**You receive:**
- Fully reflowed PCB with H616 + DDR + eMMC + PHY + hub + passives + regulators, etc.
- Unpopulated footprints for:
  - RJ45 MagJack
  - 2× USB‑A
  - headers (display / UART / optional GPIO header)

**You provide:**
- The through-hole parts above (or you can let them do it as manual/THT—just costs more).

---

## 7) Board-design effort reality check (how much work is involved)

Designing an H616 + DDR + eMMC board is **not** “Raspberry Pi header soldering” difficulty. The hard parts are:

1) **Power tree & sequencing**  
   Multiple rails, ramp order, and decoupling discipline.

2) **High-speed memory routing (DDR)**  
   - length matching
   - controlled impedance
   - BGA fanout strategy
   - careful reference planes

3) **Bring-up**  
   - boot ROM expectations
   - early UART output
   - power integrity debugging

Boot media notes: the sunxi boot layout has SoC-specific quirks; e.g., H616/H618 uses an alternate SPL location at **256KB** and mainline U‑Boot handles the layout. citeturn2search6  

**Translation:** expect at least one revision spin. Two is normal. Three is not rare.

---

## 8) Things that should be their own follow-up docs (worth doing next)

These are too big for this single “BOM + fab breakdown” doc, but you *will* want them:

1) **Power Tree + Sequencing Spec**
   - exact rails, current budgets, regulator selection
   - inrush/current-limit for USB VBUS
   - thermal model and copper pours

2) **DDR3 Routing & Stackup Plan**
   - layer stack proposal (likely 6 layers)
   - impedance targets
   - length matching budget and constraints file

3) **Boot + Flashing Workflow**
   - dev UART logging steps
   - SD image layout for first boot and recovery
   - eMMC provisioning and rollback strategy
   (Sunxi boot layout details matter here.) citeturn2search6  

4) **Manufacturing Test Plan**
   - “does it power” test
   - UART “hello world” test
   - Ethernet link test
   - USB hub enumeration test
   - display + buttons smoke test

---

## 9) Quick “starter BOM” list (what you’re actually getting)

### From the fab (SMT/BGA assembled)
- H616 SoC citeturn0search6turn2search7  
- DDR3/DDR3L 512MB class citeturn5search8  
- eMMC 8GB citeturn1search1turn1search7  
- Ethernet PHY citeturn0search3  
- USB2 hub citeturn1search4  
- power ICs + passives (chosen in detailed BOM)
- ESD protection + crystals/oscillators (chosen in detailed BOM)

### You solder
- RJ45 MagJack citeturn1search0  
- 2× USB‑A connectors citeturn2search2turn2search8  
- headers (display / UART / optional GPIO)

### You plug in
- ST7735 display module citeturn1search6  
- USB Wi‑Fi dongle citeturn6search2  

---

## Appendix A — concrete “example totals” (so you can sanity check)

These are not quotes, just a math check using the price references above.

### Example: 10 units (board-only, no Wi‑Fi dongle, no display)
- Components: **~$27–$30**
- PCB + assembly overhead: **~$8–$15**
→ **~$35–$45 per board** (very typical for first 10)

### Example: 10 units complete device
Add:
- ST7735 module ~$2.8 citeturn1search6  
- USB Wi‑Fi dongle ~$10 citeturn6search2  
→ **~$45–$60 per complete unit**

---

## Appendix B — your “send to fab” checklist (copy/paste)

- [ ] KiCad design rule check (DRC) clean  
- [ ] ERC clean  
- [ ] footprints validated for: H616 BGA, DDR BGA, eMMC BGA (pin‑1 markers!)  
- [ ] Gerbers exported (top/bottom copper, mask, silk, paste, edge cuts)  
- [ ] Drill files exported  
- [ ] BOM exported (MPN, quantity, refdes, LCSC/JLC part numbers where applicable) citeturn0search5  
- [ ] CPL/centroid exported (refdes, X/Y, rotation, side) citeturn0search5  
- [ ] Assembly drawings (PDF) with polarity + orientation notes  
- [ ] Fab drawing (PDF) with stackup notes  
- [ ] PCBA notes: “do not populate” (DNP) list + which connectors are hand-soldered  
- [ ] Bring-up note: UART pins + expected boot log

