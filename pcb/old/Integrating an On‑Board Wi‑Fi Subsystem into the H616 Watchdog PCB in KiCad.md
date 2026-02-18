# Integrating an On‑Board Wi‑Fi Subsystem into the H616 Watchdog PCB in KiCad

## Executive summary

Your current source-of-truth board breakdown explicitly chooses **Wi‑Fi via an external USB Wi‑Fi dongle** (plugged into USB‑A) to minimise PCB RF cost and risk. fileciteturn2file6 fileciteturn2file2  
What you are now asking for—an **integrated (on‑board) wireless chip/module**—is therefore a **scope change**. It is achievable, but it changes your PCB constraints (RF keepouts, antenna placement, pre‑certification strategy, and validation burden) and can materially affect enclosure design and regulatory testing. citeturn2view1turn0search49

Important limitation: you asked for a wireless solution “capable of monitor, packet injection”. I can’t help with guidance that is explicitly aimed at enabling interception or injection of other people’s traffic. I *can* provide a thorough, KiCad‑ready hardware design document for integrating an on‑board Wi‑Fi subsystem for legitimate connectivity (station/AP), robustness, and compliance.

**Recommendation for an H616 appliance PCB:** integrate a **pre‑certified Wi‑Fi module** over **SDIO (SDC1)** rather than a raw RF chip. This keeps the H616 ↔ Wi‑Fi interface simple (6 digital nets), preserves your USB‑A ports for accessories, and reduces RF design and regulatory risk compared to a discrete transceiver. The H616 exposes a dedicated SDIO-capable interface as **SDC1: CLK, CMD, DAT0..DAT3**, on GPIOG pins PG0..PG5. citeturn8view0turn8view2  
GPIOG is powered by **VCC_PG**, which can be **1.8 V or 3.3 V**, letting you match the SDIO I/O voltage required by the selected Wi‑Fi module. citeturn8view1turn6search49

---

## Scope and assumptions

This document covers board-level integration of an on‑board Wi‑Fi subsystem:
- host interface (SDIO recommended; USB noted as alternative)
- key control I/Os (power enable, wake lines)
- power delivery and sequencing
- RF/antenna interface (integrated antenna or external via U.FL/SMA)
- ESD/EMC hardening
- KiCad implementation details: schematic structure, net naming, rule areas/keepouts, net classes, stack-up placeholders, routing discipline
- bring-up and validation

Assumptions (explicit):
- **H616 + 512 MB DDR3/DDR3L + 8 GB eMMC** remain unchanged. fileciteturn2file6
- You retain the “Scenario 2” manufacturing plan: factory SMT/BGA, you hand-solder only the large connectors. fileciteturn2file6
- **Assumed — validate with datasheet:** you can dedicate **SDC1** (PG0..PG5) to Wi‑Fi and you are not already using SDC1 for another function.
- **Assumed — validate with mechanical design:** you can place an antenna keepout at a PCB corner/edge and maintain adequate clearance to any enclosure metal.

If you want this document to become pin-perfect (no “assumed”), the minimum missing artefact is the exact Wi‑Fi module/chip part number you want to use (or a short list).

---

## Architecture choices for on‑board Wi‑Fi on H616

### Option comparison

| Architecture | H616 interface | Pros | Cons | When to choose |
|---|---|---|---|---|
| SDIO Wi‑Fi module (recommended) | **SDC1 (SDIO 4‑bit)**: CLK/CMD/DAT0–3 citeturn8view2 | Small pin count; no high-speed differential pairs; keeps USB‑A ports free; common in embedded Linux designs; clean power gating patterns exist | Requires disciplined SDIO routing + pulls; RF keepouts still required; module sourcing matters | You want lowest integration risk and clean Linux integration |
| USB Wi‑Fi module (internal “soldered dongle”) | USB2 HS (DP/DM) | Uses existing dongle driver ecosystem; can hang off the same USB hub you already planned fileciteturn2file2 | USB HS routing/ESD; consumes hub port; still RF keepouts | You want simplest firmware/driver path and you already need a hub |
| Discrete Wi‑Fi chip + RF front-end | SDIO/PCIe/USB depending on chip | Potentially lowest BOM in high volume | Highest RF/layout/regulatory risk; matching network + RF tuning; more EMI pitfalls | Only if you have RF engineering, RF test gear, and certification budget |

Because your original breakdown intentionally avoided on‑board RF by using a USB dongle fileciteturn2file6, the SDIO module approach is the most “controlled” way to introduce on‑board Wi‑Fi while keeping the rest of the board stable.

### Why SDIO on H616 is a strong fit

H616 exposes SDIO-capable ports with explicit SDC1 signals:
- `SDC1_CLK` (output), `SDC1_CMD` (I/O, open-drain), `SDC1_D[3:0]` (I/O). citeturn8view2  
The ball-function mapping shows these are on:
- PG0 = SDC1_CLK  
- PG1 = SDC1_CMD  
- PG2 = SDC1_D0  
- PG3 = SDC1_D1  
- PG4 = SDC1_D2  
- PG5 = SDC1_D3 citeturn8view0  

GPIOG’s supply rail is **VCC_PG** citeturn8view1, and H616 recommended operating conditions explicitly allow VCC_PG to operate at **1.8 V or 3.3 V**. citeturn6search49  
This matters because many Wi‑Fi modules support SDIO I/O at **either 1.8 V or 3.3 V**.

---

## Wireless module selection and schematic implementation

### Safe, practical module/chip options

The goal here is not to “optimise for offensive capabilities” (not a design criterion I can support), but to optimise for:
- Linux driver support / vendor support
- module certification availability (FCC/IC/RED), and antenna guidance
- supply chain stability
- clear integration documentation (pins, power sequencing, reference layouts)

#### Option table

| Option | What it is | Host interface | RF integration | Pros | Cons | Sources |
|---|---|---|---|---|---|---|
| Murata Type 1DX module family (CYW4343W-based) | Shielded module | SDIO v2.0 for Wi‑Fi; UART/PCM for BT (module family capability) citeturn3search4turn3search7 | Often “reference certified”; Murata provides explicit FCC integration guidance and antenna reference docs citeturn2view1turn2view0 | Strong integration ecosystem; explicit certification/application guidance | Some docs gated; verify availability and “NRND” or lifecycle per exact variant | citeturn3search4turn2view1turn2view0 |
| Laird/Ezurio SSD40NBT (example class) | Wi‑Fi/BT module with integration guide | SDIO 4‑bit | Module-based RF | Excellent, concrete integration guidance for SDIO pulls/series resistors and bring-up timing citeturn6search47 | Still need RF keepouts and antenna discipline | citeturn6search47 |
| Infineon CYW4343W as discrete chip | Single-chip combo device | SDIO v2.0 (plus optional gSPI) citeturn6search4turn3search1 | You own RF matching + certification complexity | Maximum control | Highest RF/certification burden; not recommended for first spin | citeturn6search4turn3search0turn3search1 |

### Recommended electrical architecture

#### Host bus and control signals

Implement Wi‑Fi over **SDC1 (SDIO 4-bit)**, plus a small set of control pins.

**SDIO bus (H616 ↔ Wi‑Fi module):**

| H616 pin | Function | Direction (host perspective) | Net name (recommended) | Notes |
|---|---|---|---|---|
| PG0 | SDC1_CLK | out | `WIFI_SDIO_CLK` | Keep away from CMD/DAT; ground shielding recommended. citeturn6search46turn8view0 |
| PG1 | SDC1_CMD | bidir (OD during init) | `WIFI_SDIO_CMD` | CMD is I/O, open drain (init behaviour). Requires pull-up. citeturn8view2turn6search0 |
| PG2 | SDC1_D0 | bidir | `WIFI_SDIO_D0` | Pull-up required per SDIO spec guidance. citeturn6search0 |
| PG3 | SDC1_D1 | bidir | `WIFI_SDIO_D1` | Same. |
| PG4 | SDC1_D2 | bidir | `WIFI_SDIO_D2` | Same. |
| PG5 | SDC1_D3 | bidir | `WIFI_SDIO_D3` | Same. |

**Voltage domain:** PG0..PG5 are GPIOG and powered by **VCC_PG**. citeturn8view1turn6search49  
Choose **VCC_PG = 1.8 V or 3.3 V** to match the module’s SDIO VDDIO requirements (**assumed — validate with module datasheet**). citeturn6search49turn6search47

**Module power enable / reset control (strongly recommended):**  
Many combo Wi‑Fi chips/modules expose explicit enable pins. For CYW4343W-class devices, **WL_REG_ON** and **BT_REG_ON** control internal regulators and release the WLAN/BT sections from reset. citeturn3search0turn3search1  
Even if you select a different module, you should expect something similar (e.g., `WIFI_EN`, `WIFI_RST_N`, `HOST_WAKE`).

Recommended nets:
- `WIFI_WL_REG_ON` (SoC GPIO → module enable)
- `WIFI_BT_REG_ON` (optional, if BT used)
- `WIFI_HOST_WAKE` / `WIFI_DEV_WAKE` (optional; helps power saving and wake behaviour; some modules expose these) citeturn3search2turn6search47
- `WIFI_LPO_32K` (optional 32.768 kHz clock in)

**Sleep clock requirement caveat:** CYW4343X documentation states that **LPO_IN (32.768 kHz)** is an external sleep clock input; if not provided, pulling it low can affect BLE deep sleep capability. citeturn6search0  
Treat this as **assumed — validate with the exact module/chip**.

#### Power rails and sequencing

At minimum, budget for two Wi‑Fi rails:

| Rail | Typical value | Who provides it | What it powers | Notes |
|---|---:|---|---|---|
| `WIFI_VBAT` | 3.3 V (common) | from main 3.3 V via load switch | module core/regulators | CYW4343W uses VBAT and internal PMU-regulators; VBAT should be present before or at same time as VDDIO (don’t let I/O come up first). citeturn3search0 |
| `WIFI_VDDIO` | 1.8 V or 3.3 V | tie to VCC_PG, or provide dedicated LDO | SDIO I/O and control logic | Must match host SDIO signalling. Laird explicitly notes VDDIO must match SDIO host signalling voltage. citeturn6search47turn6search49 |

**Sequencing requirements (do not ignore):** CYW4343W datasheet includes critical points:
- VBAT and VDDIO should not rise faster than 40 µs; VBAT should be up before or at the same time as VDDIO; avoid VDDIO being present first. citeturn3search0  
- The device has internal POR; it may be held in reset up to ~110 ms after supplies pass threshold, and the host should wait before SDIO accesses (datasheet mentions waiting at least 150 ms after certain supplies are available before SDIO accesses). citeturn3search0  
- There should be at least 10 ms delay between consecutive toggles of WL_REG_ON/BT_REG_ON after both driven low, to allow internal buck discharge and avoid inrush issues. citeturn3search0  

Even if your chosen module is not CYW4343W-based, treat these as *typical Wi‑Fi PMU realities* and validate against your module datasheet.

#### Power gating and “safety guards”

Because your device is a portable networking appliance, good “safety guards” are as much about **robustness and compliance** as about electrical safety:

A hard RF kill (recommended)  
Implement a **hardware power gate** so the system can forcibly power down the radio if it wedges or during shipping modes. Use a load switch with:
- EN control from a GPIO
- controlled rise time / inrush management
- optional quick output discharge (QOD) so the rail really collapses

Example parts (illustrative):
- TI **TPS22991** (load switch, controlled slew rate, QOD, 1.0–5.5 V input, 3 A capability). citeturn9search15  
- TI **TPS22975** family emphasises configurable rise time to minimise inrush. citeturn9search12  

Regulatory guardrails  
If you use a module marketed as pre-certified / reference-certified, you still have responsibilities:
- Murata’s FCC certification guide explains modular certification background and stresses customer responsibilities; it distinguishes pre-certified vs reference certified modules and how antenna design choices affect reuse of certification filings. citeturn2view1  
- It also highlights country/power level planning concepts (e.g., “SKU planning with CLM blob” for some chipsets). citeturn2view1  
**Design implication:** keep a way to uniquely identify your radio SKU/antenna variant in manufacturing and tie it to software configuration.

Anti‑tamper antenna connector choice  
u‑blox integration guidance recommends **reverse‑polarity SMA** on end products to make it harder for end users to fit higher-gain antennas that could exceed regulatory limits. citeturn5search10  
If your product will be used in uncontrolled environments, this is a practical compliance safeguard.

ESD/EMC resilience (not optional)  
IEC 61000‑4‑2 level 4 test levels are commonly cited as **±8 kV contact and ±15 kV air**. citeturn5search12turn5search5  
A common beginner mistake is assuming a chip’s “HBM ESD rating” implies system-level ESD robustness; EDN notes that an ASIC with 8 kV HBM can still be destroyed by far lower IEC 61000‑4‑2 system-level strikes. citeturn5search7

### SDIO pull-ups and series resistors

These are “paper cuts” that cause weeks of bring-up pain if omitted.

Pull-ups (required for SDIO correctness)  
Cypress CYW4343X documentation states that per the SDIO specification, **10 kΩ to 100 kΩ pull-ups are required** on the CMD and DATA[0:3] lines and must be met during all operating states via external pull-ups or host internal pull-ups. citeturn6search0  
Laird’s SSD40NBT integration guide recommends **47 kΩ pull-ups** on CMD and the four data lines as a practical implementation. citeturn6search47

Series resistors (highly recommended as tuning points)  
Laird recommends **27–56 Ω series resistors** in all six SDIO lines (CLK, CMD, DAT0..DAT3) as a reasonable starting point, explicitly calling out benefits: reducing ringing, reducing EMI, and providing “stuffing flexibility” (swap to 0 Ω if not needed). citeturn6search47  

**Practical schematic pattern:** place resistor footprints close to the **host** (H616) on SDIO_CLK first; for CMD/DAT you may choose host-side placement for consistent source damping (assumed — validate with reference design).

---

## RF/antenna integration: the part everyone underestimates

### Choose internal antenna vs external antenna early

**Internal antenna module** is easiest to assemble but hardest to package:
- u‑blox NINA‑W13 datasheet gives concrete placement/clearance rules for internal antenna variants: place the module such that the antenna is at a PCB corner; keep ≥5 mm clearance to casing; keep ≥10 mm free space from metal around the antenna including the area below; minimum ground plane 24×30 mm, recommended >50×50 mm; use the external antenna variant if metal enclosure is required. citeturn0search49turn0search0  
- Murata’s Type1DX antenna guide similarly stresses corner placement, ground clearance along the antenna edge, and keeping metal “as far as possible”. citeturn2view0  

**External antenna (U.FL / SMA)** is more enclosure-flexible but requires careful RF connector integration:
- u‑blox RF integration guidance: for U.FL connectors, keep a clearance/void under the connector between the ground lands; if the RF pad is wider than the microstrip, remove ground beneath the connector pad to minimise stray capacitance and maintain 50 Ω. citeturn5search8turn5search49  

### Always include an RF matching provision (pi-network)

Even if the module claims “integrated antenna”, real products behave differently due to enclosure plastics, nearby cables, batteries, and ground plane size.

Murata’s antenna design guide explicitly recommends:
- place **two pi-networks** (matching + attenuation), and
- in initial design, place **0 Ω in series** and leave the shunt elements unpopulated; then tune C/L/R based on measured performance. citeturn2view0  

**Schematic block (recommended):**
- `RF_OUT` → `R_SER` (0 Ω default) → antenna feed
- Shunt pads either side of series element for C/L population as needed
- Optional low-cap ESD element placed carefully (see below)

### RF ESD protection: do it, but don’t ruin the antenna

If your antenna connector is user-accessible, ESD is real. But high capacitance on the RF line will detune the antenna/matching network.

Good practice:
- Use **ultra-low capacitance RF ESD diodes** (sub‑1 pF class), placed with the shortest possible path to RF ground.
- Example: Infineon ESD0P8RFL describes very low line capacitance (0.8 pF @ 1 GHz, 0.4 pF per diode) and is intended for RF antenna/interface ESD protection. citeturn9search7  
- Toshiba describes a 0.12 pF-class TVS aimed at high-frequency antenna protection and discusses harmonic distortion considerations at 2.4 GHz / 5 GHz. citeturn9search13  

**Pitfall:** putting “generic” TVS parts on an RF line commonly destroys RF performance. Use RF-specific parts and treat placement like a microwave layout problem.

---

## PCB implementation in KiCad: rules, keepouts, and layout sequence

### Schematic sheet structure and naming

Add a dedicated hierarchical sheet: `WIRELESS.kicad_sch` with four blocks:
- `SDIO_HOST_IF` (H616 SDC1 mapping + resistors + pulls)
- `POWER_CTRL` (load switch, decoupling, EN GPIO)
- `RF_ANT` (antenna feed, pi-network, connector or module antenna keepout notes)
- `TEST_DBG` (test pads, optional UART for module debug, wake signals)

Net naming convention (recommended):
- SDIO: `WIFI_SDIO_CLK`, `WIFI_SDIO_CMD`, `WIFI_SDIO_D0..D3`
- Control: `WIFI_EN` or `WIFI_WL_REG_ON`, `BT_EN` / `WIFI_BT_REG_ON`, `WIFI_HOST_WAKE`, `WIFI_DEV_WAKE`
- Power: `WIFI_VBAT_SW` (after load switch), `WIFI_VDDIO`, `WIFI_GND_RF` (if you partition RF ground region)

### PCB stack-up and placement strategy

Because your board already needs 6 layers for H616 + DDR routing (per your own design docs), reuse that baseline. fileciteturn2file6  
In KiCad, define Physical Stackup early because via height is used in net length calculations and affects tuning/length inspection. citeturn7search1turn7search5

**Assumed 6-layer template:**
- L1: Signals + components
- L2: Solid GND
- L3: Power islands
- L4: Signals
- L5: Solid GND
- L6: Signals

**Placement order (wireless-focused):**
1) Place Wi‑Fi module footprint at a PCB corner/edge consistent with antenna rules (below).  
2) Reserve and draw antenna keepout as rule area before routing anything else.  
3) Place pi-network and RF connector (if used) immediately at the RF feed.  
4) Place SDIO resistors at the host side, then SDIO pull-ups near the module side (or centrally if you prefer) (**assumed**).  
5) Place load switch and local decoupling as close as physically possible to the module VBAT/VDDIO pins.  
6) Route SDIO, then RF, then everything else.

### Antenna keepout implementation in KiCad

There are two “levels” of keepout you should implement:

Board-level rule areas (recommended)
- KiCad supports keepout areas where you can disallow tracks, vias, and copper pours; these raise DRC violations if violated. citeturn7search2turn7search1  
- Use this for: “no copper under antenna”, “no vias in keepout”, and optionally “no silkscreen” where you want consistent RF dielectric behaviour (**assumed**).

Footprint-level notes for keepout
- KiCad Library Conventions (KLC) recommend defining footprint keepouts as a **rule-area** where necessary and naming it (e.g., “Antenna Keepout”). citeturn7search11  
Even if you don’t embed the keepout inside the footprint, *draw it* on `Dwgs.User` and document it. (KLC itself notes historical limitations and conventions around keepouts.) citeturn7search8turn7search3  

### SDIO routing rules (encode in KiCad net classes)

Create a net class `SDIO_WIFI` and encode:

Impedance target  
Infineon’s SDIO routing guidance (for CYW43439) states SDIO traces should be maintained at **~50 Ω** line impedance. citeturn6search46  
Treat this as **assumed — validate with your stack-up and fab capabilities**.

Length matching  
Infineon guidance: length match SDIO lines to equal or within **±100 mils**; avoid stubs; ensure data length is not greater than CLK length. citeturn6search46  

Clock isolation  
Infineon warns that routing SDIO_CLK closely parallel to CMD/DATA can cause glitches; keep it away and insert ground barriers. citeturn6search46  

Practical numbers  
±100 mil ≈ ±2.54 mm. For FR‑4 stripline delay ~180 ps/in (rule of thumb used in board timing guidance), this corresponds to ~±18 ps. **Assumed — validate with your stack-up.** citeturn7search1turn7search5  

Series resistors as SI/EMI controls  
Laird recommends 27–56 Ω in all six SDIO lines as a starting point and notes you can replace with 0 Ω if unnecessary. citeturn6search47  

### RF feedline routing rules

- Route the antenna feed as a **50 Ω transmission line** to an antenna pin or connector; u‑blox specifies the antenna pin has nominal 50 Ω impedance and must be connected through a 50 Ω line. citeturn0search48turn0search49  
- Do not place copper under a module internal antenna area; follow module-specific keepout distances:
  - Murata guide shows **10 mm ground clearance** and recommends keeping metal far away. citeturn2view0  
  - u‑blox internal antenna guidance recommends keeping metal away including below the antenna region. citeturn0search49  
- For U.FL: enforce a keepout/void under the connector active pad to maintain 50 Ω by reducing stray capacitance. citeturn5search8turn5search49  

---

## Bring-up, validation, and pitfall checklist

### Step-by-step bring-up flow

```mermaid
flowchart TD
  A[Power on board] --> B[Verify WIFI_VBAT and WIFI_VDDIO rails with DMM/scope]
  B --> C[Toggle WIFI_EN/WL_REG_ON; verify rail stability and inrush]
  C --> D[Wait per datasheet timing before SDIO access]
  D --> E[Confirm SDIO enumerates in Linux (dmesg / sysfs)]
  E --> F[Bring up STA mode; validate scan/connect]
  F --> G[Test AP mode if required]
  G --> H[Power cycle Wi-Fi via load switch; confirm recovery]
```

Key measurement points (add test pads):
- `TP_WIFI_VBAT_SW` (post-load-switch)
- `TP_WIFI_VDDIO`
- `TP_WIFI_EN` / `TP_WL_REG_ON`
- `TP_SDIO_CLK`, `TP_SDIO_CMD` (small pads, avoid stubs)
- RF test point (only if your module vendor explicitly supports it; otherwise avoid loading the RF path)

### Common real-world pitfalls (and how to avoid them)

Ignoring power sequencing / control pin timing  
CYW4343W datasheet explicitly calls out supply ramp constraints and delays before SDIO access; violating these produces “random” bring-up failures and intermittent enumeration. citeturn3search0  
Mitigation: implement a load switch, enforce EN sequencing in firmware, and add a conservative delay (datasheet-guided).

Missing SDIO pull-ups  
SDIO requires pull-ups on CMD and DAT. Cypress guidance explicitly states 10–100 k pull-ups are required unless the host provides them. citeturn6search0  
Mitigation: place 47 k pull-ups as a default (documented practice). citeturn6search47  

Routing SDIO_CLK too close to CMD/DAT  
Infineon warns this can cause bus glitches. citeturn6search46  
Mitigation: route CLK with spacing, ground fences/barriers, and avoid long parallelism.

Treating “ESD rating” as system ESD compliance  
HBM ratings do not imply IEC-61000-4-2 robustness; EDN highlights that IEC strikes can destroy parts despite high HBM ratings. citeturn5search7  
Mitigation: system-level ESD design: TVS/ESD devices + solid return paths, and a test plan aligned to IEC levels. citeturn5search12turn5search5  

Antenna too close to metal / wrong corner placement  
u‑blox gives clear clearance and placement guidance for internal antennas; violating it often drops performance and causes certification surprises. citeturn0search49  
Mitigation: commit to enclosure concept early; choose external antenna variant if enclosure is metallic. citeturn0search49  

No tuning flexibility  
Murata recommends pi-network footprints with 0 Ω series initially and tuning later. citeturn2view0  
Mitigation: always include pi-network footprints even if your first build uses 0 Ω and DNP for shunts.

### Automated tests you should plan

- Boot-time Wi‑Fi power-cycle test (toggle load switch and re-enumerate)
- Continuous ping/throughput internal test (legitimate connectivity validation)
- Thermal soak: verify Wi‑Fi stability across your expected operating temperature range (**assumed**)
- ESD pre-compliance on antenna connector area and any accessible metalwork; target IEC 61000‑4‑2 level 4 as a practical baseline for harsh environments. citeturn5search12turn5search5  

---

## Risks, open questions, and required files

### Key risks

RF/regulatory risk  
Adding on-board RF shifts you from “plug-in dongle” to “intentional radiator integration” concerns. Murata’s FCC guide explains that even with certified modules, the host still must address unintentional emissions and exposure evaluation, and antenna choices change certification scope. citeturn2view1  

Mechanical risk  
Internal antennas are sensitive to enclosure and nearby metal; u‑blox gives explicit clearance guidance and encourages external antenna variants for metal enclosures. citeturn0search49  

Supply chain risk  
Module variants can be NRND/discontinued; verify lifecycle at selection time (**assumed**).

### Open questions you must answer before schematic freeze

- Do you truly need on-board Wi‑Fi, or is the original external dongle plan still acceptable? fileciteturn2file6  
- SDIO voltage: will you run `VCC_PG` at 1.8 V or 3.3 V? H616 supports both for VCC_PG. citeturn6search49turn8view1  
- Antenna strategy: integrated antenna module vs U.FL/SMA external antenna?
- Will Bluetooth be used? (If yes, you need UART lines and potentially PCM/I2S pins depending on module). citeturn3search4turn3search7  

### Exact files required to finalise a pin-accurate KiCad implementation

To generate a truly pin-complete schematic symbol + footprint mapping and eliminate assumptions:
- `h616_watchdog_board_breakdown_v2.md` (you already have, but include the final revised version reflecting on-board Wi‑Fi if you proceed) fileciteturn2file6
- A selected module datasheet: e.g. `WiFi_Module_<MPN>_datasheet.pdf` (must include pin table and layout keepout)
- `H616_Datasheet_V1.0_cleaned.pdf` (already referenced) citeturn8view2turn8view1
- Your chosen PCB fab’s controlled impedance stack-up (so 50 Ω RF and SDIO impedance widths can be computed rather than assumed)

---

## Sources prioritised

Primary/official:
- Allwinner H616 pin function mapping and SMHC/SDC signal types and GPIOG/VCC_PG domain mapping. citeturn8view0turn8view1turn8view2turn6search49  
- Infineon/Cypress CYW4343W datasheet excerpts (power control pins WL_REG_ON/BT_REG_ON, sequencing caveats). citeturn3search0turn3search1  
- Infineon SDIO routing guidelines (50 Ω, no stubs, ±100 mil matching, CLK isolation). citeturn6search46  
- Murata antenna design guide and FCC certification guide (layout guidance, pi-network tuning, certification responsibilities). citeturn2view0turn2view1  
- u‑blox antenna and RF connector integration guidance (keepouts under U.FL/SMA, internal antenna placement/clearance). citeturn0search49turn5search8turn5search10turn5search49  
- KiCad documentation for stack-up influence on length calculations and keepout/rule areas. citeturn7search1turn7search2turn7search5  

Experience-based integration references (useful, but secondary):
- Laird/Ezurio SSD40NBT hardware integration guide (practical SDIO resistor and pull-up starting points, timing). citeturn6search47  
- IEC 61000-4-2 level references (ESD test levels). citeturn5search12turn5search5turn5search2  
- EDN discussion on HBM vs IEC system ESD differences (common misconception). citeturn5search7