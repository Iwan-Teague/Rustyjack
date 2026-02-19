# DDR3 vs DDR3L Strategy and KiCad v9.0.4 Implementation Plan for the H616 Watchdog PCB

## Executive summary

Section 3.2 of the project architecture document frames DRAM as a *risk‑dominating subsystem* for first‑spin success: the board must deliver **512 MB** external DRAM that remains stable under temperature, supply droop, and real workloads, while keeping the power tree “boring” and debuggable. The architecture’s explicit strategy is to prefer **DDR3L parts that remain compatible with 1.5 V operation** so the design can run at **1.35 V** when sourcing allows, but can fall back to **1.5 V** to match the Orange Pi Zero 2’s reference rail plan if needed (source: `/mnt/data/KeyCAD_H616_Watchdog_PCB_Architecture_v0.md`, §3.2; also `/mnt/data/DDR3 vs DDR3L on an Allwinner H616 Watchdog Board Selection Architecture and KiCad Implementation Guide.md`, “Recommended selection strategy”).  

The practical KiCad v9.0.4 plan is to:  
build DDR as a dedicated hierarchical sheet with **net naming that supports KiCad’s diff‑pair recognition**, implement **rail testability** (VCC_DRAM/VDDQ, VDD18_DRAM, VREF, optional VTT footprints), and encode the *minimum enforceable* DDR constraints directly into KiCad **netclasses + custom rules** (`.kicad_dru`) so routing cannot drift silently. KiCad v9’s support for **multiple netclasses per net** and rule‑language helpers like `A.hasNetclass()` materially improves how you encode “BGA escape” vs “DDR tuned” constraints in the same net (vs earlier versions). citeturn9search5turn11search2  

Because H616 DRAM initialisation is software‑sensitive, the first‑spin selection should bias toward a topology that is known to work on shipping H616 boards (Orange Pi Zero 2 uses a **two‑device x16×2** pattern on its DDR sheet, despite the sheet title containing “DDR4” wording; the schematic content is DDR3). Source: Orange Pi schematic v1.3 page rendering at `/mnt/data/.../opi_p07_ddr4_16x2.png`; plus `/mnt/data/Orange_Pi_Zero2_H616_Reference_Extraction.md` noting the “DDR4” wording mismatch.

## Architecture intent and decisions required by section 3.2

The architecture doc’s section 3.2 is short but precise: it locks **capacity = 512 MB**, recommends copying a known‑good topology (Orange Pi’s x16×2 style 32‑bit bus pattern is explicitly mentioned), and states that the board must cleanly provide whichever DRAM rail is chosen (DDR3 at 1.5 V or DDR3L at 1.35 V). It also mandates bring‑up affordances: **test points** on the DRAM rail(s), and optional **0 Ω links/shunt footprints** to measure DRAM current under stress (source: `/mnt/data/KeyCAD_H616_Watchdog_PCB_Architecture_v0.md`, §3.2).  

H616 itself is widely documented as supporting multiple DRAM types including DDR3 and DDR3L. citeturn10search0

### Assumptions and required decisions

The internal docs deliberately leave some implementation parameters “implementation‑free”, so the DDR workstream must explicitly decide them before layout lock. The table below is written so you can copy it into your project’s decision log.

| Item | Why it matters | Options | Recommendation for first spin | Status |
|---|---|---|---|---|
| DRAM topology for 512 MB | Dominates routing complexity, bootloader DRAM init risk, and BOM availability | A) **32‑bit bus** using **2× x16** devices; for 512 MB this implies **2× 2Gb x16**. B) **16‑bit bus** using **1× 4Gb x16** (=512 MB). (source: `/mnt/data/DDR3 vs DDR3L…Guide.md`, “Memory organisation choices for 512 MB”) | **Prefer topology that matches a known‑good H616 board**, i.e., the Orange Pi 2‑device pattern *if* 2Gb x16 parts are realistically sourceable. Otherwise accept 16‑bit single‑device and plan for more software DRAM‑timing work. | Required |
| DDR3 vs DDR3L voltage choice | Sets VDD/VDDQ rail value(s), power dissipation, and sourcing flexibility | DDR3 1.5 V; DDR3L 1.35 V (often with 1.5 V compatible mode) | Follow architecture strategy: **select DDR3L parts that can run at 1.5 V**, implement a rail that can be strapped to 1.35 V or 1.5 V (source: `/mnt/data/KeyCAD_H616_Watchdog_PCB_Architecture_v0.md`, §3.2; `/mnt/data/DDR3 vs DDR3L…Guide.md`, “Recommended selection strategy”) | Required |
| VREF generation | VREF noise is a common DDR bring‑up killer; must track VDDQ/2 | A) Simple divider + filtering (as Orange Pi shows). B) Divider + buffer. C) Dedicated VREF IC | **Copy Orange Pi’s divider pattern** initially, but reserve footprint space for a buffer/IC if SI/PI results demand it. Micron guidance treats VREF as analogue and sets tight noise expectations. citeturn6search3turn8search3 | Required |
| VTT rail | Needed only if you implement external termination to VDDQ/2 | A) Omit (ODT + point‑to‑point). B) Implement VTT regulator/island | For a compact SoC+1–2 DRAM board, **omit in Rev‑A** but **reserve footprints** (terminator packs + small VTT regulator region) as “cheap insurance”. Micron provides explicit VTT island guidance. citeturn8search26turn11search2 | Required |
| PCB stack‑up | Drives impedance, propagation delay, escape routing feasibility | 4‑layer vs 6‑layer; dielectric thicknesses etc. | **Assume 6‑layer FR‑4** baseline. This aligns with internal design intent and Micron’s point‑to‑point guidance that poor SI makes 3–4 layer DDR largely unusable except limited cases. citeturn8search3turn1search44 | Required |
| DDR impedance targets | Needed for width/spacing and field‑solver validation | Common framing: ~50 Ω SE, ~100 Ω differential | Treat as **targets** until fab stack‑up is fixed; Intel and ST provide spacing/topology and matching constraints that presume controlled return paths. citeturn1search2turn1search42turn8search3 | Required |
| Manufacturing class (track/space/vias) | Determines whether BGA escape can be done without via‑in‑pad | Standard vs HDI; via drill and annular ring | If using H616 TFBGA (0.65 mm pitch), expect the DDR region to require “tight” rules; encode “BGA escape” separately from “main DDR routing” (KiCad v9 multi‑netclass helps). citeturn9search5turn11search2 | Required |

## Selection rationale and part selection guidance for 512 MB

### DDR3 vs DDR3L rationale grounded in the project docs

At PCB level, the key difference between DDR3 and DDR3L is the **VDD/VDDQ rail**: 1.5 V vs 1.35 V nominal (source: `/mnt/data/DDR3 vs DDR3L…Guide.md`, “What actually changes”). DDR3L is recommended as the default because it reduces power/thermal stress and, crucially for procurement, can be chosen such that it remains usable at 1.5 V if the system must fall back (source: `/mnt/data/DDR3 vs DDR3L…Guide.md`, “Why DDR3L is usually the better default”; `/mnt/data/KeyCAD_H616_Watchdog_PCB_Architecture_v0.md`, §3.2).  

From a vendor‑data perspective, DDR3L devices specify strict rail behaviour: VDD and VDDQ must track each other, and VREFDQ is expected to be ~0.5×VDD and track it; noise is constrained around nominal. citeturn6search1turn6search3

### Part selection guidance

Your internal docs already point to a practical package class: **x16 FBGA‑96** DDR3/DDR3L devices are prevalent in SBCs and match what Orange Pi demonstrates (source: `/mnt/data/DDR3 vs DDR3L…Guide.md`, “Recommended DRAM type…”; Orange Pi DDR sheet snippet path below).  

For **512 MB**, the architecture‑consistent choices are:

- **Topology‑matching** approach (lowest H616 risk): 32‑bit bus using **two x16 devices** (Orange Pi pattern). For 512 MB total this means **two 2Gb x16** devices. This is flagged in internal docs as “recommended for reduced risk” but depends heavily on whether 2Gb x16 devices are obtainable (source: `/mnt/data/DDR3 vs DDR3L…Guide.md`, “Memory organisation choices for 512 MB”).  
- **BOM‑simplifying** approach (higher software/init risk): 16‑bit bus using **one 4Gb x16** device (=512 MB). This reduces routing load but may require more work to ensure the DRAM init path is correct for a 16‑bit topology (source: `/mnt/data/DDR3 vs DDR3L…Guide.md`, “Memory organisation choices for 512 MB”).  

#### Example part shortlist

These are **examples** to anchor footprints and availability work; final choices must be validated against current supply, datasheets, and the H616 DRAM init configuration you intend to use.

| Topology | Example family / MPN (optional) | Density / width | Voltage class | Package | Notes |
|---|---|---|---|---|---|
| 16‑bit, 1 device | Micron MT41K256M16 family | 4Gb x16 | DDR3L | FBGA | Internal docs cite this family as a solid DDR3L reference. (source: `/mnt/data/DDR3 vs DDR3L…Guide.md`, “Recommended DRAM type…”) |
| 16‑bit, 1 device | SK hynix H5TC4G63EFR‑RDA | 4Gb x16 | DDR3L | FBGA | Mentioned in internal doc; verify ballout against actual datasheet before committing. (source: `/mnt/data/DDR3 vs DDR3L…Guide.md`) |
| 16‑bit, 1 device | Samsung K4B4G1646E‑BYMA | 4Gb x16 | DDR3 | FBGA | Internal doc notes use in H616 reference boards; aligns with a “copy rail plan” 1.5 V strategy if needed. (source: `/mnt/data/DDR3 vs DDR3L…Guide.md`) |
| 32‑bit, 2 devices | “2Gb x16 DDR3(L)” parts (exact MPN TBD) | 2Gb x16 ×2 | DDR3 or DDR3L | FBGA | Best matches Orange Pi bus width pattern for H616, but may be harder to source; treat as a gating procurement item. (source: `/mnt/data/DDR3 vs DDR3L…Guide.md`, “Memory organisation choices…”) |

## Power rails, sequencing, and decoupling strategy

### Rail requirements and what must exist electrically

Your internal guidance breaks the DDR subsystem into a “rail contract”: the SoC has DRAM‑related domains (notably **VCC_DRAM** and **VDD18_DRAM** in the project docs), while the memory devices require VDD/VDDQ plus references and calibration components (sources: `/mnt/data/DDR3 vs DDR3L…Guide.md`, “Power rails…” and “A concrete rail plan…”; `/mnt/data/H616 Watchdog PCB Architecture Deep Dive for KiCad Memory and Boot Storage Subsystem.md`, “DDR3/DDR3L rails…”).  

At the DRAM‑device level, vendor data emphasises:

- **VDD and VDDQ must track** (they are frequently the same rail on discrete designs). citeturn6search1  
- **VREFDQ** should be ~0.5×VDD and must meet tight noise limits; VTT is a *system termination supply* and is not applied directly to the DRAM package. citeturn6search3  
- If you use VTT, Micron recommends VTT be applied after VDDQ to avoid latch‑up and provides layout guidance for VTT/VREF islands and termination placement. citeturn8search26turn8search3  

### Practical rail plan aligned to section 3.2

A first‑spin plan that matches section 3.2’s “boring but flexible” strategy:

- Implement **VDD18_DRAM (1.8 V)** for the H616 DRAM domain (source: `/mnt/data/DDR3 vs DDR3L…Guide.md`, “A concrete rail plan…”).  
- Implement **VCC_DRAM / VDDQ** as a strap‑selectable rail: 1.35 V (DDR3L) or 1.5 V (DDR3). This can be done with one regulator and alternative feedback resistor pads, rather than two separate rails, preserving bring‑up simplicity (design intent: `/mnt/data/KeyCAD_H616_Watchdog_PCB_Architecture_v0.md`, §3.2; rail listing: `/mnt/data/DDR3 vs DDR3L…Guide.md`, “A concrete rail plan…”).  
- Implement **VREF** as **VDDQ/2** using a 1% divider + filtering as the baseline. This is exactly what Orange Pi shows (divider resistors + local capacitors), and internal docs explicitly cite it as an “example pattern in an H616 design” (source: `/mnt/data/DDR3 vs DDR3L…Guide.md`, “VREF is the silent killer”; Orange Pi snippet below).  
- Treat **VTT** as **optional** unless you intentionally add external parallel termination. Keep PCB footprint options so you can add it in Rev‑B without re‑floorplanning (source: `/mnt/data/DDR3 vs DDR3L…Guide.md`, “Do you need VTT?”).  

### Decoupling strategy and placement discipline

Internal project docs specify starting points:

- For each DRAM device, place multiple **0.1 µF** close to VDD/VDDQ pins/balls (the doc explicitly expects you to “tuck into the BGA escape keepout” where feasible).  
- For **VREF**, place **0.1 µF + 1 µF** close to the generator and near VREF pins/balls (source: `/mnt/data/H616 Watchdog PCB Architecture Deep Dive for KiCad Memory and Boot Storage Subsystem.md`, “Decoupling values and placement starting points”).  

External references reinforce why this matters: Micron’s point‑to‑point note explicitly frames VREF stability as critical and recommends tight control around nominal. citeturn8search3turn6search3  

### Orange Pi DDR sheet pattern you can reuse

The Orange Pi Zero 2 schematic v1.3 DDR page (rendered below) is directly useful because it shows, in one place, the *working* set of small but easy‑to‑forget items: a VREF divider/filter network, an **RZQ ≈ 240 Ω** calibration resistor, and dense local decoupling clusters. Note the title block includes “DDR4 16×2”; the *sheet content* is labelled DDR3 and implements DDR3‑style devices, matching the project’s instruction to treat this as DDR3. (Primary source: `/mnt/data/Orange_Pi_Zero2_H616_Schematic_v1.3.pdf`, rendered page image path shown.)

![Orange Pi Zero2 H616 schematic snippet showing DDR3 x16×2 style page, VREF divider, and decoupling clusters (rendered from `/mnt/data/user-SUTpJAuJBTIbdk1CotO8q8Xq__c1df8433-8eab-4a22-8cd8-05f35cac6ac1/667400b63b85494e9ce5f13de54d580a/mnt/data/opi_p07_ddr4_16x2.png`)](/mnt/data/user-SUTpJAuJBTIbdk1CotO8q8Xq__c1df8433-8eab-4a22-8cd8-05f35cac6ac1/667400b63b85494e9ce5f13de54d580a/mnt/data/opi_p07_ddr4_16x2.png)

What to copy verbatim into your schematic (and what to parameterise):
- **Copy**: VREF divider + local decoupling pattern (internal docs cite this as a working H616 example).  
- **Copy**: RZQ resistor concept (typically 240 Ω ±1%). This aligns with external DDR3/3L configuration references that use **RZQ = 240 Ω ±1%** as the calibration basis. citeturn1search43  
- **Parameterise**: whether ZQ is shared or per‑device, and whether CK termination is populated by default; keep footprints to allow both during bring‑up (see pitfalls section below).

## KiCad v9.0.4 technical implementation plan

### Schematic construction and net naming

Internal docs and KiCad constraints converge on one rule: **net naming is not cosmetic**; it is how you make KiCad enforce and tune DDR.

Use the project’s recommended KiCad‑friendly naming (source: `/mnt/data/H616 Watchdog PCB Architecture Deep Dive for KiCad Memory and Boot Storage Subsystem.md`, “DDR3/DDR3L bus grouping”; `/mnt/data/DDR3 vs DDR3L…Guide.md`, “Net naming scheme…”):

- Clock diff pair: `DDR_CK_P`, `DDR_CK_N`
- Per‑lane strobes: `DDR_DQS0_P`, `DDR_DQS0_N`, `DDR_DQS1_P`, `DDR_DQS1_N` (and lanes 2/3 if 32‑bit)
- Byte lanes: `DDR_DQ0..DDR_DQ7`, `DDR_DM0` etc.
- Address/control: `DDR_A0..DDR_A15`, `DDR_BA0..DDR_BA2`, `DDR_RESET_N`, `DDR_CKE`, `DDR_CS_N`, `DDR_ODT`, `DDR_RAS_N`, `DDR_CAS_N`, `DDR_WE_N`

This is also aligned with KiCad’s diff‑pair tooling expectations: KiCad identifies diff pairs by consistent `*_P/_N` naming and provides diff‑pair constraints via custom rules. citeturn11search2turn11search1  

### Net grouping and lane mapping diagram

Use explicit grouping to prevent mistakes during layout and debugging, especially if you choose the 32‑bit (two‑device) topology.

```mermaid
flowchart LR
  subgraph H616[H616 DRAM Interface]
    CK[DDR_CK_P / DDR_CK_N]
    AC[Addr/Cmd/Ctrl: DDR_A*, DDR_BA*, DDR_*]
    subgraph L0[Lane 0]
      DQS0[DDR_DQS0_P/N]
      DQ0[DDR_DQ0..7 + DDR_DM0]
    end
    subgraph L1[Lane 1]
      DQS1[DDR_DQS1_P/N]
      DQ1[DDR_DQ8..15 + DDR_DM1]
    end
    subgraph L2[Lane 2 optional]
      DQS2[DDR_DQS2_P/N]
      DQ2[DDR_DQ16..23 + DDR_DM2]
    end
    subgraph L3[Lane 3 optional]
      DQS3[DDR_DQS3_P/N]
      DQ3[DDR_DQ24..31 + DDR_DM3]
    end
  end

  subgraph DRAM_A[DDR3(L) Device A]
    A_L0[L0 nets]
    A_L1[L1 nets]
  end

  subgraph DRAM_B[DDR3(L) Device B]
    B_L2[L2 nets]
    B_L3[L3 nets]
  end

  CK --> DRAM_A
  CK --> DRAM_B
  AC --> DRAM_A
  AC --> DRAM_B
  L0 --> A_L0
  L1 --> A_L1
  L2 --> B_L2
  L3 --> B_L3
```

Interpretation:
- **16‑bit topology**: only L0 and L1 exist; DRAM_B block is absent.  
- **32‑bit topology**: lanes are split across two packages (exact mapping is board‑specific; make it explicit on the schematic regardless of routing flexibility).

### Netclasses and KiCad v9.0.4 rules

KiCad v9 introduced **multiple net classes per net** and the helper `A.hasNetclass()` for rule conditions. This matters because you may want the same net to be both “DDR” and “BGA escape” and to inherit properties by priority order. citeturn9search5turn0search6  

Also: custom design rules are stored in a project `.kicad_dru` file, and KiCad’s own docs stress it must be committed alongside the PCB and project files (and edited inside KiCad, not in an external editor). citeturn0search1turn11search36  

#### Recommended netclasses (placeholders where stack‑up is still unknown)

Use netclasses to group DDR by function first; then apply more specific constraints via `.kicad_dru` once the stack‑up is known. Values below are *intentionally conservative placeholders*; where controlled impedance or fab capability is required, it is marked as **no specific constraint**.

| Netclass | Applies to | Track width | Clearance | Diff pair gap | Impedance target | Length / skew constraints |
|---|---|---:|---:|---:|---|---|
| `DDR_CK` | `DDR_CK_P/N` | no specific constraint | no specific constraint | no specific constraint | Differential clock routing guidance exists, but width/gap require stack‑up. citeturn1search2turn1search42 | P/N skew tight (set with custom `skew`), pair length match per Intel guidance. citeturn1search2turn11search0 |
| `DDR_DQS0`… | `DDR_DQSx_P/N` | no specific constraint | no specific constraint | no specific constraint | Typically treated as ~100 Ω differential in many guides; validate vs stack‑up. citeturn1search42turn1search44 | P/N skew tight; keep lane‑internal skew budget (see rules below) |
| `DDR_DQ_L0`… | `DDR_DQ*`, `DDR_DM*` | no specific constraint | no specific constraint | n/a | Commonly treated as ~50 Ω single‑ended target; validate vs stack‑up. citeturn1search2turn8search3 | Match within lane to DQS (see routing budgets) |
| `DDR_ADDR_CMD` | `DDR_A*`, `DDR_BA*`, `DDR_RAS_N`, etc. | no specific constraint | no specific constraint | n/a | Same as above | Match to CK within a bounded window (see routing budgets) |
| `DDR_CTRL` | `DDR_RESET_N`, `DDR_CKE`, `DDR_CS_N`, `DDR_ODT` | no specific constraint | no specific constraint | n/a | Same as above | Treat like addr/cmd group unless vendor/tooling says otherwise |
| `DDR_BGA_ESCAPE` (aux class) | Any DDR nets inside H616+DRAM courtyard regions | fab‑limited | fab‑limited | fab‑limited | n/a | Use this class *only* to allow tighter rules inside courtyards via rule conditions |

#### Example `.kicad_dru` rule snippets (KiCad 9 compatible)

These are written to be idiomatic for v9 (use `hasNetclass()` because nets can include `Default` plus others). citeturn9search5turn11search2  

```lisp
# Example: enforce that DDR lane nets are length-matched via a skew budget
(rule "DDR Lane0 skew limit"
  (condition "A.hasNetclass('DDR_DQ_L0')")
  (constraint skew (max 1.0mm)))   # placeholder; refined after stack-up + timing model

# Example: restrict via count on DDR data nets (avoid uncontrolled discontinuities)
(rule "DDR data via count limit"
  (condition "A.hasNetclass('DDR_DQ_L0') || A.hasNetclass('DDR_DQ_L1')")
  (constraint via_count (max 2)))  # aligns with common guidance to limit vias citeturn1search44turn11search1

# Example: enforce differential pair gap bounds once stack-up is fixed
(rule "DDR DQS diff pair gap"
  (condition "A.hasNetclass('DDR_DQS0') || A.hasNetclass('DDR_DQS1')")
  (constraint diff_pair_gap (min 0.10mm) (opt 0.15mm) (max 0.25mm))) # placeholder

# Example: keep-outs and stricter neck-down within the H616 escape region (courtyard named in KiCad)
(rule "H616 escape neckdown"
  (condition "A.intersectsCourtyard('U_H616')")
  (constraint track_width (min 0.10mm) (opt 0.12mm))
  (constraint clearance (min 0.10mm) (opt 0.12mm)))
```

Notes:
- KiCad provides DRC violations for **via_count**, **diff_pair_gap**, **track length out of range**, and **skew out of range**, all driven by custom rules. citeturn11search1turn11search2  
- Don’t assume the length tuner can “fix everything”: it only tunes **point‑to‑point** nets and stops at branches; stub leftovers can block DDR tuning. citeturn9search1turn9search0  

### Routing rules for DDR3 in physical terms (first‑spin budgets)

Your internal guide provides ps↔mm conversions and anchors them to Intel guidance (±10 ps within byte lane, ±20 ps addr/cmd to clock). Source: `/mnt/data/DDR3 vs DDR3L…Guide.md`, “Electrical length matching targets…”. Intel’s own DDR3 layout guidance contains these same mismatch figures for byte‑lane and addr/cmd matching. citeturn1search0turn1search2  

A conservative, KiCad‑implementable first‑spin rule set:

- **Byte‑lane matching (DQ/DM to DQS)**: start with **±1.0 mm** physical mismatch within each byte lane (this matches ST’s DDR3/DDR3L guideline of ±40 mils ≈ 1.016 mm). citeturn1search42  
- **DQS vs clock relationship**: ST provides a concrete bound: DQS length is allowed to be **0 to 590 mils (≈15 mm) shorter** than CK, and CK should be the longest. citeturn1search42  
- **Address/command vs clock**: use Intel’s **±20 ps** guideline as the conceptual target, but treat physical conversion as *stack‑up dependent*; encode physical bounds after you lock the fab dielectric. citeturn1search0turn1search2  
- **Via discipline**: keep byte‑lane nets on the same layer as much as possible; enforce **identical via count across nets in a lane**, and minimise total vias. Microsemi explicitly recommends routing DQS with its lane on the same critical layer and avoiding more than three vias between controller and memory device. citeturn1search44  
- **Plane integrity**: never route DDR nets over plane splits; always maintain a contiguous return path. Intel and other vendors stress avoiding adjacent signal layers and routing over appropriate planes. citeturn1search2turn1search44  

### BGA escape and layer usage

Internal project guidance assumes a **6‑layer** baseline stack‑up and assigns DDR mainly to top/inner routing with solid reference planes (source: `/mnt/data/DDR3 vs DDR3L…Guide.md`, “Stack-up and layer assignment”; `/mnt/data/H616 Watchdog PCB Architecture Deep Dive…md`, “KiCad PCB implementation rules”). This direction is also consistent with Micron’s point‑to‑point guidance emphasising 6‑layer stackups for SI. citeturn8search3turn8search26  

```mermaid
flowchart TB
  subgraph Stackup[Conceptual 6-layer DDR stack usage]
    L1[L1: DDR escape + short routes (microstrip)]
    L2[L2: Solid GND return]
    L3[L3: Power islands (VDDQ/VDD18_DRAM) - avoid splits under DDR]
    L4[L4: DDR longer matched routes (stripline)]
    L5[L5: Solid GND return/shield]
    L6[L6: Non-DDR signals; avoid DDR here]
  end

  H616BGA[H616 TFBGA] -->|escape| L1
  DRAMFBGA[DDR3(L) FBGA] -->|escape| L1
  L1 -->|controlled return| L2
  L4 -->|controlled return| L5
```

Practical escape strategy:
- Route **DQS + its byte lane** as a “bundle”: same layers, same via count, minimal layer transitions. citeturn1search44turn1search42  
- If you must use via‑in‑pad for escape density, treat it as a manufacturing decision: filled/capped vias may be required to avoid solder wicking; keep it explicit in fab notes and footprints (project DFM decision, not implicit).

## Reuse from Orange Pi and other open-source designs, plus common pitfalls

### What you can safely take from Orange Pi Zero 2

From the Orange Pi DDR sheet (path shown in image caption), the following patterns are directly reusable in the Watchdog schematic and layout “shape”, regardless of whether you run at 1.35 V or 1.5 V:

- The **2‑device DDR3 layout concept**: SoC adjacent to two FBGA DDR devices, short escape routing, dense local decoupling. (Primary: Orange Pi schematic snippet; internal: `/mnt/data/KeyCAD_H616_Watchdog_PCB_Architecture_v0.md`, §3.2 encouraging topology reuse.)  
- A **VREF divider** with local decoupling placed close to the DRAM region (internal docs explicitly call out Orange Pi’s VREF divider as a usable example pattern). (source: `/mnt/data/DDR3 vs DDR3L…Guide.md`, “VREF is the silent killer”)  
- Presence of **RZQ ~240 Ω** calibration resistor concept (Orange Pi shows a 240 Ω part; 240 Ω ±1% is a standard calibration basis in configuration docs). citeturn1search43  

What should change in your KeyCAD project versus a straight copy:
- **Make the “DDR4” wording mismatch impossible to propagate**: name your sheet and documents DDR3/DDR3L consistently, and add a note that Orange Pi’s sheet title is misleading (source: `/mnt/data/Orange_Pi_Zero2_H616_Reference_Extraction.md`; image evidence from Orange Pi rendered DDR page).  
- **Add explicit bring‑up hooks** demanded by your architecture: testpoints on DRAM rails and optional current shunt links (source: `/mnt/data/KeyCAD_H616_Watchdog_PCB_Architecture_v0.md`, §3.2). Orange Pi is an SBC optimised for production; your board is an instrumented bring‑up platform.

### Open-source DDR3 designs to borrow patterns from

These do not use H616, but they are valuable as “battle‑tested” DDR3 integration patterns, especially around bring‑up and configuration discipline:

- **BeagleBone Black**: documents a very similar feature mix—**512 MB DDR3L**, onboard eMMC, microSD, and 10/100 Ethernet—making it a good reference for “embedded Linux board with DDR3L and boot storage” integration. citeturn2search5  
  A relevant pitfall discussed in TI’s ecosystem is misunderstanding which groups must be length‑matched; community guidance reiterates that you should follow the hardware design guide and that matching is group‑based, not “all nets identical length”. citeturn2search1  
- **OpenRex (i.MX6)**: explicitly positions itself as completely open source with downloadable schematic and PCB and uses soldered DDR3‑1066; useful for patterns around open documentation and DDR bring‑up‑friendly board architecture. citeturn7search2  
- **Olimex OLinuXino family**: multiple open hardware Allwinner boards show a recurring operational pitfall: **DDR configuration parameters are board‑specific**, and even swapping DDR3 vendor parts across revisions can require different images/configuration. This is a concrete reminder that DRAM part selection and boot chain DRAM init are linked. citeturn7search4turn7search3  

### Common pitfalls and mitigations

Your internal DDR guide has a dedicated “pitfalls” section; the most damaging ones align strongly with external vendor guidance and KiCad tool behaviour (source: `/mnt/data/DDR3 vs DDR3L…Guide.md`, “Common pitfalls…”).

- **Routing over plane splits** breaks return paths; vendors explicitly instruct routing over appropriate planes and maintaining contiguous reference planes. citeturn1search2turn1search44  
- **“Length matched” but not “delay matched”** happens when you mix layers with different propagation velocities. Treat layer changes as a design event and keep byte lanes co‑layered where possible. citeturn1search2turn1search44  
- **Unequal via counts inside a byte lane** introduces discontinuity and skew; enforce via count bounds in KiCad (`via_count`) and keep DQS aligned with its lane. citeturn1search44turn11search1  
- **VREF handled like a digital net**: VREF is an analogue reference; Micron specifies tight VREF noise constraints and expects it to track VDD. citeturn6search3turn8search3  
- **Overconfidence in training**: Intel’s DDR3 guidance explicitly tells you not to rely on controller deskew beyond limited mismatch; this supports being conservative on matching budgets. citeturn1search0turn1search2  
- **KiCad tuning blocked by stubs/branches**: KiCad’s length tuner stops at branches and won’t tune branching nets; stub track leftovers can silently break tuning. Always run cleanup and check topology. citeturn9search1turn9search0  
- **H616‑specific configuration drift**: linux‑sunxi notes that H616/A133 use a Synopsys uMCTL2 DRAM controller and that knowledge is transferable from A133/DRAMC; U‑Boot development discussions show that adding memory types often relies on “magic values” extracted from boot firmware (“boot0”). This is a warning that changing DRAM type/topology without updating DRAM init parameters is a real bring‑up risk. citeturn10search1turn10search3turn10search2  

## DDR verification plan, KiCad deliverables, and first-spin checklist

### DDR-specific deliverables and repo locations

Section 3.2 explicitly calls for a follow‑on low‑level reference doc (`REF_DDR3_DDR3L.md`) plus schematic/layout implementation (source: `/mnt/data/KeyCAD_H616_Watchdog_PCB_Architecture_v0.md`, §3.2).

| Deliverable | Purpose | Suggested location |
|---|---|---|
| `REF_DDR3_DDR3L.md` | Single source of truth: topology decision, rail choice (1.35/1.5), routing budgets, bring‑up plan | `docs/hw/REF_DDR3_DDR3L.md` |
| DDR schematic sheet | Implement nets, rails, VREF/RZQ/terminations, testpoints | `kicad/sch/21_ddr3.kicad_sch` (exact naming per your repo conventions) |
| DDR‑specific netclasses | Ensure correct grouping in both schematic and PCB | Inside `.kicad_pro` / schematic setup |
| Custom rules file | Encode skew/length/via_count/diff gaps | `kicad/constraints/watchdog.kicad_dru` (must be committed) citeturn0search1turn11search36 |
| Layout annotations | Document DDR “keep‑inside zone”, routing layer plan, tuning patterns | In PCB text layers + `docs/hw/ddr_layout_notes.md` |

### Bring-up tests and measurement plan

A disciplined DDR bring‑up sequence is required because DDR failures can masquerade as “dead board”. Internal docs propose probing rails, VREF, clock nodes, and ZQ nodes as first‑line checks (source: `/mnt/data/DDR3 vs DDR3L…Guide.md`, “Bring-up, validation, and what to probe”).

A practical plan consistent with vendor guidance:

- **Power‑off checks**: verify resistance from VDDQ to GND and from VREF to GND is in expected range; confirm no shorts around the BGA escape clusters (generic PI hygiene).  
- **Power‑on rail validation**: measure VDD18_DRAM and VDDQ ramp and stability; if VTT is implemented, ensure it is applied after VDDQ to avoid latch‑up risk per Micron guidance. citeturn8search26turn8search3  
- **VREF validation**: confirm VREF ≈ VDDQ/2 and check noise; Micron constrains allowable noise around VREFDQ and expects tracking. citeturn6search3turn6search1  
- **Boot‑log confirmation**: UART boot log should report DRAM size (e.g., Orange Pi logs “DRAM: 1 GiB” in U‑Boot; your target should reflect 512 MB once configured). citeturn10reddit39  
- **Memory tests**: run `memtester`/equivalent patterns under CPU/GPU stress and thermal soak; exercise both sequential and pseudo‑random patterns; log failures with temperature/voltage context. (Implementation detail referenced in internal bring‑up section: `/mnt/data/DDR3 vs DDR3L…Guide.md`).

### First-spin DDR checklist

This is a condensed “go/no‑go” list for manufacturing release and first PCB bring‑up:

- Schematic: topology (16‑bit vs 32‑bit) decided and reflected in net naming and lane mapping (source: `/mnt/data/DDR3 vs DDR3L…Guide.md`, “Memory organisation choices…”).  
- Rails: VDDQ/VCC_DRAM rail is strap‑selectable (1.35/1.5) *or* fully locked per procurement decision; VDD and VDDQ tracking requirements met. citeturn6search1  
- VREF: implemented as VDDQ/2, filtered, routed as analogue; has local decoupling near DRAM pins/balls. citeturn6search3turn8search3  
- Calibration: RZQ resistor implemented (nominal 240 Ω ±1%) and placed close to the DRAM ZQ pin(s). citeturn1search43  
- Layout: 6‑layer stack‑up locked; DDR routes avoid plane splits and maintain contiguous return paths. citeturn1search2turn8search3  
- Routing: lane‑based length matching budgets implemented; via counts equalised within a lane; total vias constrained. citeturn1search44turn11search1  
- KiCad enforcement: `.kicad_dru` exists, passes syntax check, and is committed; rule conditions use `hasNetclass()` (KiCad v9 multi‑netclass semantics). citeturn9search5turn11search2  
- Tuning feasibility: no DDR net has hidden stubs/branches that would defeat KiCad’s tuner. citeturn9search1turn9search0  
- Bring‑up hooks: testpoints exist for VDDQ/VCC_DRAM, VDD18_DRAM, VREF, and (if present) VTT; optional 0 Ω shunt footprint exists for current measurement as architecture requests (source: `/mnt/data/KeyCAD_H616_Watchdog_PCB_Architecture_v0.md`, §3.2).  

