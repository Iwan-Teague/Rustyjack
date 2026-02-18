# Orange Pi Zero2 H616 Reference Extraction

The document is timestamped **2026-02-18 01:05:20 Europe/Dublin** (as requested) and is structured to act as a **source-of-truth reference** for cloning Orange Pi Zero2 (H616) integration patterns into your own KiCad build. citeturn13view0turn2view0turn15view0turn16view0

## Scope and primary reference artefacts

This reference is intentionally focused on **Orange Pi Zero2 (Allwinner H616)**, because that is the closest match to your target SoC and overall SBC shape. citeturn13view0turn2view0

It also explicitly distinguishes **Orange Pi Zero2** from **Orange Pi Zero 2W** because “Zero 2W” is generally documented as an **H618**-based family (different SoC class), and should be treated as a separate reference unless you intentionally change SoCs. citeturn0search2turn19view0

The doc is built primarily from:
- **Orange Pi Zero2 H616 schematic v1.3** (public PDF) for electrical block-level truth. citeturn1view0turn2view0turn3view1turn3view2turn2view4  
- **Orange Pi Zero2 H616 user manual v1.0** (public PDF) for *shipping-product* I/O descriptions, pin tables, and declared Wi‑Fi chip choice. citeturn12view0turn13view0turn13view2turn13view3  
- **Mainline Linux device tree** for “software-facing truth” (rails/USB mode assumptions/LED GPIOs/etc.). citeturn15view0turn16view0  

## Orange Pi Zero2 architecture you can reuse

The Orange Pi Zero2 reference architecture, as extracted into the doc, is the set of integration decisions that matter most when “leapfrogging” into a custom PCB:

The user manual describes the board as **H616** with **512MB/1GB DDR3**, **microSD + 2MB SPI flash**, **10/100/1000 Ethernet**, **Wi‑Fi+BT via AW859A**, and **Type‑C 5V/2A power input**. citeturn13view0  
The schematic block diagram matches the same overall functional story: **AXP305 PMIC**, H616, dual DDR (two devices), Wi‑Fi and Ethernet PHY blocks, and the main connector set. citeturn2view0turn3view1turn3view2turn2view4

The extracted reference doc pulls out and normalises (for later KiCad use) the most reusable “big rocks”:
- **PMIC-led power architecture** using **AXP305**, including the rail families and how they map to SoC subsystems. citeturn3view1turn15view0  
- **DDR subsystem implemented as two discrete DDR3 FBGA devices**, consistent with the manual’s “512MB/1GB” variants and the schematic’s two-chip topology. citeturn13view0turn3view0turn4view2  
- **Ethernet implemented via an external PHY** (**RTL8211F**) and RJ45/magnetics, with the PHY’s support circuitry and a 25 MHz reference shown in the schematic. citeturn3view2  
- **Wi‑Fi/BT implemented as an SDIO + UART/PCM style combo module**, with explicit wake/reg-on/reset nets and an RF feed to an antenna connector footprint. citeturn2view4turn2view2turn7search4  
- **USB host port power switching** rather than pouring raw 5V: the schematic shows a dedicated VBUS switch (**SY6280**) driven by a named enable net (`USB1-DRVVBUS`). citeturn24view0turn24view1turn16view0  

## USB‑C behaviour and “5V input” interpretation

A key nuance that the reference doc captures (because it directly impacts your prototype board decisions):

Mainline DT explicitly documents that the **USB‑C port is wired to USB2 PHY0 but does not implement a role switch**, with both CC pins pulled down; therefore the DT chooses **fixed peripheral mode** (`dr_mode="peripheral"`). citeturn16view0  

That aligns cleanly with your clarified intent: **USB‑C as a 5V input**, not negotiated USB‑PD and not “full featured OTG by default.” The Orange Pi approach is a known, shipping-product precedent for the “simple sink, keep it boring” model. citeturn3view1turn16view0  

## Contradictions inside the Orange Pi schematic pack and the chosen “truth”

One of the most important outcomes of this deep extraction is identifying where the public schematic pack is self-inconsistent, and where an external truth source resolves it.

The Wi‑Fi block is labelled “AP6256” in the schematic pack’s index and revision notes, but the Wi‑Fi schematic sheet itself is titled **“WIFI AW859A”**, and the user manual declares **AW859A** as the on-board Wi‑Fi/BT chip. The doc treats **AW859A as the shipped truth** and treats “AP6256” mentions as naming drift. citeturn6view0turn6view1turn13view0turn7search4  

The memory section includes “DDR4” wording in the sheet title/index, but the actual DRAM devices are explicitly labelled **DDR3-FBGA96** and the manual states **DDR3**. Additionally, mainline DT configures the DRAM rail (`vdd-dram`) as a fixed **1.5V** regulator, aligning with DDR3 rather than DDR4. The doc therefore treats “DDR4” markings as schematic artefacts and the implementation as **DDR3 @ 1.5V baseline**. citeturn4view2turn4view3turn13view0turn15view0  

The user manual includes a dimension line that conflicts with the manual’s own board imagery; the reference doc flags this as “verify mechanically from a physical board or mechanical drawing” rather than trusting either number blindly. citeturn13view0turn13view1turn0search10  

## Board layout availability and what you can realistically “copy”

The reference doc includes links to publicly accessible artefacts you can use today, and it is explicit about what is *not* available:

Orange Pi typically publishes **schematics** widely (as above), but **official PCB layout/gerbers** are generally *not* provided as open hardware; community discussions around “PCB files” for Orange Pi boards consistently reflect that reality. citeturn9search18turn9search6  

There are, however, community resources that may help with enclosure/mechanical planning and “layout inspiration,” which the reference document points to as *non-official* aids:
- a community **Altium project “template” repo** that includes `.PcbDoc`/`.SchDoc` artefacts (treat as third-party, not authoritative). citeturn11view0turn9search10  
- third-party **3D model** listings that can assist mechanical work (again, not authoritative for electrical design). citeturn9search26  

The downloadable reference document is written so that, even without official gerbers, you can still extract a very large amount of reliable “what works” information from the combination of schematic + user manual + mainline DT — and then adapt it to your own I/O deltas (2× USB‑A, eMMC, microSD recovery-first bring-up, debug affordances) in subsequent subsystem documents. citeturn2view0turn13view0turn16view0