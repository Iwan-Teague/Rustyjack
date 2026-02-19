# REF_DEBUG_BRINGUP.md

This is a living bring-up reference for the H616 Watchdog PCB.

## A) Required lab kit

- Bench PSU with current limit + current readout.
- 2‑channel scope (4 is nicer).
- 3.3 V UART‑USB adapter.
- Decent DMM.
- Optional: USB host connection for FEL.
- Optional: JTAG probe (only if your board exposes it and you have a known-good OpenOCD/JTAG flow).

## B) First power-on (cold board)

### B1) Visual + continuity

- Inspect BGA area for obvious solder issues (if assembled).
- Continuity: confirm no hard short between `5V_IN` and GND.

### B2) Bench PSU setup

- Voltage: **5.0 V**
- Current limit: start conservative (0.3–0.5 A), raise only when evidence says it’s safe.

Record:
- Inrush peak current:
- Steady-state current:

### B3) Rail check (no boot assumptions)

Probe the test points in this order (fill actual targets once the power-tree doc is frozen):

| Rail TP | Expected | Measured | Notes |
|---|---:|---:|---|
| TP_5V_IN | 5.0 V |  |  |
| TP_3V3_SYS | 3.3 V |  |  |
| TP_1V8_SYS | 1.8 V |  |  |
| TP_VDD_SYS | ~0.9–1.2 V |  |  |
| TP_VDD_CPU | ~0.9–1.2 V |  |  |
| TP_VCC_DRAM/VDDQ | 1.35 or 1.5 V |  |  |
| TP_VDD18_DRAM | 1.8 V |  |  |

If any rail is missing, stop. Debug power enable pins, sequencing, and shorts before attempting boot.

## C) UART log capture

- Connect UART (3.3 V TTL): `UART0_TX`, `UART0_RX`, `GND`.
- Capture from power-on to at least 10 seconds.

Record:
- Baud rate used:
- Log filename:

## D) Boot + recovery tests

### D1) Normal boot attempt

- Boot from the intended primary storage.
- Save UART output.

### D2) Forced recovery path

You should have at least one deterministic recovery method:

- **FEL / USB** recovery (strap FEL low at reset, or your board’s chosen trigger).
- Or microSD recovery image.

Validation steps (host side):
- Verify device enumerates / `sunxi-fel version` works.

Record:
- Recovery method used:
- Host OS/tools:
- Result:

## E) Triage patterns

### Symptom: no UART output

Suspects (order):
1) Reset held low.
2) 24 MHz clock missing.
3) UART voltage domain/pin mapping wrong.
4) Boot straps illegal.

### Symptom: BootROM prints then hangs

Common suspects:
- DDR VDDQ/VREF issues.
- DDR routing/topology issues.
- Power sequencing timing.

### Symptom: boots SD but not eMMC

Common suspects:
- eMMC reset/power rail not correct.
- Signal integrity (CLK/CMD).
- Pinmux or device-tree config.

## F) What to attach when reporting a failure

- PSU settings + current draw numbers.
- Full UART log.
- Rail measurements table.
- Photo of the board area relevant to the failure.

