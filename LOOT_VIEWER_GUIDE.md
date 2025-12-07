# Loot Viewer - Quick Reference

## How to Use

### Opening Loot Files
1. From Main Menu, select **Loot**
2. Choose category: **Wireless Captures** or **Ethernet Loot** (Transfer to USB is also available)
3. Navigate file list with **UP/DOWN**
4. Press **SELECT** to open file

### Reading Files (Scrollable Viewer)

#### Button Controls
| Button | Action |
|--------|--------|
| **UP** | Scroll up one line |
| **DOWN** | Scroll down one line |
| **SELECT (RIGHT)** | Jump down one page (5 lines) |
| **BACK (LEFT)** | Close file, return to list |
| **Key1** | Refresh display |
| **Key2** | Return to main menu |
| **Key3** | Reboot system (with confirmation) |

#### Display Elements
```
┌─────────────────────────┐
│ CPU 12% RAM 45% DSK 78% │ ← Status bar
├─────────────────────────┤
│ file.txt (15/150)       │ ← Title + position
│ This is line 15         │
│ This is line 16         │ ← Content
│ This is line 17         │   (5 lines visible)
│ This is line 18         │
│ This is line 19         │
│ ↓ More below ↓          │ ← Navigation hint
└─────────────────────────┘
```

### Position Indicator Format
- `filename (1/150)` = At line 1 of 150 total lines
- `filename (146/150)` = Near end of file
- `[File truncated]` = File has more than 5000 lines (not all loaded)

## Tips

- Browse multiple files: After viewing a file, press BACK to return to file list - no need to navigate from main menu again
- Quick navigation: Use SELECT to jump down pages quickly when reading long files
- Check position: The `(current/total)` indicator always shows where you are in the file
- Long lines: Lines longer than 18 characters automatically wrap to next line
- Large files: Files with 5000+ lines will be truncated - you'll see the first 5000 lines only

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "No files" message | No loot captured yet in that category |
| "File is empty" | File exists but contains no content |
| Garbled text | File may contain binary data |
| Slow scrolling | Normal for files >1000 lines |
| Can't scroll up from line 1 | Already at beginning of file |
| Can't scroll down at end | Already at last line |

## File Locations
- **Wireless**: `~/Rustyjack/loot/Wireless/<target>/` (target = SSID, else BSSID). Handshakes, PMKIDs, and deauth logs are grouped per network. The UI lists files recursively, so captures inside per-target folders appear in the menu.
- **Ethernet**: `~/Rustyjack/loot/Ethernet/` (LAN discovery and port scan results).

---
**Quick Access Path**: Main Menu → Loot → [Category] → [File] → Scroll
