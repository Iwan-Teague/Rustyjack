# Loot Viewer Architecture Diagram
Created: 2026-01-07

> Note: Archived doc. Current builds no longer use external tcpdump, ettercap, ncat, arp-scan, or arpspoof/dsniff; references below are historical.


## Before vs After Comparison

### BEFORE - Static File Viewer
```
Main Menu
    ↓
  Loot
    ↓
[Select Category]
    ↓
Nmap/DNSSpoof
    ↓
[One file shown at a time]
UP/DOWN cycles through filenames
    ↓
SELECT opens file
    ↓
┌─────────────────────────┐
│ file.txt                │
│ Line 1                  │
│ Line 2                  │
│ Line 3                  │ ← STATIC (no scrolling)
│ Line 4                  │ ← Only ~6 lines visible
│ Line 5                  │
│ ...content truncated... │
└─────────────────────────┘
    ↓
BACK/SELECT exits
    ↓
Return to Main Menu
(must navigate again to view another file)
```

### AFTER - Interactive Scrollable Viewer
```
Main Menu
    ↓
  Loot
    ↓
[Select Category]
    ↓
Nmap/DNSSpoof
    ↓
┌─────────────────────────┐
│ Loot files              │
│ scan_192.168.1.0.xml    │ ← Current selection
└─────────────────────────┘
UP/DOWN cycles, SELECT opens
    ↓
┌─────────────────────────┐
│ scan.xml (1/150)        │ ← Position indicator
│ Starting Nmap 7.94      │
│ Nmap scan report for... │
│ Host is up (0.0012s)    │ ← SCROLLABLE
│ PORT   STATE  SERVICE   │ ← Line-by-line
│ 22/tcp open   ssh       │
│ ↓ More below ↓          │ ← Visual hint
└─────────────────────────┘
UP/DOWN = scroll 1 line
SELECT = jump 1 page
    ↓
BACK returns to file list
    ↓
┌─────────────────────────┐
│ Loot files              │
│ scan_192.168.1.0.xml    │
│ scan_192.168.1.1.xml    │ ← Select another
│ scan_10.0.0.0.xml       │
└─────────────────────────┘
    ↓
[Browse more files without leaving Loot section]
    ↓
BACK exits to Main Menu
```

## Component Interaction Flow

```
┌─────────────────────────────────────────────────────────────┐
│                        APP LAYER                             │
│                                                              │
│  show_loot(section)                                          │
│      │                                                        │
│      ├─→ Core: LootCommand::List  ──→  Get file paths       │
│      │                                                        │
│      └─→ Loop: choose_from_list()  ──→  User selects file   │
│              │                                                │
│              └─→ view_loot_file(path)                        │
│                      │                                        │
│                      ├─→ Core: LootCommand::Read             │
│                      │        └─→ Returns lines[], truncated │
│                      │                                        │
│                      └─→ scrollable_text_viewer()            │
│                              │                                │
│                              ├─→ Track offset (scroll pos)   │
│                              ├─→ Slice lines[offset..offset+5]│
│                              ├─→ Display: draw_dialog()      │
│                              ├─→ Wait for button press       │
│                              ├─→ map_button() → action       │
│                              └─→ Update offset / exit        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
                                 ↓
┌─────────────────────────────────────────────────────────────┐
│                      DISPLAY LAYER                           │
│                                                              │
│  draw_dialog(lines[], status)                                │
│      │                                                        │
│      ├─→ Clear screen                                        │
│      ├─→ Draw toolbar (CPU/RAM/Disk)                         │
│      ├─→ Draw dialog box background                          │
│      ├─→ Render text lines with wrap_text()                  │
│      └─→ Update LCD hardware                                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
                                 ↓
┌─────────────────────────────────────────────────────────────┐
│                     HARDWARE LAYER                           │
│                                                              │
│  ST7735 LCD (128x128px) via SPI                              │
│  ButtonPad (6 physical buttons)                              │
│      - Up, Down, Left, Right, Select                         │
│      - Key1 (Refresh), Key2 (Menu), Key3 (Reboot)            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## State Machine Diagram

```
┌─────────────┐
│  Main Menu  │
└──────┬──────┘
       │ Select "Loot"
       ↓
┌─────────────┐
│   Loot      │
│   Category  │
│   Selector  │
└──────┬──────┘
       │ Select category (Nmap/DNSSpoof)
       ↓
┌─────────────────┐
│  File Browser   │◄────────────┐
│  (Loop State)   │             │
│                 │             │ BACK from viewer
│  - Load list    │             │
│  - Show file    │             │
│  - Wait button  │             │
│  - On SELECT:   │─────────────┤
└─────────┬───────┘             │
          │                     │
          │ Open file           │
          ↓                     │
┌─────────────────┐             │
│  File Viewer    │             │
│  (Scroll State) │             │
│                 │             │
│  offset = 0     │             │
│  Loop:          │             │
│    - Show page  │             │
│    - Get button │             │
│    - UP/DOWN:   │             │
│      adjust     │             │
│      offset     │             │
│    - BACK:      │─────────────┘
│      exit       │
└─────────────────┘
```

## Memory Layout (Simplified)

```
Stack Frame for scrollable_text_viewer():

┌────────────────────────────────┐
│ title: &str (reference)        │ ← Points to filename string
├────────────────────────────────┤
│ lines: &[String] (slice)       │ ← Points to Vec in parent scope
├────────────────────────────────┤
│ truncated: bool (1 byte)       │
├────────────────────────────────┤
│ offset: usize (8 bytes)        │ ← Current scroll position
├────────────────────────────────┤
│ LINES_PER_PAGE: const (inline) │ ← Compile-time constant
└────────────────────────────────┘

Heap Allocations:
- Vec<String> for lines (allocated in view_loot_file)
- Each String in the Vec (from JSON deserialization)
- Dialog content Vec (temporary, for each frame)

No persistent allocations - all freed when exiting viewer
```

## Button Mapping

```
Physical Button Layout (Waveshare HAT):
┌─────────────────────────┐
│                         │
│    [KEY1]  [KEY2]  [KEY3]│ ← Top row
│                         │
│         [  UP  ]        │
│    [LEFT]  [RIGHT]      │ ← D-pad
│        [DOWN]           │
│                         │
└─────────────────────────┘

Loot Viewer Mapping:
┌─────────────────────────┐
│ Refresh  Menu  Reboot   │
│                         │
│     Scroll Up ↑         │
│  Exit     Open/Jump     │
│     Scroll Down ↓       │
│                         │
└─────────────────────────┘

Button Priority (File Viewer):
1. UP/DOWN - Primary navigation
2. SELECT - Page jump (fast scroll)
3. BACK - Exit viewer
4. Key2 - Quick home
5. Key1 - Refresh (low priority)
6. Key3 - Reboot (emergency)
```

## Data Flow Timeline

```
Time →

T0: User presses SELECT on "Loot"
    │
    └─→ App: execute_action(MenuAction::Loot(section))

T1: App calls show_loot(section)
    │
    └─→ Core: dispatch(LootCommand::List)

T2: Core reads filesystem
    │
    └─→ Returns JSON: { files: [{path: "..."}, ...] }

T3: App extracts paths and labels
    │
    └─→ Enters file browser loop

T4: User navigates, presses SELECT on file
    │
    └─→ App calls view_loot_file(path)

T5: Core reads file content
    │
    └─→ Returns JSON: { lines: [...], truncated: false }

T6: App enters scrollable_text_viewer()
    │
    ├─→ offset = 0
    │
    └─→ Display loop starts

T7: Each frame:
    │
    ├─→ Slice lines[offset..offset+5]
    ├─→ Build content with title + lines + hint
    ├─→ Draw to display
    ├─→ Wait for button (BLOCKING)
    ├─→ Process button → update offset
    └─→ Loop or exit

T8: User presses BACK
    │
    └─→ Return to file browser (T3)

T9: User presses BACK again
    │
    └─→ Exit show_loot(), return to main menu
```

---

This architecture enables:
- Efficient memory usage (no full file buffering)
- Responsive UI (event-driven updates)
- Intuitive navigation (familiar button patterns)
- Extensible design (easy to add features)
