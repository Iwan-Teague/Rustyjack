# Loot Viewer Implementation - Scrollable File Browser
**Last Updated**: 2025-11-24

> Note: Archived doc. Current builds no longer use external tcpdump, ettercap, ncat, arp-scan, or arpspoof/dsniff; references below are historical.


## Overview
This implementation replaces the static Loot section with an interactive, scrollable file viewer that allows users to browse and read captured loot files directly on the device's small display.

## What Changed

### Previous Behavior
1. User navigated to Loot menu
2. Selected category (Nmap/DNSSpoof)
3. Saw a list of files (one at a time via up/down navigation)
4. Selected a file
5. Viewed entire file content in a **static dialog** (no scrolling, limited to ~6 visible lines)

### New Behavior
1. User navigates to Loot menu
2. Selects category (Nmap/DNSSpoof)
3. **Immediately sees a browsable file list** (navigates with up/down buttons)
4. Selects a file to view
5. **Opens scrollable viewer** with:
   - Line-by-line scrolling (Up/Down buttons)
   - Page-down capability (Select button)
   - Current position indicator (e.g., "file.txt (1/150)")
   - Visual indicators for more content
   - Truncation warning if file exceeds 5000 lines
6. After viewing, **returns to file list** (can select another file without going back to main menu)

## Technical Implementation

### Key Components

#### 1. **Modified `show_loot()` Function**
```rust
fn show_loot(&mut self, section: LootSection) -> Result<()>
```
- Fetches file list from core
- Enters a **loop** that keeps showing the file list until user backs out
- When user selects a file, calls `view_loot_file()`
- Returns to file list after viewing, allowing multiple files to be viewed in one session

#### 2. **New `view_loot_file()` Function**
```rust
fn view_loot_file(&mut self, path: &str) -> Result<()>
```
- Reads file content via core's `LootCommand::Read`
- Increased max_lines from 500 to **5000** for better coverage
- Extracts lines and truncation status
- Passes data to scrollable viewer

#### 3. **New `scrollable_text_viewer()` Function**
```rust
fn scrollable_text_viewer(&mut self, title: &str, lines: &[String], truncated: bool) -> Result<()>
```
This is the core scrolling engine:

**Features:**
- **Pagination**: Shows 5 lines at a time (configurable via `LINES_PER_PAGE`)
- **Offset tracking**: Maintains current scroll position
- **Visual feedback**: 
  - Position indicator: `filename (1/150)` shows current line / total lines
  - "↓ More below ↓" indicator when more content exists
  - "[File truncated]" warning when file exceeds max_lines

**Button Controls:**
- **Up**: Scroll up one line
- **Down**: Scroll down one line  
- **Select**: Jump down one page (5 lines)
- **Back**: Exit viewer, return to file list
- **Main Menu**: Exit to main menu
- **Refresh (Key1)**: Redraw current page
- **Reboot (Key3)**: Initiate system reboot (with confirmation)

### Integration with Existing Code

The implementation leverages your existing architecture:

1. **`choose_from_list()`**: Reused for file selection (shows one file at a time, cycles with up/down)
2. **`draw_dialog()`**: Used to render text content on display
3. **`map_button()`**: Translates physical button presses to actions
4. **Core dispatch system**: Uses existing `Commands::Loot` infrastructure
5. **StatusOverlay**: Shows system stats (CPU/RAM/disk) in toolbar

### Data Flow

```
User selects Loot category
    ↓
Core: LootCommand::List → returns file paths
    ↓
UI: Loop showing file list via choose_from_list()
    ↓
User selects file
    ↓
Core: LootCommand::Read → returns lines array, truncated flag
    ↓
UI: scrollable_text_viewer() with offset tracking
    ↓
User scrolls through content
    ↓
User presses Back → returns to file list loop
```

## Design Decisions Based on Research

### Embedded Graphics Best Practices
From reviewing `embedded-graphics` documentation and your existing display implementation:

1. **Text Wrapping**: Your existing `wrap_text()` function handles long lines automatically (max 18 chars for 128px display)

2. **Memory Efficiency**: 
   - Read up to 5000 lines (reasonable for Pi Zero W's ~512MB RAM)
   - Only render visible lines (5 at a time)
   - No frame buffering needed - direct draw to display

3. **Display Constraints**:
   - 128x128 pixel ST7735 LCD
   - ~6-7 lines visible in dialog area
   - 6x10 monospace font (FONT_6X10)
   - Allocate 1 line for title, 5 for content, 1 for navigation hints

4. **Performance**: 
   - Redraw on button press (event-driven, not continuous refresh)
   - No animations to reduce CPU overhead
   - Blocking button wait (no threading needed)

### User Experience Improvements

1. **Persistent File List**: Loop-based file browser means users can view multiple files without returning to menu hierarchy

2. **Smart Scrolling**:
   - Line-by-line for precision
   - Page jump for speed
   - Visual feedback prevents disorientation

3. **Graceful Degradation**:
   - Empty files show clear message
   - Truncated files notify user
   - Long lines automatically wrap

## Testing Recommendations

### On Pi Zero W 2:

1. **Basic Navigation**:
   ```bash
   # Generate some test loot files
   echo -e "Line 1\nLine 2\nLine 3\nLine 4\nLine 5\nLine 6\nLine 7" > ~/Rustyjack/loot/Nmap/test.txt
   ```

2. **Scroll Testing**:
   - Create files with various line counts (5, 50, 500 lines)
   - Test scrolling to end and back to beginning
   - Verify truncation indicator appears for 5000+ line files

3. **Edge Cases**:
   - Empty files
   - Very long lines (>18 chars - should wrap)
   - Special characters
   - Non-UTF8 content (should error gracefully)

4. **Performance**:
   - Large files (1000+ lines) - should feel responsive
   - Rapid button presses - should queue properly

## Potential Future Enhancements

1. **Search Function**: Add Key2 to search within file
2. **Export Selected**: Mark files for USB transfer
3. **Syntax Highlighting**: Color-code based on file type
4. **Jump to Line**: Quick navigation for large files
5. **Multiple File Compare**: Side-by-side view (limited by display size)

## Code Quality Notes

- Uses existing error handling patterns (`Result<()>`)
- Follows Rust idioms (iterators, pattern matching)
- No unsafe code
- No heap allocations in hot path
- Reuses existing display infrastructure
- Maintains consistency with menu navigation
- Properly handles edge cases (empty files, truncation)

## Deployment

After pulling the changes on your Pi:

```bash
cd ~/Rustyjack
git pull origin test
cd rustyjack-ui
cargo build --release

# Test immediately
sudo systemctl restart rustyjack
# or run directly:
# sudo ./target/release/rustyjack-ui
```

Navigate: **Main Menu → Loot → [Category] → Select file → Scroll with buttons**

---

**Implementation Status**: Complete and pushed to `test` branch
