# Display Fixes - Dead Pixels & Text Wrapping

## Issues Fixed

### 1. Dead Pixels on Display Edges
**Problem:** First column (leftmost) and last row (bottom) of the 128x128 display had dead pixels, causing content to be partially invisible.

**Solution:** Adjusted the display offset values to shift the entire rendering area away from the dead pixel regions:
- `LCD_OFFSET_X`: Increased from `2` to `3` (shifts content 1 pixel right)
- `LCD_OFFSET_Y`: Increased from `1` to `2` (shifts content 1 pixel up)

This centers the GUI on the working pixels of the display, avoiding the dead edges.

### 2. Text Truncation Beyond 18 Characters
**Problem:** Long text strings (operation names, messages, network SSIDs, etc.) were getting truncated with `...` or cut off at the display edge, making them unreadable.

**Solution:** Implemented intelligent text wrapping:
- Created `wrap_text()` helper function that breaks text at 18-character width
- Wraps on word boundaries when possible (avoids breaking mid-word)
- Force-breaks very long words that exceed the line width
- Applied to all dialog boxes, progress messages, and status displays

## Files Modified

### `rustyjack-ui/src/display.rs`
1. **Display offset adjustment** (lines 28-31)
   - Changed `LCD_OFFSET_X` from 2 to 3
   - Changed `LCD_OFFSET_Y` from 1 to 2
   - Added comment explaining the dead pixel avoidance

2. **Text wrapping function** (lines 10-68)
   - New `wrap_text()` function handles word-boundary aware line breaking
   - Handles edge cases like very long words and empty strings

3. **Dialog rendering** (`draw_dialog()`, lines 614-636)
   - Now wraps each line at 18 characters before rendering
   - Reduced line spacing from 12px to 10px to fit more wrapped lines
   - Stops rendering if running out of vertical space

4. **Progress dialog rendering** (`draw_progress_dialog()`, lines 638-675)
   - Wraps both title and message text instead of truncating
   - Takes first wrapped line of title (for space)
   - Shows up to 2 wrapped lines of message

5. **Attack metrics dashboard** (lines 856-866)
   - Changed from truncation (`"{}..."`) to wrapping for operation names
   - Wraps at 16 chars to account for bullet point prefix

## What This Means for Users

### Before:
- Menu items and messages that extended to the left or bottom edges were partially invisible
- Long operation names appeared as "Very Long Oper..." with truncation
- Network names, file paths, and error messages were often unreadable

### After:
- All content is visible on the working display area
- Long text automatically wraps to multiple lines (e.g., "Very Long Operation" → "Very Long" on line 1, "Operation" on line 2)
- Full information is readable without truncation
- More professional appearance with proper text flow

## Testing Instructions

On your Pi Zero W 2:

```bash
# Pull the latest changes
cd ~/Rustyjack
git pull origin test

# Rebuild the UI
cd rustyjack-ui
cargo build --release

# Stop the service and test manually
sudo systemctl stop rustyjack
sudo ./target/release/rustyjack-ui
```

### What to Verify:
1. **Dead pixel fix:** Check that menu borders and text don't appear cut off on the left edge or bottom
2. **Text wrapping:** Navigate to operations with long names (e.g., "Full Vulnerability Scan") and verify they wrap to multiple lines instead of truncating
3. **Dialog messages:** Run operations that show progress/status messages and verify long text wraps properly
4. **Overall appearance:** Display should look more centered and professional

### Known Characteristics:
- Maximum of **18 characters per line** for wrapped text
- Dialog boxes can show approximately **5-6 wrapped lines** depending on spacing
- Progress dialogs show **title + 2 message lines** maximum
- Text wrapping prefers word boundaries but will force-break very long words

## Technical Details

### Display Specification:
- **Resolution:** 128x128 pixels
- **Dead pixels:** Column 0 (left), Row 127 (bottom)
- **Working area:** 127x127 effective pixels with new offset
- **Font:** FONT_6X10 (6 pixels wide, 10 pixels tall)
- **Max chars/line:** 18 characters (6px × 18 = 108px, leaving margins)

### Wrapping Algorithm:
1. If text ≤ 18 chars: return as single line
2. Split text into words by whitespace
3. For each word:
   - If it fits on current line: add it
   - If it doesn't fit: start new line
   - If word itself > 18 chars: force-break at 18-char boundaries
4. Return array of wrapped lines

This ensures maximum readability while respecting the physical display constraints.
