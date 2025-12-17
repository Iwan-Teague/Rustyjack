# Loot Viewer

Supersedes:
- `LOOT_VIEWER_ARCHITECTURE.md`
- `LOOT_VIEWER_IMPLEMENTATION.md`
- `LOOT_VIEWER_GUIDE.md`

## UX
- From Loot menu, user sees file list immediately; can open multiple files without backing out.
- Scrollable viewer: up/down line scroll, select/right page-down (~5 lines), left/back to list. Key1 refresh, Key2 main menu, Key3 reboot (with confirmation).
- Title shows filename and position (e.g., `file.txt (15/150)`); hints indicate more content.

## Implementation
- Reworked `show_loot()` loop to keep user in the list until exit.
- Truncation guard for very large files (e.g., 5000+ lines).
- Status bar retained (CPU/RAM/disk).

## Usage tips
- Wireless captures stored under `loot/Wireless/<target>/`; Ethernet loot under `loot/Ethernet/`.
- File browsing is read-only; errors surface in-place.
