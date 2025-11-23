#!/usr/bin/env python3
"""
Automatically fix display.rs for embedded-graphics 0.7 compatibility
Run on Pi after git pull: python3 fix_display_final.py
"""

import re
import sys
from pathlib import Path

def fix_display_rs():
    filepath = Path("/root/Rustyjack/rustyjack-ui/src/display.rs")
    
    if not filepath.exists():
        print(f"Error: {filepath} not found")
        return 1
    
    print(f"Reading {filepath}...")
    content = filepath.read_text()
    
    # Backup
    backup_path = filepath.with_suffix(".rs.backup")
    backup_path.write_text(content)
    print(f"Backup saved to {backup_path}")
    
    original_content = content
    
    # Fix 1: Rectangle with Size -> Rectangle with bottom-right Point
    # Pattern: Rectangle::new(Point::new(x, y), Size::new(w, h))
    def fix_rectangle(match):
        point_part = match.group(1)  # "Point::new(x, y)"
        width = match.group(2)
        height = match.group(3)
        
        # Extract x and y from Point::new(x, y)
        point_match = re.search(r'Point::new\(([^,]+),\s*([^)]+)\)', point_part)
        if point_match:
            x = point_match.group(1)
            y = point_match.group(2)
            # Create bottom-right point
            return f'Rectangle::new({point_part}, Point::new({x} + ({width}) as i32 - 1, {y} + ({height}) as i32 - 1))'
        return match.group(0)  # Return original if can't parse
    
    content = re.sub(
        r'Rectangle::new\((Point::new\([^)]+\)),\s*Size::new\(([^,]+),\s*([^)]+)\)\)',
        fix_rectangle,
        content
    )
    
    # Fix 2: Draw error handling - all .draw(&mut self.lcd)? need error mapping
    content = re.sub(
        r'\.draw\(&mut self\.lcd\)\?',
        r'.draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?',
        content
    )
    
    # Fix 3: Text API changes
    # Old: Text::new(text, point, style).draw(...)
    # New: Text::new(text, point).into_styled(style).draw(...)
    content = re.sub(
        r'Text::new\(([^,]+),\s*([^,]+),\s*(self\.[a-z_]+)\)',
        r'Text::new(\1, \2).into_styled(\3)',
        content
    )
    
    # Fix 4: Remove Size import
    content = re.sub(r',\s*Size\s*,', ',', content)
    content = re.sub(r'use embedded_graphics::prelude::Size;?\n?', '', content)
    
    # Fix 5: Ensure prelude is imported
    if 'use embedded_graphics::prelude::*;' not in content:
        # Add after other embedded_graphics imports
        content = re.sub(
            r'(use embedded_graphics::\{[^}]+\};)',
            r'\1\nuse embedded_graphics::prelude::*;',
            content,
            count=1
        )
    
    # Write fixed content
    if content != original_content:
        filepath.write_text(content)
        print(f"✓ Fixed {filepath}")
        print(f"  - Fixed Rectangle API")
        print(f"  - Fixed draw() error handling")
        print(f"  - Fixed Text API")
        return 0
    else:
        print("No changes needed")
        return 0

if __name__ == "__main__":
    try:
        sys.exit(fix_display_rs())
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
