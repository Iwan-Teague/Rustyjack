#!/usr/bin/env python3
"""
Fix display.rs to work with embedded-graphics 0.7 API
Run this on the Pi after git pull
"""

import re
import sys

def fix_display_rs():
    filepath = "/root/Rustyjack/rustyjack-ui/src/display.rs"
    
    with open(filepath, 'r') as f:
        content = f.content()
    
    # Backup
    with open(filepath + ".backup", 'w') as f:
        f.write(content)
    
    # Fix 1: Rectangle API - change from Size to bottom-right Point
    # Rectangle::new(Point::new(x, y), Size::new(w, h)) 
    # -> Rectangle::new(Point::new(x, y), Point::new(x+w-1, y+h-1))
    pattern = r'Rectangle::new\(\s*Point::new\((\d+),\s*(\d+)\),\s*Size::new\(([^,]+),\s*([^)]+)\)\s*\)'
    def replace_rectangle(match):
        x, y, w, h = match.groups()
        # Convert to use bottom-right point
        return f'Rectangle::new(Point::new({x}, {y}), Point::new({x} + ({w}) as i32 - 1, {y} + ({h}) as i32 - 1))'
    
    content = re.sub(pattern, replace_rectangle, content)
    
    # Fix 2: Draw error handling - .draw() returns () in 0.7, needs error mapping
    content = re.sub(
        r'\.draw\(&mut self\.lcd\)\?;',
        r'.draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;',
        content
    )
    
    # Fix 3: Remove Size import if present  
    content = re.sub(r'use embedded_graphics::prelude::Size;', '', content)
    
    # Fix 4: Text API - Text::new in 0.7 takes (text, position, style) differently
    # This is complex, so we'll handle it with a pattern
    # Old: Text::new(text, Point::new(x, y), style).draw(&mut self.lcd)?;
    # New: Text::new(text, Point::new(x, y)).into_styled(style).draw(&mut self.lcd).map_err(...)?;
    
    pattern = r'Text::new\(([^,]+),\s*([^,]+),\s*([^)]+)\)\.draw\(&mut self\.lcd\)\?;'
    replacement = r'Text::new(\1, \2).into_styled(\3).draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Text draw error"))?;'
    content = re.sub(pattern, replacement, content)
    
    # Save fixed content
    with open(filepath, 'w') as f:
        f.write(content)
    
    print(f"Fixed {filepath}")
    print(f"Backup saved to {filepath}.backup")
    return 0

if __name__ == "__main__":
    sys.exit(fix_display_rs())
