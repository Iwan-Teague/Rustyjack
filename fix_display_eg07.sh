#!/bin/bash
# This script fixes display.rs to work with embedded-graphics 0.7

cd /root/Rustyjack/rustyjack-ui/src

# Backup original
cp display.rs display.rs.backup

# Fix: Replace Size::new with Point (embedded-graphics 0.7 uses points for rectangles)
# Fix: Replace .into_styled(style).draw() with .into_styled(style).draw()  (works similarly)
# Fix: Replace MonoTextStyle with TextStyle
# Fix: Replace .draw(&mut self.lcd)? with .draw(&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?

# The main issue is that embedded-graphics 0.7 uses a different Rectangle API
# and Text API, and returns () instead of Result

sed -i 's/MonoTextStyle/TextStyle/g' display.rs
sed -i 's/&FONT_6X10/Font6x8/g' display.rs
sed -i 's/font_regular/text_style_regular/g' display.rs
sed -i 's/font_highlight/text_style_highlight/g' display.rs  
sed -i 's/font_small/text_style_small/g' display.rs

# Fix Rectangle API - embedded-graphics 0.7 uses top_left and bottom_right points
# Instead of Point and Size
sed -i 's/Rectangle::new(\([^,]*\), Size::new(\([^,]*\), \([^)]*\)))/Rectangle::new(\1, Point::new(\1.x + \2 as i32, \1.y + \3 as i32))/g' display.rs

# Fix draw error handling - 0.7 returns () not Result
sed -i 's/\.draw(&mut self\.lcd)?;/.draw(\&mut self.lcd).map_err(|_| anyhow::anyhow!("Draw error"))?;/g' display.rs

echo "Fixed display.rs for embedded-graphics 0.7"
echo "Backup saved as display.rs.backup"
