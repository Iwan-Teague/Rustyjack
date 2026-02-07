RustyJack UI Theme & Color System — Deep Dive

Target: Pi Zero 2 W build • Report date: 2026-02-07


# Executive summary

Theme customization in the current RustyJack UI is implemented as a small, centralized color palette loaded from gui_conf.json into a ColorScheme (hex strings). At runtime, Display::update_palette converts those strings into an Rgb565 Palette that most drawing code uses consistently.

Users can change several colors via Settings → Colors. Each color uses the same picker flow (a menu-style list of preset colors), and changes are applied immediately to the running display.

The system is mostly homogenized inside the UI crate, but there are a few sharp edges that cause inconsistent behavior, incomplete coverage, and accidental reversion of theme changes. This report enumerates those issues and proposes concrete fixes that keep code size under control by reusing existing flows.

# Scope and sources inspected

Primary code inspected:

- crates/rustyjack-ui/src/config.rs
- crates/rustyjack-ui/src/menu.rs
- crates/rustyjack-ui/src/app/settings.rs
- crates/rustyjack-ui/src/app/menu.rs
- crates/rustyjack-ui/src/display.rs
- docs/ui_action_map.md
Note: docs/ and logs/done/ contain very little direct documentation of theming. The authoritative behavior is in code.

# How theming works today

## Where theme values live

Theme is represented by ColorScheme in GuiConfig and persisted to gui_conf.json. Each field is a hex string like "#AA00FF".

```text
crates/rustyjack-ui/src/config.rs (lines 147–178)
pub struct ColorScheme {
  pub background: String,
  pub border: String,
  pub text: String,
  pub selected_text: String,
  pub selected_background: String,
  pub gamepad: String,
  pub gamepad_fill: String,
  pub toolbar: String,
}
```

At runtime, Display converts ColorScheme into a Palette of Rgb565 values:

```text
crates/rustyjack-ui/src/display.rs (lines 2485–2510)
impl Palette {
  pub fn from_scheme(colors: &ColorScheme) -> Self {
    Self {
      background: parse_color(&colors.background, Rgb565::BLACK),
      border: parse_color(&colors.border, Rgb565::WHITE),
      text: parse_color(&colors.text, Rgb565::WHITE),
      selected_text: parse_color(&colors.selected_text, Rgb565::WHITE),
      selected_background: parse_color(&colors.selected_background, Rgb565::BLACK),
      toolbar: parse_color(&colors.toolbar, Rgb565::new(20, 20, 20)),
    }
  }
}
```

Important: gamepad and gamepad_fill exist in config but are not currently included in Palette and appear unused in the UI codebase.

## How the user changes colors in the UI

The UI wiring explicitly maps SetColor to App::pick_color:

```text
docs/ui_action_map.md (line 17)
| SetColor | `App::pick_color` | Local | N/A |
```

Settings → Colors provides entries for Background, Text, Selected Text, Selected BG, and Toolbar:

```text
crates/rustyjack-ui/src/menu.rs (lines 569–582)
fn colors_menu() -> Vec<MenuEntry> {
  vec![
    MenuEntry::new("Background", SetColor(Background)),
    MenuEntry::new("Text", SetColor(Text)),
    MenuEntry::new("Selected Text", SetColor(SelectedText)),
    MenuEntry::new("Selected BG", SetColor(SelectedBackground)),
    MenuEntry::new("Toolbar", SetColor(Toolbar)),
  ]
}
```

All these entries reuse the same picker wizard (menu-style selector) with a fixed set of preset colors:

```text
crates/rustyjack-ui/src/app/settings.rs (lines 33–67)
pub(crate) fn pick_color(&mut self, target: ColorTarget) -> Result<()> {
  let choices = [
    ("White", "#FFFFFF"), ("Black", "#000000"), ("Green", "#00FF00"),
    ("Red", "#FF0000"), ("Blue", "#0000FF"), ("Navy", "#000080"),
    ("Purple", "#AA00FF"),
  ];
  if let Some(idx) = self.choose_from_menu("Pick Color", &labels)? {
    self.apply_color(target, choices[idx].1);
    self.show_message("Colors", ["Updated"]) }
}
pub(crate) fn apply_color(&mut self, target: ColorTarget, value: &str) {
  // updates self.config.colors.* then:
  self.display.update_palette(&self.config.colors);
}
```

## Runtime consistency

Most rendering code uses Palette values (background, toolbar, selected_background, selected_text, border) rather than hard-coded colors. This is good: theme changes generally propagate everywhere once update_palette has run.

There are a few exceptions (detailed in Problems below) where hard-coded colors bypass the palette.

# Problems found and recommended fixes

## Problem 1: Color changes are applied but not persisted (inconsistent with other settings)

Where: App::pick_color/apply_color updates self.config.colors and refreshes Display palette, but does not save gui_conf.json. Meanwhile many other settings (e.g., toggle_logs, interface selection) save immediately.

Why it matters: Users can think they ‘set a theme’, reboot, and lose it. It is also inconsistent UX: some settings persist instantly and others require a separate Save Config action, with no ‘unsaved changes’ indicator.

Recommended fix: Persist after a successful color change (save the config file) OR make the entire Settings system explicitly ‘staged’ with an on-screen unsaved marker. The smaller change is to save immediately.

### What the fix looks like

```text
/// In pick_color, after apply_color:
self.apply_color(target, hex);
let config_path = self.root.join("gui_conf.json");
if let Err(e) = self.save_config_file(&config_path) {
    self.show_message("Colors", ["Updated", "Save failed"])?;
} else {
    self.show_message("Colors", ["Updated", "Saved"])?;
}
```

## Problem 2: Theme customization coverage is incomplete (Border is used but not editable; unused fields exist)

Where: ColorScheme defines border, gamepad, gamepad_fill; Palette uses border; colors menu does not expose Border; gamepad fields appear unused.

Why it matters: You have theme-relevant values that affect rendering (border) but are not user-editable, and other values that are editable only by JSON editing (or dead). This creates fragmentation and surprises when trying to ‘homogenize’ theme behavior.

Recommended fix: Either (A) expose every actively used palette role in Settings → Colors, and remove (or implement) unused roles, OR (B) explicitly label hidden roles as advanced-only and provide a separate Advanced Colors menu.

### What the fix looks like

```text
/// Option A: expose Border in colors_menu
fn colors_menu() -> Vec<MenuEntry> {
  vec![
    MenuEntry::new("Background", SetColor(Background)),
    MenuEntry::new("Border", SetColor(Border)),
    MenuEntry::new("Text", SetColor(Text)),
    MenuEntry::new("Selected Text", SetColor(SelectedText)),
    MenuEntry::new("Selected BG", SetColor(SelectedBackground)),
    MenuEntry::new("Toolbar", SetColor(Toolbar)),
  ]
}

/// If gamepad/gamepad_fill are not used: remove from ColorScheme
/// or wire them into Palette + rendering so they’re real.
```

## Problem 3: Hard-coded colors bypass the theme (splash screen clear + fallback text)

Where: Display::show_splash_screen clears to Rgb565::BLACK and uses a hard-coded purple text style for fallback (Rgb565::new(21,0,31)). Display::new also clears to black before palette is constructed.

Why it matters: This causes immediate visible ‘theme glitches’: a non-black background theme flashes black on boot, and the fallback splash text ignores configured text color. It undermines the promise that theme changes are global.

Recommended fix: Replace hard-coded colors with palette roles wherever the screen is intended to be themed. Keep hard-coded colors only for diagnostics.

### What the fix looks like

```text
/// In Display::new, use the configured palette background
let palette = Palette::from_scheme(colors);
Rectangle::new(Point::new(0,0), Size::new(w,h))
  .into_styled(PrimitiveStyle::with_fill(palette.background))
  .draw(&mut lcd)?;

/// In show_splash_screen
let style = PrimitiveStyle::with_fill(self.palette.background);
...
let text_style = MonoTextStyleBuilder::new()
  .font(&FONT_6X10)
  .text_color(self.palette.text)
  .build();
```

## Problem 4: Invalid color values silently fall back, and colors are not normalized on load

Where: parse_color only accepts 6-digit hex and returns a fallback without warning; GuiConfig::load normalizes some sections but not colors.

Why it matters: If gui_conf.json is edited manually (or written by a future picker), invalid values will quietly become white/black/etc depending on fallback. Debugging becomes annoying because the UI ‘works’ but ignores the user’s config.

Recommended fix: Add ColorScheme::normalize() called from GuiConfig::load, to validate/normalize every color string (trim, uppercase, enforce leading #, clamp to #RRGGBB). If invalid, restore default and record a warning for the user.

### What the fix looks like

```text
/// Sketch
impl ColorScheme {
  pub fn normalize(&mut self) -> bool {
    let mut changed = false;
    changed |= normalize_hex(&mut self.background, "#000000");
    changed |= normalize_hex(&mut self.border, "#8800AA");
    ...
    changed
  }
}

/// In GuiConfig::load
if config.colors.normalize() { changed = true; }
```

## Problem 5: The ‘theme’ is a flat list of raw colors; no presets, no semantic roles, no contrast guardrails

Where: Current picker provides a handful of fixed colors; users can easily create unreadable combinations (e.g., black text on black background), and there is no concept of a cohesive theme preset.

Why it matters: As soon as you add more screens and UI elements, a flat list of colors tends to grow into inconsistent, hard-to-maintain ‘one-off’ values. Lack of semantic roles also makes it hard to keep file size down while scaling the UI.

Recommended fix: Introduce a small set of semantic roles and (optionally) theme presets that populate ColorScheme. Keep overrides per role. Add a lightweight contrast check/warning for critical pairs (text vs background, text vs toolbar, selected_text vs selected_background).

### What the fix looks like

```text
/// Minimal approach (low code size):
enum ThemePreset { DarkPurple, Light, HighContrast }

fn apply_preset(colors: &mut ColorScheme, preset: ThemePreset) {
  match preset {
    DarkPurple => { colors.background="#000000".into(); ... }
    Light => { colors.background="#FFFFFF".into(); colors.text="#000000".into(); ... }
    HighContrast => { ... }
  }
}

/// Contrast warning (see WCAG contrast ratio): if below threshold, show message.
if contrast_ratio(text, background) < 4.5 { warn_user(); }
```

# After-state: what the project looks like once stabilized

After implementing the above fixes, the UI theming system becomes predictable, centralized, and scalable without ballooning code size.

## Clear goals met

- Single source of truth for all themed colors: ColorScheme → Palette → drawing code (no accidental hard-coded UI colors).
- One consistent edit flow for all theme-related changes (same wizard + same persistence behavior).
- All actively used palette roles are editable; unused config fields are removed or fully implemented.
- Theme changes persist reliably and are visible immediately.
- Optional: a small set of presets provides coherent looks without forcing manual per-color editing.
- Optional: contrast warnings prevent accidental unreadable combinations.
## Recommended architecture (minimal, practical)

Keep the current ColorScheme/Pallette split, but add a tiny ‘Theme’ layer in the UI crate:

• ThemePreset (enum) + apply_preset()

• ColorRole/ColorTarget mapping centralized (get_mut on ColorTarget)

• ColorScheme::normalize()

• App helper: mutate_config_and_save(label, |cfg| { ... })

## Reference notes for implementation

For contrast math and thresholds, the WCAG contrast ratio definition is a good, well-known baseline; even if you don’t fully implement sRGB gamma in-device, a simplified luminance heuristic is better than nothing.

For ‘palette as a struct’ patterns, Rust GUI frameworks like Iced model themes as a Palette that drives consistent styling; the same idea maps well to embedded UIs.

# External references

- W3C/WAI: Contrast ratio definition (WCAG): https://www.w3.org/WAI/GL/wiki/Contrast_ratio
- MDN: Understanding WCAG color contrast: https://developer.mozilla.org/en-US/docs/Web/Accessibility/Guides/Understanding_WCAG/Perceivable/Color_contrast
- embedded-graphics docs: MonoTextStyleBuilder: https://docs.rs/embedded-graphics/latest/embedded_graphics/mono_font/struct.MonoTextStyleBuilder.html
- Iced docs: theme / Palette pattern: https://docs.iced.rs/iced/theme/index.html
- Serde docs: default values for fields: https://serde.rs/attr-default.html
