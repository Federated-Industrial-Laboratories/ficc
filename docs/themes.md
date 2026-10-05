# Appearance and custom themes

Open **Appearance** in the console header to change the interface. Select a
theme card to apply it immediately. Search by name or description, or filter
the catalogue by **Light themes**, **Dark themes** or **My themes**.
Separate or fullscreen workspaces also provide **Workspace appearance**.

FICC includes 26 themes: Classic Light, Classic Dark and 24 additional palettes.
Classic Light keeps the original silver console and warm paper. Classic Dark
uses AOTX PRISM's Graphite colors. The additional themes cover linen, botanical,
ocean, jewel, industrial and monochrome palettes.

The selected theme, custom themes and material preference are saved in this
browser for the current origin. Workspace windows on the same origin share
the preference. Another browser profile or a different host, port or protocol
has separate settings. Clearing browser site data removes these preferences.
If browser storage is unavailable, changes apply for the current page session.

## Materials and recovery

Enable **Flat materials** to remove material gradients and the background grid.
Disable this override to use the selected theme's own material settings. Some
themes are flat by design, including Archive Linen, Graph Paper, Carbon
Manuscript and Moss Lantern.

Use **Restore Classic Light** to return to the original appearance and its
material settings. This keeps imported themes available in the catalogue.
If a saved custom identifier conflicts with a newly available built-in theme,
FICC renames the custom identifier and keeps its contents. An invalid saved
theme does not remove other valid custom themes.

## Import, export and share

1. Select a theme and choose **Export JSON** to download its JSON file.
2. Give an exported built-in theme a new `id` before importing it as a custom
   theme. Built-in identifiers are reserved.
3. Edit the file in a text editor, then choose **Import JSON** in Appearance.
4. The imported theme applies immediately. Importing an existing custom `id`
   updates that custom theme.
5. Use **Remove custom theme** to remove the selected imported theme.

Exports include the effective material choice, including the flat override, so
the file can reproduce that appearance. Import one theme object per file.
Files must be valid JSON, at most 64 KiB in UTF-8, without comments or trailing
commas. The complete export, including inherited defaults, must also fit this
limit. A browser can store up to 32 custom themes in addition to the built-in
catalogue. Export custom work before clearing browser site data.

Start with the complete [Tideline example](theme-examples/tideline.json)
for editable gradients, or the [Beacon example](theme-examples/beacon.json)
for a flat theme with a replacement logo.

## Theme format

The required fields are `version`, `id`, `name` and `scheme`. Omitted colors,
materials and logo values inherit the defaults for the chosen scheme.

```json
{
  "version": 1,
  "id": "my-studio",
  "name": "My Studio",
  "description": "A quiet console with a flat finish.",
  "scheme": "light",
  "colors": {
    "orange": "#82b1eb",
    "accent": "#245895",
    "orange-light": "#e5efff",
    "on-accent": "#152d4d"
  },
  "materials": { "enabled": false },
  "logo": { "type": "monogram", "color": "accent", "secondary": "brand" }
}
```

| Field | Accepted value |
| --- | --- |
| `version` | The number `1`. |
| `id` | 1-48 characters; a lowercase letter first, then lowercase letters, digits or hyphens. |
| `name` | 1-64 characters. |
| `description` | Optional text, up to 240 characters; an empty string is accepted. |
| `scheme` | `light` or `dark`; selects the base palette and native control appearance. |
| `colors` | An optional object containing named color overrides. |
| `materials` | Optional material, gradient and background grid settings. |
| `logo` | Optional built-in symbol or custom vector paths. |

Text fields cannot contain control characters. Unrecognized fields are rejected
so spelling mistakes do not silently change the result. Theme files contain
data only; CSS, scripts, image URLs and raw SVG documents are not accepted.

## Color tokens

Color values use six-digit hex notation: `#RRGGBB`. `shadow`, `overlay` and
the material grid color also accept eight-digit `#RRGGBBAA` values. Alpha is
not accepted for normal text or surface colors.

| Tokens | Purpose |
| --- | --- |
| `canvas` | Background around the application shell. |
| `white`, `paper` | Main content background and inner panel or input background. |
| `surface`, `rail` | Secondary panels, controls and navigation material. |
| `ink`, `muted` | Main text and supporting text. |
| `orange` | Primary button fill, selected edges and other accent marks. |
| `accent` | Accent text, links and meter fills. |
| `orange-light` | Selection and mode-banner background. |
| `on-accent` | Text on primary buttons. |
| `line`, `frame` | Dividers and control or panel borders. |
| `brand` | Wordmark and table-heading text. |
| `dark`, `status-ink` | Status-strip background and text. |
| `highlight`, `shadow` | Material highlights and shadows. |
| `green`, `red`, `warning` | Positive, error and warning status text. |
| `info`, `info-bg` | Information notice text and background. |
| `warning-bg`, `error-bg` | Warning and error notice backgrounds. |
| `on-danger` | Text on buttons filled with `red`. |
| `focus` | Keyboard focus outline. |
| `terminal-bg`, `terminal-ink`, `terminal-cursor` | Terminal background, default text and cursor. |
| `overlay` | Backdrop behind modal dialogs. |

The names `white` and `orange` identify roles, not required colors. Dark themes
use a dark `white` surface; blue themes can use blue `orange` accents.

Keep text readable on every surface where it appears. Check `muted`, `brand`
and semantic status colors as well as `ink`, including selected rows and all
gradient stops. Check `on-accent` against `orange`, `on-danger` against `red`
and notice text against its notice background. Preserve visible distinctions
between success, warning and error states. The importer validates structure
and bounded values; it does not certify contrast or visual accessibility.

## Gradients and the background grid

Five optional gradients define the materials:

| Material | Used for |
| --- | --- |
| `metal` | Panel titles and metal trim. |
| `control` | Button surfaces. |
| `rail` | Navigation background. |
| `masthead` | Header background. |
| `table` | Table headings. |

Each gradient has an angle from 0 to 360 degrees and 2-8 stops. Each stop has
`color` and `at` fields. Colors are palette token names or six-digit hex values.
Positions range from 0 to 100 and must be in ascending order; equal positions
create a sharp transition. Named tokens track later palette edits.

```json
{
  "enabled": true,
  "metal": {
    "angle": 110,
    "stops": [
      { "color": "paper", "at": 0 },
      { "color": "surface", "at": 45 },
      { "color": "rail", "at": 100 }
    ]
  },
  "grid": { "enabled": true, "size": 32, "color": "#175b700c" }
}
```

Place this object in the theme's `materials` field. `grid.size` ranges from
8 to 160 pixels. Set `grid.enabled` to `false` to remove just the grid.
Set `materials.enabled` to `false` to disable all gradients and the grid for
that theme. The Appearance dialog's **Flat materials** override can disable
these effects for any selected theme.

## Logo graphics

Choose `cluster`, `orbit` or `monogram` as the logo `type` for a built-in symbol.
Its `color` and `secondary` fields accept palette tokens or six-digit hex
colors. Their defaults are `orange` and `brand`.

For a replacement graphic, use `type: "paths"` with a four-number `viewBox`
and a `paths` array. The [Beacon example](theme-examples/beacon.json) shows
a complete replacement. Each path accepts:

| Field | Accepted value |
| --- | --- |
| `d` | SVG path commands and numbers, beginning with `M` or `m`; up to 4,096 characters. |
| `fill` | A palette token, six-digit hex color or `none`; defaults to `orange`. |
| `stroke` | A palette token, six-digit hex color or `none`; defaults to `none`. |
| `strokeWidth` | A number from 0 to 32; defaults to 1. |

Supply 1-64 paths. The view box uses `[x, y, width, height]`; coordinates range
from -4,096 to 4,096, and dimensions from 1 to 4,096. Paths use their own
`fill` and `stroke` values; `color` and `secondary` configure built-in symbols.
Reference palette tokens directly in custom paths to recolor the graphic.

Use path data exported from a vector editor, without its enclosing SVG markup.
The format supports geometry and color only. It does not load external files,
fonts, images, filters, event handlers or scripts.
