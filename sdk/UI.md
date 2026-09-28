# Host component format

[SDK](README.md) | [Process protocol](PROTOCOL.md) | [Workspace guide](../docs/workspaces.md)

A manifest's `ui` field is a JSON component tree. Its root is `column`, `row`,
`group` or `tabs`. The host renders every component. Packages cannot provide
HTML, CSS, JavaScript handlers or remote component URLs.

Common fields are `id`, `label`, `disabled`, `state`, `message` and `bind`.
Use distinct IDs for components with retained state or selection. Available
states are `ready`, `loading`, `empty`, `stale` and `error`.

## Components

| Type | Main fields or behavior |
| --- | --- |
| column, row, group | `children`; vertical, horizontal or framed containers. |
| toolbar, menu | `children`; grouped host actions. |
| tabs | `items`, each with `id`, `label` and `children`. |
| text | `text`. |
| status | `text` and `tone`: neutral, good, warning or error. |
| details | `items` of `label` and scalar `value`. |
| button | Declared `action` and optional `parameters` mapping. |
| table | `columns`, `rows`, `selection` and `page_size`. |
| field | `name`, `value`, and text, number or checkbox `input_type`. |
| select, radio | `name`, `options` and selected `value`. |
| slider | `name`, `value`, `min`, `max` and positive `step`. |
| progress, meter | Bounded numeric `value`; meter also supports `min`. |
| tree | `name`, nested `items` and selected `value`. |
| pager | `name`, `page` and `total`. |
| log | Bounded `lines` of plain text. |
| credential | A host-owned opaque `ref`; no password value. |
| editor | Workspace notes with explicit Save. |
| file-editor | Host-owned registered-root text editor; requires an `id`. |
| clock | IANA `timezone`, with UTC as the default. |
| audio-player | Host playback controls and explicit local file selection. |

The tree has at most 128 components and eight nested levels. Containers have at
most 32 children. Tab groups have at most 16 tabs. Unknown fields are refused.
The format validator in `src/ficc/modules/ui.py` defines each type's exact fields.

## Tables and action parameters

Columns have stable `id` and `label` fields. Rows have a stable `id` and a
`values` object keyed by column ID. Values are strings, finite numbers, booleans
or null. Tables provide host sorting, filtering, selection and paging.

Selection is `none`, `single` or `multiple`. A selectable table requires an `id`.
Selections identify rows by ID, so sorting cannot change the requested objects.
There are at most 128 rows and 32 columns; page sizes range from 1 to 128.

Button parameters use one source per parameter: a named field, a table selection,
or a literal scalar. The named action's parameter schema still validates them.

```json
{
  "type": "button",
  "label": "Inspect selection",
  "action": "inspect",
  "parameters": {
    "resource_ids": {"selection": "resources"},
    "limit": {"value": 64},
    "filter": {"field": "filter"}
  }
}
```

This component requires an `inspect` action, a selectable `resources` table and
a field named `filter` in the same view. Module actions receive the complete
frozen target list. Host confirmation remains separate from a mutation preview.

## Result bindings

A binding names an action and a literal path through that action's result.
Paths have at most eight keys or array indices. They cannot call functions,
evaluate expressions, or access prototypes. Invalid data produces a visible
component error instead of entering the document as HTML.

```json
{
  "type": "table",
  "id": "systems",
  "columns": [{"id": "name", "label": "System"}],
  "rows": [],
  "bind": {
    "rows": {"action": "load", "path": ["results", 0, "data", "rows"]}
  }
}
```

This table consumes the declared `load` action's first result. That result's
`data.rows` must match the table row format. See the complete
[system status manifest](../modules/system-status/manifest.json).

The host controls temporary action output. A new invocation removes old preview
controls. A delayed earlier response cannot replace the latest action's output.
Provider confirmations show host-resolved identities and effects, not module text.

## Host services

The note editor requires `workspace:read` and `workspace:write`. The audio player
also requires `audio:playback`. The file editor requires `workspace:read` and
`files:read`; `files:write` can remain optional.

Console primitives return opaque references for the shared viewer. They do not
return provider passwords, sockets or unrestricted URLs. The host supplies input
release, fullscreen transitions, size limits and current permission checks.
