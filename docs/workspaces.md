# Workspaces and productivity

[Contents](README.md) | [Modules](modules.md) | [Sound](audio.md) | [Remote displays](viewer.md)

The **Workspace** navigation entry opens a saved desktop area. Each workspace
contains module panels and their saved data. Each window has a separate layout,
so two monitors can show the same workspace with different arrangements.

The **Current project** selector controls the workspace list. Members of one
project share its saved panels and contents. Each user's views and saved window
surfaces are private. Only the local owner administers installed packages and
system providers. See [identities and projects](identities.md) for membership,
project switching and the current local-access limits.

## Create and arrange

Enter a name and select **New workspace**. Use **Manage modules** to install and
enable a package. Select that package and select **Add module**. System modules
ask for a target selection from their granted machines or folders.

Drag panel tabs to arrange groups. **Float** creates a movable window inside the
workspace.

**Dock** returns it to a docked group. **Expand** fills the workspace
with that panel; selecting it again restores the previous arrangement.

**Hide** closes a panel's current view and retains its saved data.
**Show hidden panels** makes hidden panels available again.

**Remove panel** deletes the panel
and its saved data after confirmation. Other layouts that contain it reset.

Select another workspace and use **Split right** or **Split below** to tile it.
A browser surface can contain four workspace tiles. A workspace can contain
64 panels. FICC stores at most 64 workspaces and 256 saved views.

## Separate windows and fullscreen

**Open in window** opens the selected workspace in a separate browser window.
Move that window to another monitor with the operating system's window controls.
If the browser blocks it, use the displayed link. Window URLs contain workspace
and layout identities, without sign-in credentials.

**Expand workspace area** uses the browser area. **Fullscreen** requests browser
fullscreen. Panel expansion, workspace fullscreen and display fullscreen retain
their owning layout. Exiting a fullscreen display restores the workspace's
previous fullscreen state. See [input release](viewer.md) before using a VM.

Floating panels remain within the current viewport after resizing. Use **Recover
panels** if a restored arrangement is unusable. Use **Saved layouts** to inspect
or resume window arrangements, or remove unused window and view records. Removing a layout does not delete
workspace data.

After a fresh application launch, select **Workspace**. If saved layouts exist,
select **Resume saved window**.
Choose **Resume window layout** beside the required workspace names in the table.
This restores its tiles, panel positions and saved view identities in the current window.
Close the original window first to avoid concurrent layout edits.

When saved layouts exist, entering Workspace does not create another saved window record.
Select a workspace and choose **Open** for a new arrangement.
**Open in window** still creates a separate layout for another monitor.
Save or discard unsaved text before resuming another window layout.

## Saving and concurrent changes

### Project templates

Open a workspace and select **Project templates**. **Share current panel
template** publishes a new immutable recipe in the current project. It contains
only module package digests and panel titles. Saved notes, panel input values,
targets, grants and personal window geometry are excluded.

Open the destination workspace and choose **Add panels to open workspace**.
Install and enable the exact module packages first, with grants for that
workspace. Select target systems or folders when prompted. All panels are
submitted together through the normal revision and permission checks; the
template cannot grant access or activate a missing package. Each new panel
starts with empty saved data and its own identity.

Project members with workspace write access can share and remove template
versions. Removing a version does not change any existing workspace. Other
projects cannot list or use the shared catalogue. Personal layouts remain private
to their user and browser surface.

### Saved state

FICC saves layout changes automatically. Notes have an explicit **Save** action.
Saved data lives in the controller's private state directory. File permissions
protect it from other local accounts; FICC does not encrypt that directory.
Use a stopped-controller [backup](backup.md) before moving or replacing it.

Concurrent edits use revision checks. A conflicting save is refused instead of
overwriting newer data. Preserve unsaved text before selecting **Reload saved
workspace**. **Discard unsaved text** requires confirmation and removes local
drafts while retaining saved notes. Leaving Workspace waits for pending saves
and refuses navigation when text needs saving or explicit discard.

Removing a workspace deletes its panels and notes after confirmation. Managed
machines and workloads remain unchanged. Retained edit copies or lifecycle
receipts can prevent removal until their recovery and cleanup are complete.

## Included productivity panels

| Panel | Behavior |
| --- | --- |
| Clock | Shows the current time; the supplied package uses UTC. |
| Notes | Stores plain text in the workspace after explicit Save. |
| Text file editor | Reads existing UTF-8 files from selected registered roots. |
| Audio player | Plays an explicitly selected local file through shared sound controls. |
| System status | Shows saved measurements and marks stale or unavailable data. |

The file editor supports local and enrolled-system roots. Register roots through
the [file controls](files.md) first. Grant `files:read`, then select the roots for
the editor panel. Add optional `files:write` only for permitted changes.

The editor accepts text files up to 256 KiB. It does not provide compilation,
debugging or language-server features. **Save file** checks the opened file
identity and retains original and draft copies. Concurrent external changes
cause a conflict. **Check save outcome** inspects an uncertain save without
repeating it. Inspect **Retained edit copies** before confirming their removal.

Do not remove a root or panel needed for retained edit recovery. Disabling a
module or revoking a permission still takes effect immediately. Permission
restoration and a fresh inspection may be needed to finish recovery.
