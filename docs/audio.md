# Workspace sound

[Contents](README.md) | [Workspaces](workspaces.md) | [Modules](modules.md)

The host sound manager supplies master volume, master mute and per-panel playback
controls. The supplied audio-player package uses this same service. Other programs'
audio remains under the operating system's sound controls.

## Play a file

1. Install the supplied audio player through **Manage modules**.
2. Grant `workspace:read`, `workspace:write` and `audio:playback` to the selected workspace.
3. Add the module to that workspace.
4. Select a file with **Open local audio**.
5. Select **Play**.

Files must be non-empty and at most 128 MiB. Supported formats depend on the
browser. WAV, Ogg, MP3, FLAC, M4A and AAC are recognized when the browser
can decode them. An unsupported format produces a visible error.

**Pause** retains the current position. **Stop** returns to the start. Use the
position slider to seek when duration is available. **Volume** and **Mute source**
control that panel. The **Sound** strip controls master volume and **Mute all**.

The file remains a browser-local selection. It is not uploaded, included in a
controller backup, or reopened after a page reload. Volume and mute preferences
are saved. Restoring a workspace never starts playback automatically.

## Ownership and limits

One window holds a playback lease for each panel. Another window cannot start
that same panel while its lease is active. Stop playback in the first window,
then select the file and **Play** in the second. If a window disappears, its
lease expires after 15 seconds. Active windows renew authority every five seconds.

Hiding the page or panel releases playback. Session expiry, package disable and
permission loss also release playback when checked. A failed authority check
stops sound and requires a new explicit **Play** action.

The audio graph limits the combined stereo peak within each window. It does not
control the operating system mixer or combine output from separate windows.
Use the operating system to select the output device. Microphone capture and VM
console audio are not enabled by workspace playback permission.
