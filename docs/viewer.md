# Remote displays

Open a console from a VM module, then select **Open display in FICC**. The host
checks the current VM identity and grants before each connection. The title shows
the enrolled system and bound VM identity. Input is released when the display opens.

Select **Capture input** to send keyboard and pointer input to the VM. Select
**Release input**, or press **Control + Alt + Shift**, to release all pressed keys
and buttons. Input also releases when focus changes, the page hides, or the display
changes fullscreen mode. FICC does not use keyboard lock or pointer lock.

**Expand display** fills the workspace display area. **Fullscreen display** requests browser
fullscreen. A display can enter fullscreen while its workspace is fullscreen.
Exiting the display returns to the workspace. Restoring a display brings its controls into view.
The module tab and window controls remain available. Resizing fits the image within the available area.

**Disconnect display** closes the display transport. It does not stop the VM.
Open another console explicitly to reconnect. Input is never replayed after a
connection failure. Package disable, grant revocation, session expiry and panel
removal close the affected connection.

## Runtime and limits

The viewer uses the display transport declared by the selected provider.
The host does not give modules a provider address, password or file
descriptor. A reference lasts 60 seconds. Its attachment ticket lasts 15 seconds
and permits one connection. Tickets travel in the first WebSocket message, never
in URLs or saved layouts. Exact origin and host checks apply.

Install the separate [native viewer runtime](viewer-runtime.md) with the source
installer or release package. FICC discovers its verified adjacent runtime.
Use `ficc serve --viewer-runtime /absolute/runtime/path` for an explicit selection.
The host checks the recorded platform and complete file inventory before use.
An invalid adjacent runtime disables displays and leaves the controller available.
An invalid explicit path refuses startup.

The host requires Bubblewrap,
a working systemd user manager and enforced resource limits. Missing requirements
refuse the display; no unrestricted mode is available.

Each display runs in private network, process and file namespaces. It receives no
home directory, controller database or management credentials. When required,
the host supplies only the selected display credential through a private channel.

Its limits are
512 MiB memory, no swap, 64 tasks, one assigned CPU and a 100 percent CPU quota.
At most four displays can be active. A connection closes after one hour, or after
30 minutes without user input. Unacknowledged output closes after 15 seconds.

The host validates native display instructions before browser rendering. Images
use lossless PNG. The maximum display size is 4096 by 2160 pixels. Limits also
apply to canvas storage, image streams, frame count and input/output rates. Slow
browsers apply backpressure to a three-frame window. A limit failure closes that
connection and leaves the workspace available.

Each binary message contains complete validated instructions, with at most
64 instructions and 64 KiB. Frame boundaries flush pending output. Current
identity, project, policy and module grants are checked before each delivery.
Other requests can run between deliveries, including permission revocation.

Clipboard, file transfer, console audio and microphone input are disabled. The
workspace audio service remains available to approved audio-player modules.
