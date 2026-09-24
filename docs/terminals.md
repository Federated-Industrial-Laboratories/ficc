# Interactive terminals

Terminals opens one SSH target at a time. The node, remote account and session
state stay visible outside terminal output. Opening a shell requires explicit
execution confirmation and the terminals:execute grant for that node. This is
full remote-account access, including paths outside registered file roots.

Ephemeral shell starts an OpenSSH session with a PTY. Closing its attachment
closes SSH; it cannot be reattached. Programs that deliberately detach may
continue remotely. Use managed jobs for recorded limits, output and results.

Tmux session starts an exact named session in a separate FICC tmux namespace.
Detach closes the view while tmux may continue. Attach uses a new ticket and
does not replay input. Stop session is a separate confirmed operation that
addresses only that recorded session. A missing session is never recreated by
Attach. Remote logout and reboot policy still governs persistence; FICC does
not enable account lingering automatically.

If creation or stopping has an uncertain outcome, Check recorded session queries
that exact remote identity. An existing session becomes available to reattach;
a missing session becomes closed. This check does not create a replacement.

## Keyboard and output

Focus terminal explicitly before typing. Ctrl+Shift+Escape returns focus to
the toolbar. Only one input target is mounted. Disconnected input is refused
and never queued for reconnection. Resize follows the terminal pane within
2-300 columns and 2-120 rows. Scrollback retains 2,000 rows in the browser.

Output is untrusted. Local xterm.js assets interpret it in the terminal well.
Remote data cannot automatically change the page title, follow links or write
the clipboard. Normal deliberate selection and copy remain available.
Raw keystrokes and terminal output are not written to FICC audit logs.

SSH starts with normal terminal line discipline: Enter completes line input,
newlines return to column one, and Ctrl+C interrupts the foreground program.
Interactive applications can select their own raw mode for binary input.
FICC transports terminal bytes without adding newline conversions.

The service pauses output reads after 256 KiB is awaiting browser processing.
The browser acknowledges bytes after xterm finishes processing them. An
unresponsive reader closes after 30 seconds with an output-gap notice. Input
frames are at most 16 KiB. Idle attachments close after 30 minutes without input.
A closed view does not promise recovery of the previous scrollback.

## Credentials and limits

terminals:read lists sessions; terminals:execute creates and attaches;
terminals:stop permits the confirmed stop action. Each scope also checks node
restrictions. Expiry or revocation closes an active attachment. For tmux this
detaches the client; it does not silently destroy a persistent remote session.

Attachment tickets are single-use and expire after 30 seconds. They travel in
the first WebSocket frame, never in its URL. The service requires the exact
local Host and Origin and checks current permission throughout the connection.

At most 16 sessions can be active, with four per node and 512 retained records.
The controller keeps durable creation identities and refuses conflicting request
keys. On restart, ephemeral records become interrupted; tmux sessions can be
explicitly attached again if the remote session still exists.
