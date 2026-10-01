# Optional system power policy

FICC does not collect sudo passwords or install system policy automatically.
An administrator can assign normal reboot and poweroff authority to an SSH account.
The supplied rule is optional. It requires systemd-logind and polkit.

The rule grants every member of `ficc-power` these operations, including when other users are signed in.
This authority applies outside FICC too. Use a dedicated account where practical.
It grants no service changes, arbitrary commands or inhibitor bypass.
FICC still requires its own module grants and an explicit action confirmation.

Inspect [the rule](ficc-power.rules) before installation. Run these commands on
the managed system as its administrator. Replace `operator` with its approved SSH account.
Check that the group name does not already have another purpose.

```sh
sudo groupadd --system ficc-power
sudo usermod --append --groups ficc-power operator
sudo install -o root -g root -m 0644 ficc-power.rules /etc/polkit-1/rules.d/49-ficc-power.rules
```

Keep an existing administrator session available. Open a new SSH connection for
the selected account so its supplementary groups are current. Reconnect the
FICC node, then refresh System administration. Install the current node helper
if the Power permission column remains Unknown.

These read-only checks do not shut down the system:

```sh
busctl --system call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanPowerOff
busctl --system call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager CanReboot
```

`yes` means current account policy permits the operation without authentication.
`challenge` requires authentication. `no` denies it; `na` means unsupported.
Inhibitors and account policy can change after this check. FICC checks again
before dispatch and reports acknowledgement separately from completion.

To remove this grant, remove the rule and group membership on that system:

```sh
sudo rm /etc/polkit-1/rules.d/49-ficc-power.rules
sudo gpasswd --delete operator ficc-power
```

Do not remove unrelated rules. Inspect the current power permission after rollback;
other system policy can grant the same operations independently.
