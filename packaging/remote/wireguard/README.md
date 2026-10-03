# Private management network

This optional Linux profile connects a public management hub to approved machines.
WireGuard supplies encrypted IP routes. FICC retains its own identities, permissions,
SSH host verification and TLS verification. Contributor connections can use public
HTTPS without this network.

The network runs outside the controller and module sandbox. An installation
administrator manages its keys, routes, services and firewall. Ordinary modules
receive no network-administration privilege. Existing WireGuard, Headscale or
NetBird routes can serve the same purpose when their administrator approves them.

## Addresses and scope

Choose unused private addresses after checking every machine's existing routes,
containers and VPNs. Replace the following placeholders consistently in all files:

| Machine | Private address | Accepted peer addresses |
| --- | --- | --- |
| Management hub | `HUB_PRIVATE_IP/32` | Each approved machine's individual `/32` |
| Managed machine A | `NODE_A_PRIVATE_IP/32` | Hub `HUB_PRIVATE_IP/32` |
| Managed machine B | `NODE_B_PRIVATE_IP/32` | Hub `HUB_PRIVATE_IP/32` |

Each machine receives a distinct key. Replace `198.51.100.10` with the hub's
public IP address. No DNS record is required. Nodes initiate UDP connections;
the hub learns their authenticated endpoints. `PersistentKeepalive = 25` on a
node maintains its NAT mapping. It is a deployment choice, not a FICC timer.

The profile routes individual management addresses only. It does not change
the default route or DNS. It does not enable IP forwarding, NAT or peer-to-peer
routing. Do not add `0.0.0.0/0`, `::/0` or a whole LAN without reviewing that scope.
The hub is trusted with access to the permitted services on these machines.

Reference: [WireGuard setup and NAT behavior](https://www.wireguard.com/quickstart/).

## Prepare keys and configuration

Install the distribution's `wireguard-tools` package and a supported kernel.
Record the installed versions. Preserve the existing SSH connection during setup.
Use a separate interface name, such as `ficc-mgmt`, after checking it is unused.

Run the following in a root shell on each machine. It refuses to overwrite an
existing key. Keep the root shell's command tracing disabled.

```sh
install -d -o root -g root -m 700 /etc/wireguard
umask 077
set -C
wg genkey > /etc/wireguard/ficc-mgmt.key
wg pubkey < /etc/wireguard/ficc-mgmt.key > /etc/wireguard/ficc-mgmt.pub
set +C
```

Exchange only public keys through an authenticated administrative channel.
Verify each key and address before adding a peer. Retain the matching private
key on its own machine. Never put private keys in module grants or workspace data.

Complete [hub.conf.example](hub.conf.example) on the hub and
[node.conf.example](node.conf.example) on each managed machine. Set machine B's
address to `NODE_B_PRIVATE_IP/32`. Remove unused peer sections. Each placeholder must be
replaced before activation. Insert the local private key through a private editor
or a file-based administrative tool, without printing it in terminal output.

Install the completed file as `/etc/wireguard/ficc-mgmt.conf`, owned by `root:root`
with mode `0600`. These configurations contain credentials. Protect their backups.
Keep the files free of `PreUp`, `PostUp`, `PreDown` and `PostDown` commands unless
an administrator has separately reviewed those executable hooks.

`AllowedIPs` selects routes and acceptable source addresses for each peer.
Keep it limited to the addresses actually assigned to that peer. Avoid overlapping
peer assignments. See [wg configuration](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8).

## Firewall and activation

Allow UDP `51820` to the hub, limited to known source addresses when possible.
Allow outbound UDP from the managed machines. Preserve existing management rules.
Do not enable or replace a firewall policy without reviewing its current use.

Permit only required services on the tunnel interface. For SSH, permit the hub's
private `/32` to the managed machine's private address on TCP `22`. Keep database
ports closed until an explicit data connection needs them. Apply normal database
authentication and verified TLS even on the private route.

Do not enable forwarding between peers or into other networks for this profile.
If forwarding is already active for another purpose, deny forwarding through
`ficc-mgmt` in that machine's existing firewall policy.

The supplied [hub rules](hub.nft.example) and [node rules](node.nft.example)
provide a separate `inet ficc_mgmt` nftables table. They filter only this interface
and refuse forwarding in both directions. Complete the private addresses before
use. The node rules admit hub SSH and diagnostic ping; the hub admits ping and
responses to its own connections. Other existing firewall rules still apply.

Check that the table name is unused. Install the matching completed rules as
`/etc/ficc-network/ficc-mgmt.nft`, owned by root with mode `0600`. Validate with
`nft --check --file /etc/ficc-network/ficc-mgmt.nft`. Install
[ficc-private-network-firewall.service](ficc-private-network-firewall.service)
under `/etc/systemd/system/`, root-owned with mode `0644`. Install
[firewall.conf](firewall.conf) under
`/etc/systemd/system/wg-quick@ficc-mgmt.service.d/` with the same ownership and mode.
Run `systemctl daemon-reload`. The tunnel now requires the firewall service;
stopping that service also stops the tunnel. Do not flush the whole ruleset.

Start the hub, then each node:

```sh
systemctl start wg-quick@ficc-mgmt
systemctl is-active wg-quick@ficc-mgmt
wg show ficc-mgmt public-key
wg show ficc-mgmt peers
wg show ficc-mgmt latest-handshakes
wg show ficc-mgmt transfer
ip route show dev ficc-mgmt
```

These selected `wg show` fields contain no private keys. Do not publish output
from `wg showconf`, `wg show ... dump`, or `wg-quick strip`; they contain credentials.
Generate traffic to a permitted service and confirm a recent handshake and
increasing counters. Compare default routes and DNS with their previous values.
Verify that an unapproved peer cannot connect and that peers cannot reach each other.
Enable `wg-quick@ficc-mgmt` at boot only after these checks pass.

Reference: [wg-quick routes and configuration](https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8).

## Use from FICC

Complete the [OpenSSH profile example](ssh_config.example) for the controller
account. Select approved usernames and private identity files. Enroll each profile
through FICC's normal machine preview and independently verify the SSH host key.
[OpenSSH certificate trust](../../../docs/ssh-trust.md) is also supported.
The WireGuard public key does not replace the SSH host key or certificate principal.

Retain the configured HTTPS origin for browser and contributor connections.
Do not substitute a private IP unless its certificate also verifies that identity.
When a service name resolves over the tunnel, TLS still checks that service name.
Database connection grants must also identify the approved destination and project.

A lost tunnel makes these private routes unavailable. FICC must report the failed
connection and must not silently choose an unapproved public address. Blocked UDP
requires an approved alternative route; WireGuard supplies no TCP relay fallback.
The separate outbound contributor HTTPS/polling path can remain available.

## Rotation, removal and recovery

Generate replacement keys on their owning machines. Coordinate public-key changes
through the administrative channel. Retain private backups and the last reviewed
configuration until the new handshake and application checks pass.

Remove a revoked public key from the hub's persistent configuration and apply that
configuration. Also remove its active peer with `wg set ficc-mgmt peer PUBLIC_KEY remove`.
Confirm its handshakes and traffic stop. Revoke FICC identities and SSH access
separately when access is being removed. Restoring a network backup must not restore
revoked peers without a fresh administrative decision.

To stop and remove the interface and its routes:

```sh
systemctl disable --now wg-quick@ficc-mgmt
```

This retains keys and configuration. Remove only the firewall entries created
for this profile. Stop `ficc-private-network-firewall.service` to remove only its
`inet ficc_mgmt` table. Do not flush existing firewall rules or delete another network's
routes. Restart using the last reviewed configuration to recover service.
