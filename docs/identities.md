<p align="center"><a href="../README.md"><img src="../.github/assets/icon.svg" width="44" alt="FICC"></a></p>

# Identities and projects

[Contents](README.md) | [Security](../SECURITY.md) | [Local API](api.md)

The controller keeps durable user identities separate from expiring credentials.
Each credential selects one project. Workspaces, jobs, file operations and
transfers belong to that project. Terminals, saved panel arrangements and
window surfaces also belong to an individual user.

Local mode uses private, same-account sign-in. [Remote mode](remote-access.md)
adds approved external identities behind the supplied HTTPS gateway.
The Linux account that runs the controller remains trusted and can issue local
sign-in credentials for any enabled identity with project membership.

## Upgrade existing state

Stop the controller and [back up its state](backup.md) before upgrading.
Schema 7 adds the local owner and local project in one migration transaction.
Schema 8 adds project resource assignments and durable operation ownership.
Existing job, file, transfer and terminal records retain their contents and
belong to the local owner and local project, even if their credential expired.
Existing workspaces, layouts and credentials retain their IDs and contents.
They belong to the local owner and local project after migration.
Existing credential scopes and expiration times do not increase.
Older window surfaces can reference a view without a saved panel layout.
Those references retain their user's ownership without consuming extra saved-view capacity.

Use `ficc open` for a fresh owner session after the upgrade. Older credentials
do not automatically receive the new `identities:manage` capability.
Version 0.2.5 uses schema 15, including signed policy packages, external identity
approvals, contributors, data sources and inspection records. An older
controller cannot open this schema. Keep the pre-upgrade backup for rollback;
do not change the schema marker to bypass this check.

## Create identities and projects

Open **Access** in the owner console. Create a user identity and a project.
Under **Project membership**, select both and grant explicit capabilities.
New identities have no membership and cannot sign in until access is granted.
The local recovery owner retains installation administration and cannot be disabled.

| Capability | Permitted use |
| --- | --- |
| `workspaces:read` | Read shared workspace contents and the user's own saved layouts. |
| `workspaces:write` | Create, change and delete project workspaces; save private layouts. |
| `modules:read` | List enabled packages and usable grants within the selected project. |
| `modules:execute` | Invoke installed panel actions with current project, resource, package and sandbox checks. |
| `audio:playback` | Use workspace audio leases and the user's sound preferences. |
| `nodes:read`, `resources:read` | Read assigned machines and their resource measurements. |
| `observations:read` | Release limited machine inventory through the agent observation interface, within current machine assignments and credential limits. |
| `observations:resources` | Release saved resource readings for a permitted machine; also requires `observations:read`. |
| `jobs:read`, `jobs:logs` | Read project jobs and logs on permitted machines. |
| `jobs:execute`, `jobs:cancel` | Submit managed jobs or cancel permitted project jobs. |
| `files:read`, `files:write`, `files:delete`, `files:mode` | Use the selected actions within assigned registered folders. |
| `terminals:read`, `terminals:execute`, `terminals:stop` | Read, open or stop the user's private project terminals. |
| `vm:read` | Read VM inventory and panel operation records on assigned systems. |
| `vm:console` | Open interactive VM display and input on assigned systems. |
| `vm:power` | Preview and confirm VM start or graceful shutdown on assigned systems. |
| `container:read`, `container:logs`, `container:power` | Inspect workloads, read logs or confirm lifecycle actions on assigned systems. |
| `admin:read`, `admin:logs`, `admin:services`, `admin:power` | Inspect systems, read journals or confirm service and system power actions. |

These are the implemented project capability boundaries. Grant the capabilities
needed by a workflow. Machine enrollment, provider administration, coding agents,
the bus, packages and identities remain local-owner operations. Project members
cannot obtain those capabilities by submitting scope names or editing a workspace.
External identity providers require separate installation and identity approval.
Runtime policy packages can further restrict each granted action and resource.

Members share workspace contents within a project. Do not grant membership in a
project that contains notes or panels the user must not read. Separate projects
have separate workspace lists and object access, including requests made with
known workspace IDs. A shared project does not share private layout records.

The owner can install and grant packages through **Manage modules**.
Select the intended project before arranging its panels. All installed packages
remain under owner administration; project members cannot install executable code.
The module target catalog lists permitted workspaces, systems and folders only.

## Use installed system panels

The owner first registers the system and its provider connection. Assign that
system to the project and grant the member the required scopes. Select the
project, then enable the package with grants for its workspace and exact systems.
Folder panels also need grants and project assignments for their registered roots.

The member opens **Workspace**, selects an enabled module and chooses its targets.
Changing panel targets needs `workspaces:write`. Invocation needs `modules:execute`
and `workspaces:read`, plus each action's resource scopes. System actions also
need `nodes:read`. Resource panels map `system:read` to `resources:read`.
Optional console, write or power actions require their own current grants.
An installed package or saved panel cannot supply missing member permissions.

With the supplied managed policy active, assign an explicit `vm-observer`,
`vm-operator`, `container-operator` or `system-operator` role as needed.
These roles restrict existing host grants. Existing observer and operator roles
do not acquire new VM, container or system administration rights automatically.
The VM observer can inspect inventory; interactive consoles require VM operator
rights and an explicit `vm:console` membership scope. See [policy roles](policies.md).

Project VM operations support the built-in libvirt and Proxmox connections.
Full-account provider adapters remain installation-owner operations, including
their inventory and consoles. They require `providers:write` and the installed
adapter's exact `provider:admin` package grant. Project membership cannot supply
either installation permission. Project members cannot edit profiles or credentials.

Retained VM, container and administration receipts stay bound to the project's
workspace, globally unique panel, package digest and selected targets. Receipt
retention prevents panel removal or retargeting until the receipt is removed.
Members with current grants can inspect shared project receipts after signing
in again. Another project cannot inspect them, including on a shared system.
Revocation preserves the recorded outcome and denies further access or dispatch.

Viewer references belong to the issuing credential and retain the invocation's
current checks. Permission, resource, package or panel changes deny attachment
and close checked display streams. A viewer ticket does not freeze old authority.
Accepted power requests can already have effects when access is revoked; their
retained outcome must be inspected through an authorized recovery workflow.

## Assign project resources

Under **Project resources**, select the project, its registered machines and its
registered folders. A remote folder also requires its machine assignment. Save
the selection. New projects have no assigned resources. The local recovery owner
retains installation access; other identities require current project assignments.

Effective access is the intersection of membership capabilities, project resource
assignments and the credential's original limits. A folder's read-only registration
also applies. Project changes never widen a credential's machine or folder limit.

Job execution and terminals use the full authority of the remote account. They
can bypass registered-folder limits through commands run by that account. Grant
these capabilities only to users trusted with that account's authority. They are
not restricted job templates or contributor workloads.

Project members with the necessary scopes and machine/folder access share job,
file-operation and transfer receipts. Another project cannot read or change those
receipts even when it has access to the same machine or folder. Terminal access
requires the creating identity in the same project. The local recovery owner can
manage terminals after selecting their project. Ownership remains after a
credential expires or is removed; renewed credentials use current permissions.

Removing a resource assignment prevents subsequent access, queued dispatch and
checked file chunks or terminal frames. An already dispatched job may continue
on its remote account. Revocation does not promise to stop that process; use an
authorized cancellation or the remote account's administration controls.

## Use the command line

The private local control socket supports the same administration operations:

```sh
ficc identity-create --label "Operations user"
ficc project-create --label "Operations"
ficc identity-list
ficc project-list
ficc project-member-set --project PROJECT_ID --subject USER_ID --revision 0 \
  --scope workspaces:read --scope workspaces:write --scope modules:read \
  --scope modules:execute --scope audio:playback
ficc project-members --project PROJECT_ID
ficc project-resources-set --project PROJECT_ID --revision 0 --node NODE_ID --root ROOT_ID
ficc project-resources --project PROJECT_ID
ficc open --subject USER_ID --project PROJECT_ID
```

Replace the ID placeholders with the IDs returned by the preceding commands.
Use the returned membership revision for later edits. Omit every `--scope` option
to remove access and revoke that member's credentials for the selected project.
Revision checks reject changes made from an outdated membership or resource form.
Resource commands replace the complete selection. Omit all `--node` and `--root`
options to remove every resource assignment. Register folders with `ficc root-add`.

`token-create` accepts `--subject` and `--project`, in addition to its existing
label, scope, lifetime and private output-file arguments. Tokens cannot switch
projects. Their effective scopes are the intersection of the credential's
original grant and current membership. Bearer and bootstrap secrets are stored only as hashes.

Use `identity-update ID --label LABEL --revision REVISION --disabled` to disable
an identity. `project-update` uses the same options. Omit `--disabled` to enable
the record again. Re-enabling does not revive revoked credentials.

## Switch projects and revoke access

The **Current project** selector changes the browser session's project. Save or
discard workspace drafts first. Switching rotates the credential and CSRF value
without extending the original expiry. Local delegated sessions retain their
scope ceiling; external sessions use the selected project's current grants.
The browser starts a
new layout in the selected project.

Cookies are shared between windows in one browser profile. Another open window
keeps its original project and session headers. The controller rejects its
requests after a switch; open a new console window to continue. Use separate
browser profiles or contexts for simultaneous logins as different users.

The controller checks membership and enabled state on every credential resolution,
including queued action checks. Clearing membership or disabling an identity or
project revokes the affected credentials. Sound leases lose authority on their
next checked heartbeat. This does not erase shared workspace data.
Member project switches and sign-outs preserve the owner's SSH observation connections.
Revoking an owner credential resets connections within that credential's machine selection.

## Recovery and limits

Backups include identities, projects, memberships, resource assignments and
workspace, operation and private layout ownership. Restore removes all credentials and disables every non-owner
identity. The owner must review memberships and re-enable users before issuing
new sign-in credentials. Restored executable package grants remain revoked.

The controller currently retains at most 256 identities, 256 projects,
4,096 memberships, 512 active credentials, 64 workspaces, 256 views and 64 surfaces.
These are installation-wide limits. A member can consume shared workspace
capacity; project resource quotas are not implemented. Read-only members can
arrange panels temporarily, but saving geometry requires `workspaces:write`.

Project boundaries do not isolate processes that run as the controller's Linux
account. Database files and backups rely on the existing private state directory
and filesystem protections. [SQLite and PostgreSQL state](state-storage.md) use the same access contract.
External sign-in requires separate [remote access configuration](remote-access.md).

[Runtime policy packages](policies.md) further restrict current grants and
provide role-based effective-access previews.

[Return to the documentation contents](README.md)
