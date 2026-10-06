# Runtime access policies

Policy packages restrict existing identity, project and resource grants. They
cannot grant a missing permission or override private operation ownership.
Ordinary workspace modules cannot install providers or change publisher trust.
Before first activation, host grants apply. After activation, policy enforcement
remains required. Missing, malformed, stale or unavailable decisions deny access.

## Configure and install

Install the separate [OPA provider](../policy-providers/opa/README.md) into the
controller's Python environment. It requires a trusted static OPA 1.21.1 binary,
Bubblewrap and systemd user resource controls. There is no unconfined fallback.
Verify the binary against its official release digest. Stop the controller,
then configure the evaluator with the verified 64-character digest:

```sh
ficc policy-provider-configure --provider opa --binary /opt/opa/opa \
  --sha256 VERIFIED_SHA256 --state-dir /home/operator/.local/state/ficc
```

Start the controller with the same state directory. This does not activate a
policy. Open **Access** as the local owner. Under **Trusted policy publishers**,
enter the publisher identifier and Ed25519 public key. Verify that key through
a trusted channel before confirming trust. Use a new identifier for key rotation;
an existing identifier cannot receive a different key.

Select an archive under **Policy enforcement**, then choose **Install policy
package**. Inspect its publisher, digest, roles and signed payload hashes.
Installation alone does not change permissions. Equivalent CLI commands are:

```sh
ficc policy-trust --publisher organisation-policy --public-key publisher.pub
ficc policy-install ./managed.ficcpolicy
ficc policy-list
ficc policy-install https://packages.example.com/policies/managed.ficcpolicy
```

Remote installation requires verified HTTPS. Redirects and URLs containing
credentials are refused. A URL does not establish publisher trust.

## Roles, previews and activation

Under **Policy role assignments**, select a project and an existing member,
choose roles, then save. Roles never replace project membership. Unknown roles
give no permissions in the supplied presets. Removing every role denies member
access after activation.

**Effective access preview** compares host grants, the policy decision and their
intersection. Check **Preview the selected package** to evaluate a candidate
without activation. A preview for another identity uses its membership ceiling;
an issued credential can be narrower. Only the local owner can preview another
identity or an inactive package.
Preview workers are separate from active enforcement and have bounded admission.
An oversized preview is rejected without disabling the active policy.

```sh
ficc policy-bind --project PROJECT_ID --subject USER_ID --role observer --revision 0
ficc policy-preview --project PROJECT_ID --subject USER_ID \
  --digest PACKAGE_SHA256 --action workspaces:write
ficc policy-activate PACKAGE_SHA256 --revision CURRENT_REVISION
ficc policy-roles --project PROJECT_ID
```

**Activate selected policy** verifies and prepares the candidate before changing
the active digest and revision. Failed preparation preserves the previous policy.
Stale revisions reject changes. **Roll back policy** activates the previous
verified digest at a new revision.

Role changes apply at checked admission and delivery boundaries. Queued jobs
are checked again before dispatch. Terminal output is checked after reading and
before browser delivery; denied sessions close. Revoking a role does not claim
that an already running remote command has stopped. Contributor termination
requires the separate executor and lease mechanism.

## Revocation and recovery

Disabling the active publisher stops its evaluator and denies ordinary access.
Re-enabling trust alone does not resume access: verify and activate the package
again. Evaluator failure also requires explicit activation. The unrestricted
local owner retains policy administration endpoints and CLI recovery. This
recovery path does not permit ordinary operations denied by the active policy.
Protect access to the controller's operating-system account.

Publisher, install, role and activation changes generate audit events. The controller
records each security change in the same transaction as its audit event. If old
process cleanup fails afterward, the change stays committed, access is denied
and a separate cleanup failure is recorded. Inspect the saved state before retrying.
Backups
preserve exact archives, publishers, role bindings and activation history.
Restore disables publishers, clears the active digest and removes provider
configuration. Required enforcement remains required. Review the restored state,
configure an evaluator, restore trust and activate before resuming member access.

## Presets and limits

The supplied presets include `agent-observer` for the
[agent observation interface](agent-observations.md). It permits
`observations:read` and `observations:resources` within existing host grants.
Assign it explicitly after approving disclosure to the receiving agent.
Other roles and older credentials do not gain observation disclosure permission.

| Package | Role | Purpose within host grants |
| --- | --- | --- |
| Managed | Observer | Read assigned machines, files, workspaces and operation records |
| Managed | Managed operator | Use managed jobs, terminals, files and workspaces |
| Managed | VM observer (`vm-observer`) | Read VM inventory and project panel records; no console or power actions |
| Managed | VM operator (`vm-operator`) | Inspect VMs, open interactive consoles and confirm VM power actions |
| Managed | Container operator (`container-operator`) | Inspect workloads and logs, and confirm container lifecycle actions |
| Managed | System operator (`system-operator`) | Inspect systems and journals, and confirm service or system power actions |
| Contribution | Observer | Read assigned machines, workspaces and job records |
| Contribution | Contributor | Prepare assigned project files and workspaces |

Both presets preserve the local owner's granted capabilities. Managed shell
and job access has full authority of the remote account. The contribution preset
does not grant managed shell or job execution, or enable compute admission
without a qualified contributor executor and lease.

The VM, container and system roles are separate opt-in assignments. Existing
roles retain their previous rights. Each action still needs explicit membership
scopes, project resource assignments and current package grants. None of these
roles permits package installation, profile changes or full-account provider
adapters. VM console access is interactive and is excluded from VM observer.

Preset sources live in `policy-packs/`; packages install after build.
[Policy authoring](../sdk/policies.md) describes signing and the decision API.
Archives have limits of 512 KiB compressed, 8 MiB expanded and 64 payload files.
The store supports 64 publishers, 64 packages and 4,096 role bindings. These
control-plane limits are not workload data-size limits.

[Return to the documentation contents](README.md)
