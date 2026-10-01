// SPDX-License-Identifier: Apache-2.0
// Select an explicit disposable VM and preserve its module activation after display checks.
export function viewerFixture() {
  const provider = process.env.FICC_VIEWER_PROVIDER || 'libvirt';
  const fixture = {
    libvirt: { packageId: 'org.ficc.libvirt', panel: 'Libvirt VMs', machine: 'ficc-vm-a' },
    proxmox: { packageId: 'org.ficc.proxmox', panel: 'Proxmox VMs', machine: 'ficc-pve-a' },
    hyperv: { packageId: 'org.ficc.hyperv', panel: 'Hyper-V', packaged: true },
    virtualbox: { packageId: 'org.ficc.virtualbox', panel: 'VirtualBox', packaged: true },
  }[provider];
  if (!fixture) throw Error('The display fixture provider is unsupported.');
  const result = { ...fixture, provider,
    workspace: process.env.FICC_VIEWER_WORKSPACE || 'VM display qualification',
    panel: process.env.FICC_VIEWER_PANEL || fixture.panel,
    machine: process.env.FICC_VIEWER_MACHINE || fixture.machine,
    profile: process.env.FICC_VIEWER_PROFILE,
  };
  if (!result.machine || (fixture.packaged && !/^[a-f0-9]{32}$/.test(result.profile || ''))) {
    throw Error('Set the explicit disposable machine and provider profile for the packaged adapter.');
  }
  return result;
}

export async function activateViewerFixture(page, fixture) {
  return page.evaluate(async fixture => {
    const { request } = await import('/static/api.js');
    const { modules } = await request('/modules'), { workspaces } = await request('/workspaces');
    const matches = workspaces.filter(value => value.name === fixture.workspace);
    if (matches.length !== 1) throw Error('The explicit disposable viewer workspace is missing or ambiguous.');
    const workspace = matches[0];
    const instances = workspace.instances.filter(instance => modules.some(module =>
      module.digest === instance.digest && module.manifest.id === fixture.packageId));
    if (instances.length !== 1 || instances[0].targets.length !== 1) {
      throw Error('The explicit disposable viewer module is missing or ambiguous.');
    }
    const instance = instances[0], module = modules.find(value => value.digest === instance.digest);
    const original = { digest: module.digest, enabled: module.enabled, grants: module.grants, workspace: workspace.id };
    await request(`/modules/${module.digest}/activation`, { method: 'POST', body: { enabled: true, grants: [
      { capability: 'workspace:read', target_ids: [workspace.id] },
      { capability: 'vm:read', target_ids: instance.targets }, { capability: 'vm:console', target_ids: instance.targets },
    ] } });
    return original;
  }, fixture);
}

export async function restoreViewerFixture(page, original) {
  if (!original) return;
  await page.evaluate(async original => {
    const { request } = await import('/static/api.js');
    await request(`/modules/${original.digest}/activation`, { method: 'POST',
      body: { enabled: original.enabled, grants: original.grants } });
  }, original);
}
