// SPDX-License-Identifier: Apache-2.0
// Bind explicit workload actions to the displayed record and its revision.
import { allowed, getSession } from './api.js';
import { button, confirmation, details, el, notice, panel, time } from './components.js';
import { terminal, words } from './workloads-model.js';
import { workloadOutput } from './workloads-output.js';

export function workloadDetail(send, received, valid) {
  let output, binding, active = true, previous = '';
  const body = el('div'), retained = el('div');
  const element = panel('Workload detail', [body, retained]);
  function action(job, operation, title, description, label, extra = {}) {
    confirmation(title, description, label, async () => {
      if (!active || !valid()) throw new Error('This workload view is no longer active.');
      const result = await send(`/workloads/${job.id}/${operation}`, { method: 'POST', body: { revision: job.revision, ...extra } });
      if (active && valid()) received(operation === 'remove' ? null : result);
    });
  }
  function update(job, enabled = true) {
    const current = JSON.stringify([job, enabled]);
    if (current === previous) return;
    previous = current;
    const disclosure = body.querySelector('details')?.open;
    const attempt = job.attempt, complete = terminal.has(job.state) || job.state === 'unknown';
    const released = !attempt || attempt.state === 'released';
    const actions = [];
    if (allowed('jobs:cancel') && !complete && !job.cancelled) actions.push(button('Cancel workload', () => action(job, 'cancel',
      `Cancel ${job.request.job.name}?`, 'Request cancellation and stop renewing this workload. The executor must confirm cleanup; retained output is kept until you release it.', 'Confirm cancellation'), { disabled: !enabled }));
    if (allowed('jobs:cancel') && complete && attempt && !released && attempt.state !== 'abandoned') actions.push(button('Release retained output', () => action(job, 'release',
      'Delete retained output?', 'This permanently deletes all retained output for this attempt and releases its reserved storage. Publish complete output to registered storage first. This browser preview is not a full artifact download. Active publications must finish or be cancelled before release.',
      'Delete output and release'), { class: 'danger-text', disabled: !enabled || !attempt.observed?.cleanup_confirmed }));
    if (allowed('jobs:cancel') && allowed('contributors:manage') && job.state === 'unknown' && attempt &&
        !['released', 'abandoned'].includes(attempt.state)) actions.push(button('Abandon retired attempt', () => action(job, 'abandon',
      'Abandon this retired attempt?', 'First revoke the contributor identity. Abandoning frees controller queue accounting only. Effects and cleanup remain unresolved, local storage cannot be reclaimed here, and this attempt cannot be retried. Inspect the retired machine separately.',
      'Acknowledge and abandon', { acknowledge_unknown: true }), { class: 'danger-text', disabled: !enabled }));
    if (allowed('jobs:execute') && job.subject_id === getSession()?.principal.subject_id && complete) actions.push(button('Retry workload', () => {
      const uncertain = job.state === 'unknown', acknowledge = el('input', { type: 'checkbox' });
      confirmation(`Retry ${job.request.job.name}?`, el('span', {},
        'Run the same immutable request as a new attempt using current authority. A new execution can repeat external effects from the earlier attempt.',
        uncertain ? el('label', { class: 'check-label' }, acknowledge, 'I understand that the previous outcome is unknown and that retry can repeat effects.') : null),
      'Confirm retry', async () => {
        if (uncertain && !acknowledge.checked) throw new Error('Acknowledge the unknown outcome before retrying.');
        if (!active || !valid()) throw new Error('This workload view is no longer active.');
        const result = await send(`/workloads/${job.id}/retry`, { method: 'POST',
          body: { revision: job.revision, acknowledge_unknown: uncertain && acknowledge.checked } });
        if (active && valid()) received(result);
      });
    }, { disabled: !enabled || !released }));
    const removable = terminal.has(job.state) && released || job.state === 'unknown' && ['released', 'abandoned'].includes(attempt?.state);
    if (allowed('jobs:cancel') && removable) actions.push(button('Remove record', () => action(job, 'remove',
      'Remove workload record?', job.state === 'unknown'
        ? 'Remove this record from the project. Its execution outcome remains unknown. Removing the record does not confirm effects or clean up an abandoned machine.'
        : 'Remove the completed workload and its released attempt records from this project.', 'Remove workload record'), { disabled: !enabled }));
    body.replaceChildren(el('div', {}, el('h3', {}, job.request.job.name),
      job.state === 'unknown' ? notice('Execution outcome is unknown. Inspect the contributor and its retained result before deciding to release or retry.', 'error') : null,
      job.cancelled && !complete ? notice('Cancellation requested. Waiting for executor cleanup confirmation.') : null,
      details([['Workload', job.id], ['State', words(job.state)], ['Pending / result reason', words(job.reason)],
        ['Generation / revision', `${job.generation} / ${job.revision}`], ['Submitted', time(job.created_at)], ['Updated', time(job.updated_at)],
        ['Candidate contributors', job.request.node_ids.join(', ')], ['Attempt', attempt?.id || 'Not assigned'],
        ['Assigned node', attempt?.node_id || 'Not assigned'], ['Attempt state', words(attempt?.state || 'not_assigned')],
        ['Lease expires', attempt ? time(attempt.lease_expires_at) : 'Not assigned'],
        ...(job.request.dataset ? [['Input dataset', job.request.dataset.id], ['Input staging', attempt?.input_progress
          ? `${attempt.input_progress.received_bytes} / ${attempt.input_progress.total_bytes} bytes via controller relay`
          : 'Waiting for the contributor receipt']] : []),
        ['Exit code', attempt?.outcome?.exit_code ?? attempt?.observed?.exit_code ?? 'Not reported'],
        ['Cleanup', attempt?.observed?.cleanup_confirmed ? 'Confirmed' : 'Not confirmed']]),
      el('div', { class: 'actions' }, actions),
      complete && !released ? el('p', { class: 'muted' }, 'Retry is available after cleanup is confirmed and retained output has been released. Only the original submitter can retry.') : null,
      el('details', { open: disclosure }, el('summary', {}, 'Submitted request'),
        el('pre', { class: 'job-request' }, JSON.stringify(job.request, null, 2)))));
    const next = enabled && attempt && attempt.state !== 'abandoned' && (attempt.observed || attempt.outcome) ? `${job.id}:${attempt.id}` : null;
    if (binding !== next) {
      output?.dispose(); output = null; binding = next;
      if (next) output = workloadOutput(job, send, () => active && valid());
      retained.replaceChildren(...(output ? [output.element] : [el('p', { class: 'muted' },
        !enabled ? 'Refresh the workload before reading output.' : attempt?.state === 'abandoned' ? 'The retired attempt remains unresolved. Local output and cleanup are unknown.' :
          attempt?.state === 'released' ? 'Retained output was released and is no longer available.' : 'Output is available after an attempt has been observed.')]));
    }
    output?.update(job);
  }
  return { element, update, dispose() { active = false; output?.dispose(); body.replaceChildren(); retained.replaceChildren(); } };
}
