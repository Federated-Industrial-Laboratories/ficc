// SPDX-License-Identifier: Apache-2.0
// Describe the declared provider consistency without promising an unavailable lock.
export const consistencyName = value => ({
  'provider-lock': 'Provider lock',
  'checked-before-dispatch': 'Checked before dispatch',
})[value] || 'Unavailable';

export const checkedBeforeDispatch = 'FICC checks VM identity and state before dispatch. Another administrator can change the VM between that check and the provider action.';
