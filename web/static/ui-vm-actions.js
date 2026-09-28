// SPDX-License-Identifier: Apache-2.0
// Select VM confirmation and history controls from the host lifecycle interface.
import { lifecycleActions } from './ui-lifecycle-actions.js';
export const vmActions = context => lifecycleActions(context, 'vms');
