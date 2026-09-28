// SPDX-License-Identifier: Apache-2.0
import { serveBroker } from './ficc-module.mjs';
serveBroker((request, broker) => request.action === 'read'
  ? broker('system.resources.read', request.targets, {})
  : request.targets.map(target => ({ target, error: { code: 'unsupported_action', message: 'Select the read action.' } })));
