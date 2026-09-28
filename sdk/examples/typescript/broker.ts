// SPDX-License-Identifier: Apache-2.0
import { serveBroker, type BrokerRequest, type Broker, type Result } from './ficc-module.mjs';
function resources(request: BrokerRequest, broker: Broker): Result[] {
  return request.action === 'read' ? broker('system.resources.read', request.targets, {})
    : request.targets.map(target => ({ target, error: { code: 'unsupported_action', message: 'Select the read action.' } }));
}
serveBroker(resources);
