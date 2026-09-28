// SPDX-License-Identifier: Apache-2.0
import { serve } from './ficc-module.mjs';

serve(request => request.targets.map((target, index) => {
  if (request.action !== 'echo' || typeof request.parameters.message !== 'string') {
    return { target, error: { code: 'unsupported_action',
      message: 'Select the echo action and supply a message.' } };
  }
  return { target, data: { message: request.parameters.message, index } };
}));
