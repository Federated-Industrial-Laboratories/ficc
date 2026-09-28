// SPDX-License-Identifier: Apache-2.0
// Keep each stereo output block below full scale with shared channel gain.
class PeakProcessor extends AudioWorkletProcessor {
  constructor() { super(); this.gain = 1; }
  process(inputs, outputs) {
    const input = inputs[0], output = outputs[0];
    let peak = 0, valid = true;
    for (const channel of input) for (const value of channel) {
      if (!Number.isFinite(value)) valid = false;
      else peak = Math.max(peak, Math.abs(value));
    }
    const limit = valid ? Math.min(1, .98 / Math.max(.98, peak)) : 0;
    const frames = output[0]?.length || 0;
    this.gain = Math.min(limit, this.gain + frames / (sampleRate * .1));
    for (let index = 0; index < output.length; index++) {
      const source = input[index], destination = output[index];
      for (let frame = 0; frame < destination.length; frame++) {
        destination[frame] = valid && source ? source[frame] * this.gain : 0;
      }
    }
    return true;
  }
}
registerProcessor('ficc-peak', PeakProcessor);
