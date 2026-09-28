// SPDX-License-Identifier: Apache-2.0
export type Request = {
  version: 1; type: 'invoke'; id: string; action: string;
  targets: string[]; parameters: Record<string, unknown>;
};
export type Result = { target: string; data: unknown } |
  { target: string; error: { code: string; message: string } };
export function serve(handler: (request: Request) => Result[]): void;
export type BrokerRequest = Omit<Request, 'version'> & { version: 2 };
export type Broker = (primitive: string, targets: string[], parameters?: Record<string, unknown>) => Result[];
export function serveBroker(handler: (request: BrokerRequest, broker: Broker) => Result[]): void;
