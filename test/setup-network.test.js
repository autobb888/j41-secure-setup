import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildRulePlan, EGRESS_PROXY_PORT } from '../lib/setup-network.js';

test('EGRESS_PROXY_PORT is 9847 (matches dispatcher)', () => assert.equal(EGRESS_PROXY_PORT, 9847));

test('rule plan: proxy-only egress — no :443 allowlist, no :53, INPUT allows only proxy port', () => {
  const plan = buildRulePlan({ bridgeIf: 'br-j41iso', gatewayIp: '172.18.0.1', proxyPort: 9847 });
  const flat = plan.map(a => a.join(' '));
  // default-deny egress from the bridge (FORWARD via our chain)
  assert.ok(flat.some(r => /J41_AGENT_OUT.*ESTABLISHED,RELATED.*ACCEPT/.test(r)), 'established accept');
  assert.ok(flat.some(r => /J41_AGENT_OUT.*-j DROP/.test(r)), 'default drop');
  // no per-host :443 accepts, no :53 accepts
  assert.ok(!flat.some(r => /dpt?:?53|--dport 53/.test(r)), 'no DNS rule');
  assert.ok(!flat.some(r => /--dport 443/.test(r)), 'no per-host 443 rule');
  // INPUT: allow bridge -> gateway:proxyPort, then drop other bridge INPUT
  assert.ok(flat.some(r => /INPUT.*-i br-j41iso.*-d 172\.18\.0\.1.*--dport 9847.*ACCEPT/.test(r)), 'proxy allow');
  assert.ok(flat.some(r => /INPUT.*-i br-j41iso.*-j DROP/.test(r)), 'input default drop');
});
