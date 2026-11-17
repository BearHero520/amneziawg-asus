'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class Control {
 constructor() { this.children = []; this.value = ''; this.attributes = {}; }
 set textContent(value) { this.text = value; this.children = []; }
 get textContent() { return this.text || ''; }
 appendChild(control) { this.children.push(control); }
 get options() { return this.children; }
 setAttribute(name, value) { this.attributes[name] = value; }
}

const els = new Map();
const awgEl = (id) => {
 if (!els.has(id)) els.set(id, new Control());
 return els.get(id);
};
let request;
const context = {
 document: {createElement: () => new Control(), querySelectorAll: () => []},
 awgDirty: false, awgEl, awgBusy: false, awgButtons() {}, awgMessage() {},
 awgRequest: (action, data) => { request = [action, JSON.parse(data.amneziawg_payload)]; }
};
const plugin = path.join(__dirname, '..', 'plugin');
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(plugin, 'res', 'amneziawg-routing.js'), 'utf8'), context);
awgEl('awg_mode').value = 'policy';
context.awgPolicyRender({settings: {routing: {}}});
assert.equal(awgEl('awg_policy').hidden, false);
context.awgPolicyAddRule();
context.awgPolicyAddDevice();
const row = awgEl('awg_policy_devices').children[0];
const source = row.children[0].children[0];
source.value = '192.168.50.21';
source.oninput();
const policy = row.children[1].children[0];
policy.value = 'vpn_geo_1';
policy.onchange();
const payload = JSON.parse(JSON.stringify(context.awgPolicyRead()));
assert.deepEqual(payload.devices, [{source: '192.168.50.21', policy: 'vpn_geo_1'}]);
assert.equal(payload.rules[0].mode, 'include');
context.awgPolicyRender({settings: {routing: {dns: 'router'}}});
assert.equal(context.awgPolicyRead().devices[0].source, '192.168.50.21', 'status refresh erased draft');
awgEl('awg_traffic_device').value = '192.168.50.21';
context.awgTrafficStart();
assert.deepEqual(request, ['traffic-start', {device: '192.168.50.21'}]);
awgEl('awg_traffic_rule').value = 'vpn_geo_1';
context.awgTrafficRender({active: false, entries: [{name: '<img onerror=evil()>', ip: '203.0.113.3'}, {name: 'www.example.test', ip: '203.0.113.4'}]});
const traffic = awgEl('awg_traffic_rows').children;
assert.equal(traffic[1].children[1].textContent, '<img onerror=evil()> / 203.0.113.3');
traffic[0].children[4].children[0].onclick();
assert.equal(context.awgPolicyRead().rules[0].domains, 'www.example.test');
const html = fs.readFileSync(path.join(plugin, 'webs', 'Module_amneziawg.asp'), 'utf8');
assert(html.includes('接入设备'));
assert(!html.includes('Module_amneziawg_advanced'));
for (const id of els.keys()) assert(html.includes('id="' + id + '"'), 'missing ' + id);
console.log('PASS unified settings, device rule drafts, traffic capture and safe rendering');
