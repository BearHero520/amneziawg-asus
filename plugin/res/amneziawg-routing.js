/* SPDX-License-Identifier: MIT */
var awgPolicyRules = [];
var awgPolicyDevices = [];
var awgPolicySignature = '';
var awgTraffic = null;

function awgPolicyOption(select, value, title) {
 var option = document.createElement('option');
 option.value = value;
 option.textContent = title;
 select.appendChild(option);
}

function awgPolicyOptions(select, value, includeBasics) {
 select.textContent = '';
 if (includeBasics) {
  awgPolicyOption(select, 'direct', '沿用路由器出口');
  awgPolicyOption(select, 'vpn_all', '全部走客户端隧道');
 }
 awgPolicyRules.forEach(function (rule) {
  awgPolicyOption(select, 'vpn_geo_' + rule.id, rule.name || '分流规则');
 });
 if (value) select.value = value;
 if (select.selectedIndex < 0 && select.options.length) select.selectedIndex = 0;
}

function awgPolicyChoices() {
 var defaults = awgEl('awg_policy_default');
 var report = awgEl('awg_traffic_rule');
 awgPolicyOptions(defaults, defaults.value, true);
 awgPolicyOptions(report, report.value, false);
 awgPolicyDrawDevices();
}

function awgPolicyControl(tag, value, onInput) {
 var control = document.createElement(tag);
 control.setAttribute('data-policy-edit', '');
 control.value = value || '';
 if (onInput) control.oninput = function () {
  onInput(control.value);
  awgDirty = true;
 };
 return control;
}

function awgPolicyButton(title, action) {
 var button = awgPolicyControl('button');
 button.type = 'button';
 button.textContent = title;
 button.onclick = action;
 return button;
}

function awgPolicyCell(row, child) {
 var cell = document.createElement('td');
 if (typeof child === 'string') cell.textContent = child;
 else cell.appendChild(child);
 row.appendChild(cell);
}

function awgPolicyDrawDevices() {
 var body = awgEl('awg_policy_devices');
 body.textContent = '';
 awgPolicyDevices.forEach(function (device, i) {
  var row = document.createElement('tr');
  var source = awgPolicyControl('input', device.source, function (value) { device.source = value; });
  source.placeholder = '192.168.50.100';
  source.setAttribute('aria-label', '设备 IPv4 或 MAC 地址');
  awgPolicyCell(row, source);
  var select = awgPolicyControl('select');
  select.setAttribute('aria-label', '设备流量去向');
  awgPolicyOptions(select, device.policy, true);
  select.onchange = function () { device.policy = select.value; awgDirty = true; };
  awgPolicyCell(row, select);
  awgPolicyCell(row, awgPolicyButton('移除', function () {
   awgPolicyDevices.splice(i, 1);
   awgDirty = true;
   awgPolicyDrawDevices();
   awgButtons();
  }));
  body.appendChild(row);
 });
}

function awgPolicyAddDevice() {
 if (awgPolicyDevices.length >= 32) return;
 awgPolicyDevices.push({source: '', policy: 'vpn_all'});
 awgDirty = true;
 awgPolicyDrawDevices();
 awgButtons();
}

function awgPolicyField(group, rule, key, title, rows, placeholder) {
 var label = document.createElement('label');
 label.textContent = title;
 var control = awgPolicyControl(rows ? 'textarea' : 'input', rule[key], function (value) { rule[key] = value; });
 if (rows) control.rows = rows;
 if (placeholder) control.placeholder = placeholder;
 control.spellcheck = false;
 label.appendChild(control);
 group.appendChild(label);
 return control;
}

function awgPolicyLoadFile(rule, input, exclude) {
 var file = input.files && input.files[0];
 if (!file) return;
 if (file.size > 24576) {
  awgMessage('本地列表最多 24 KB，较大的列表可使用订阅地址。', true);
  input.value = '';
  return;
 }
 var reader = new FileReader();
 reader.onload = function () {
  var domains = exclude ? 'exclude_domains' : 'domains';
  var networks = exclude ? 'exclude_networks' : 'networks';
  String(reader.result).split(/\r?\n/).forEach(function (line) {
   var item = line.split('#')[0].trim();
   if (!item) return;
   var key = /^\d+(?:\.\d+){3}(?:\/\d+)?$/.test(item) ? networks : domains;
   rule[key] = [rule[key], item].filter(Boolean).join('\n');
  });
  awgDirty = true;
  awgPolicyDrawRules(rule.id);
  awgButtons();
 };
 reader.onerror = function () { awgMessage('无法读取列表文件。', true); };
 reader.readAsText(file);
}

function awgPolicyDrawRules(openID) {
 var list = awgEl('awg_policy_rules');
 list.textContent = '';
 awgPolicyRules.forEach(function (rule, i) {
  var card = document.createElement('details');
  card.className = 'policy-rule';
  card.open = rule.id === openID;
  var summary = document.createElement('summary');
  summary.textContent = rule.name || '分流规则';
  card.appendChild(summary);
  var fields = document.createElement('div');
  fields.className = 'policy-options';
  card.appendChild(fields);
  var name = awgPolicyField(fields, rule, 'name', '名称', 0, '例如：国内直出');
  name.maxLength = 24;
  name.onchange = function () {
   summary.textContent = rule.name || '分流规则';
   awgPolicyChoices();
   awgButtons();
  };
  var label = document.createElement('label');
  label.textContent = '匹配行为';
  var mode = awgPolicyControl('select');
  awgPolicyOption(mode, 'include', '匹配走隧道，其余走本地');
  awgPolicyOption(mode, 'exclude', '匹配走本地，其余走隧道');
  mode.value = rule.mode;
  mode.onchange = function () { rule.mode = mode.value; awgDirty = true; };
  label.appendChild(mode);
  fields.appendChild(label);
  awgPolicyField(fields, rule, 'geoip', 'GeoIP 分类', 0, '例如：cn');
  awgPolicyField(fields, rule, 'geosite', 'GeoSite 分类', 0, '例如：cn, github');
  awgPolicyField(fields, rule, 'antifilter', 'Antifilter 列表', 0, '例如：subnet, community_domains');
  awgPolicyField(fields, rule, 'domains', '域名', 3, '每行一个域名');
  awgPolicyField(fields, rule, 'networks', 'IPv4 或 CIDR', 3, '每行一个地址或网段');
  awgPolicyField(fields, rule, 'urls', '订阅地址', 3, '每行一个 HTTP(S) URL');
  awgPolicyField(fields, rule, 'exclude_domains', '例外域名', 3);
  awgPolicyField(fields, rule, 'exclude_networks', '例外 IP 或 CIDR', 3);
  awgPolicyField(fields, rule, 'exclude_urls', '例外订阅地址', 3);
  [false, true].forEach(function (exclude) {
   var upload = document.createElement('label');
   upload.textContent = exclude ? '导入例外列表' : '导入本地列表';
   var file = awgPolicyControl('input');
   file.type = 'file';
   file.accept = '.txt,.list,.cidr';
   file.onchange = function () { awgPolicyLoadFile(rule, file, exclude); };
   upload.appendChild(file);
   fields.appendChild(upload);
  });
  card.appendChild(awgPolicyButton('删除规则', function () {
   var ref = 'vpn_geo_' + rule.id;
   if (awgEl('awg_policy_default').value === ref || awgPolicyDevices.some(function (item) { return item.policy === ref; })) {
    awgMessage('这套规则仍在使用，请先更改相应设备或默认策略。', true);
    return;
   }
   awgPolicyRules.splice(i, 1);
   awgDirty = true;
   awgPolicyChoices();
   awgPolicyDrawRules();
   awgButtons();
  }));
  list.appendChild(card);
 });
}

function awgPolicyAddRule() {
 for (var id = 1; id <= 8; id++) {
  if (awgPolicyRules.some(function (rule) { return rule.id === id; })) continue;
  awgPolicyRules.push({id: id, name: '分流规则 ' + id, mode: 'include'});
  awgDirty = true;
  awgPolicyChoices();
  awgPolicyDrawRules(id);
  awgButtons();
  return;
 }
}

function awgPolicyRead() {
 return {
  default: awgEl('awg_policy_default').value || 'direct',
  dns: awgEl('awg_policy_dns').value || 'router',
  ipv4_only: awgEl('awg_policy_ipv4').checked,
  kill_switch: awgEl('awg_policy_guard').checked,
  auto_update: awgEl('awg_policy_auto').checked,
  devices: awgPolicyDevices.map(function (item) { return {source: item.source.trim(), policy: item.policy}; }),
  rules: awgPolicyRules
 };
}

function awgPolicyMode() {
 var mode = awgEl('awg_mode').value;
 awgEl('awg_policy').hidden = mode !== 'policy';
 awgEl('awg_lan_settings').hidden = mode === 'policy';
 awgEl('awg_source_row').hidden = mode === 'policy';
}

function awgPolicyInitial() {
 awgEl('awg_mode').addEventListener('change', awgPolicyMode);
 ['awg_policy_default', 'awg_policy_dns', 'awg_policy_ipv4', 'awg_policy_guard', 'awg_policy_auto'].forEach(function (id) {
  awgEl(id).addEventListener('change', function () { awgDirty = true; });
 });
}

function awgPolicyRender(status) {
 var r = status.settings.routing || {};
 var signature = JSON.stringify(r);
 if (!awgDirty && signature !== awgPolicySignature) {
  awgPolicySignature = signature;
  awgPolicyRules = r.rules || [];
  awgPolicyDevices = r.devices || [];
  awgPolicyChoices();
  awgEl('awg_policy_default').value = r.default || 'direct';
  awgEl('awg_policy_dns').value = r.dns || 'router';
  awgEl('awg_policy_ipv4').checked = !!r.ipv4_only;
  awgEl('awg_policy_guard').checked = !!r.kill_switch;
  awgEl('awg_policy_auto').checked = !!r.auto_update;
  awgPolicyDrawRules();
 }
 var lists = status.rule_lists || {};
 awgEl('awg_policy_list_status').textContent = lists.message || '列表在启动后下载，运行时可手动更新。';
 awgPolicyMode();
}

function awgPolicyButtons() {
 var active = awgLastStatus && awgLastStatus.running && awgLastStatus.settings.mode === 'policy';
 var locked = awgBusy || !awgLastStatus || awgLastStatus.running || awgLastStatus.protected || awgLastStatus.guard_pending;
 document.querySelectorAll('[data-policy-edit]').forEach(function (control) { control.disabled = !!locked; });
 if (!locked) {
  awgEl('awg_policy_add_device').disabled = awgPolicyDevices.length >= 32;
  awgEl('awg_policy_add_rule').disabled = awgPolicyRules.length >= 8;
 }
 awgEl('awg_policy_refresh').disabled = awgBusy || !active || !!(awgLastStatus.rule_lists || {}).running;
 awgEl('awg_traffic_start').disabled = awgBusy || !active || !!(awgTraffic && awgTraffic.active);
 awgEl('awg_traffic_stop').disabled = awgBusy || !(awgTraffic && awgTraffic.active);
 awgEl('awg_traffic_rule').disabled = !!locked || !awgPolicyRules.length;
 document.querySelectorAll('[data-policy-add-entry]').forEach(function (button) {
  button.disabled = !!locked || !awgPolicyRules.length;
 });
}

function awgTrafficToggle() {
 if (awgEl('awg_traffic').open && awgCurrentPage === 'settings') awgPollStatus('traffic-status', false);
}

function awgTrafficStart() {
 var ip = awgEl('awg_traffic_device').value.trim();
 if (!ip) {
  awgMessage('请输入要分析的设备 IPv4 地址。', true);
  return;
 }
 awgRequest('traffic-start', {amneziawg_payload: JSON.stringify({device: ip})}, true);
}

function awgTrafficRender(state) {
 awgTraffic = state;
 awgEl('awg_traffic_state').textContent = state.active ? '正在分析 ' + state.device :
  (state.device ? '分析已结束，设备 ' + state.device : '每次最多分析 10 分钟。');
 var body = awgEl('awg_traffic_rows');
 body.textContent = '';
 (state.entries || []).slice().reverse().forEach(function (entry) {
  var row = document.createElement('tr');
  awgPolicyCell(row, entry.t || '');
  awgPolicyCell(row, entry.name === entry.ip ? entry.ip : [entry.name, entry.ip].filter(Boolean).join(' / '));
  awgPolicyCell(row, [entry.proto, entry.port].filter(Boolean).join(' / '));
  awgPolicyCell(row, {direct: '本地出口', vpn: '客户端隧道', geo: '匹配分流规则'}[entry.verdict] || '');
  var button = awgPolicyButton('加入规则', function () {
   var ref = awgEl('awg_traffic_rule').value;
   var rule = awgPolicyRules.find(function (item) { return ref === 'vpn_geo_' + item.id; });
   if (!rule) return;
   var isDomain = entry.name && entry.name !== entry.ip;
   var key = isDomain ? 'domains' : 'networks';
   var value = isDomain ? entry.name : entry.ip;
   if (value) rule[key] = [rule[key], value].filter(Boolean).join('\n');
   awgDirty = true;
   awgPolicyDrawRules(rule.id);
   awgButtons();
   awgMessage('已加入草稿，请保存设置。', false);
  });
  button.setAttribute('data-policy-add-entry', '');
  awgPolicyCell(row, button);
  body.appendChild(row);
 });
}
