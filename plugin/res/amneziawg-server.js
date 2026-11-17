/* SPDX-License-Identifier: MIT */
var awgServer = null;
var awgServerDirty = false;
var awgServerFields = ['port', 'address', 'address6', 'endpoint_mode', 'endpoint', 'auto', 'allow_lan', 'internet', 'fullv', 'dns', 'extra', 'keep_lan_source', 'keep_client_dns'];

function awgServerInitial() {
 awgServerFields.forEach(function (field) {
  ['input', 'change'].forEach(function (event) {
   awgEl('sv_' + field).addEventListener(event, function () {
    awgServerDirty = true;
    awgServerButtons();
   });
  });
 });
}

function awgServerButtons() {
 var active = awgServer && (awgServer.running || awgServer.pending);
 var locked = awgBusy || !!active || !awgServer;
 var peerLocked = awgBusy || !awgServer || !!awgServer.pending;
 var canAdd = !peerLocked && awgServer.configured && awgServer.clients.length < 10;
 awgServerFields.forEach(function (field) { awgEl('sv_' + field).disabled = locked; });
 awgEl('sv_endpoint').disabled = locked || awgEl('sv_endpoint_mode').value === 'auto';
 awgEl('sv_save').disabled = locked;
 awgEl('sv_add').disabled = !canAdd;
 awgEl('sv_name').disabled = peerLocked;
 var legacy = awgEl('sv_import_legacy');
 legacy.hidden = !(awgServer && awgServer.legacy_devices);
 legacy.disabled = locked || !awgServer.configured || awgServer.clients.length >= 10;
 awgEl('sv_start').disabled = awgBusy || !awgServer || !!active || !awgServer.configured ||
  !awgServer.clients.some(function (device) { return !device.disabled; });
 awgEl('sv_stop').disabled = awgBusy || (!active && !(awgServer && awgServer.wanted));
 awgEl('sv_add').textContent = awgBusy && awgPendingAction === 'server-add' ? '添加中…' : '添加设备';
 awgEl('sv_start').textContent = awgBusy && awgPendingAction === 'server-up' ? '启动中…' : '启动服务端';
 awgEl('sv_stop').textContent = awgBusy && awgPendingAction === 'server-down' ? '停止中…' :
  awgServer && awgServer.recovering ? '停止并取消重试' : '停止服务端';
 document.querySelectorAll('[data-server-delete], [data-server-toggle], [data-server-scope]').forEach(function (control) {
  control.disabled = peerLocked;
 });
 document.querySelectorAll('[data-server-exit]').forEach(function (control) {
  control.disabled = peerLocked || control.getAttribute('data-lan') === 'true';
 });
 document.querySelectorAll('[data-server-export], [data-server-view]').forEach(function (control) {
  control.disabled = awgBusy;
 });
}

function awgServerCell(row, content) {
 var cell = document.createElement('td');
 if (typeof content === 'string') cell.textContent = content;
 else cell.appendChild(content);
 row.appendChild(cell);
 return cell;
}

function awgDeviceSelect(device, field, title, choices, route, lanOnly) {
 var select = document.createElement('select');
 select.setAttribute('aria-label', device.name + ' ' + title);
 select.setAttribute('data-server-' + field, device.id);
 if (lanOnly) select.setAttribute('data-lan', 'true');
 choices.forEach(function (choice) {
  var option = document.createElement('option');
  option.value = choice[0];
  option.textContent = choice[1];
  option.disabled = !!choice[2];
  select.appendChild(option);
 });
 select.value = route[field];
 select.onchange = function () {
  var change = { id: device.id, scope: route.scope, exit: route.exit };
  change[field] = select.value;
  // Polling and failed saves continue to display the applied settings.
  select.value = route[field];
  awgServerAction('server-route', change);
 };
 return select;
}

function awgDeviceRow(device, settings, exits) {
 var row = document.createElement('tr');
 var route = { scope: (device.route || {}).scope || '', exit: (device.route || {}).exit || '' };
 awgServerCell(row, device.name);
 awgServerCell(row, device.address + (device.address6 ? ' / ' + device.address6 : ''));
 awgServerCell(row, awgDeviceSelect(device, 'scope', '访问范围', [
  ['', '跟随服务端'], ['lan', '仅家庭内网', !settings.allow_lan], ['full', '内网和家庭上网', !settings.internet]
 ], route, false));
 var egress = [['', '跟随路由器'], ['proxy', '透明代理'], ['wan', '宽带直出'], ['vpn_all', '客户端隧道（IPv4）']];
 exits.forEach(function (rule) { egress.push([rule.id, rule.name + '（IPv4）']); });
 awgServerCell(row, awgDeviceSelect(device, 'exit', '家庭出口', egress, route, route.scope === 'lan' || !settings.internet));
 var enabled = document.createElement('input');
 enabled.type = 'checkbox';
 enabled.checked = !device.disabled;
 enabled.setAttribute('aria-label', '启用 ' + device.name);
 enabled.setAttribute('data-server-toggle', device.id);
 enabled.onchange = function () {
  enabled.checked = !device.disabled;
  var action = device.disabled ? 'server-enable' : 'server-disable';
  if (device.disabled || confirm('禁用设备“' + device.name + '”？仅该设备会立即断开。')) {
   awgServerAction(action, {id: device.id});
  }
 };
 awgServerCell(row, enabled);
 awgServerCell(row, '');
 awgServerCell(row, '');
 var actions = document.createElement('div');
 actions.className = 'server-device-actions';
 [['扫码', 'view'], ['下载配置', 'export'], ['删除', 'delete']].forEach(function (action) {
  var button = document.createElement('button');
  button.type = 'button';
  button.textContent = action[0];
  button.setAttribute('data-server-' + action[1], device.id);
  button.onclick = function () {
   if (action[1] === 'view') {
    awgConfigOpen(device.id, device.name, button);
    return;
   }
   if (action[1] !== 'delete' || confirm('删除设备“' + device.name + '”？该设备的原配置将失效。')) {
    awgServerAction('server-' + action[1], {id: device.id});
   }
  };
  actions.appendChild(button);
 });
 awgServerCell(row, actions);
 return row;
}

function awgServerRender(s) {
 awgServer = s;
 awgEl('sv_status').textContent = s.pending ? '运行异常 / 设备变更待处理' :
  s.recovering ? '恢复失败 / 等待自动重试' : s.running ? '服务端已启动' : '服务端已停止';
 awgEl('sv_status').className = 'awg-state' + (s.running ? ' connected' : '');
 awgEl('sv_ddns').textContent = s.ddns || '尚未设置 DDNS';
 awgEl('sv_detected').textContent = s.endpoint || '未获取到可用地址';
 awgEl('sv_lan').textContent = s.lan || '未识别';
 awgEl('sv_warning').textContent = s.warning || '';
 awgEl('sv_public').textContent = s.public || '首次保存后自动生成';
 if (!awgServerDirty) {
  awgServerFields.forEach(function (field) {
   var el = awgEl('sv_' + field);
   if (el.type === 'checkbox') el.checked = !!s.settings[field];
   else el.value = s.settings[field] === undefined ? '' : s.settings[field];
  });
 }
 var body = awgEl('sv_clients');
 var exits = s.egress_rules || [];
 var signature = JSON.stringify([!!s.settings.allow_lan, !!s.settings.internet, exits, s.clients.map(function (p) {
  return [p.id, p.name, p.address, p.address6, !!p.disabled, p.route];
 })]);
 if (body.getAttribute('data-peers') !== signature) {
  body.setAttribute('data-peers', signature);
  body.textContent = '';
  s.clients.forEach(function (p) { body.appendChild(awgDeviceRow(p, s.settings, exits)); });
 }
 s.clients.forEach(function (p, i) {
  var cells = body.children[i].children;
  cells[5].textContent = p.disabled ? '已禁用' : p.handshake ? new Date(p.handshake * 1000).toLocaleString() : '尚未握手';
  cells[6].textContent = awgBytes(p.rx || 0) + ' / ' + awgBytes(p.tx || 0);
 });
 awgEl('sv_empty').hidden = !!s.clients.length;
 awgEl('sv_count').textContent = s.clients.length + ' / 10';
 var note = awgEl('sv_egress_note');
 note.hidden = !!s.client_egress || !s.clients.some(function (p) { return /^vpn_/.test((p.route || {}).exit || ''); });
 note.textContent = '客户端分流当前未启用，选择客户端隧道的设备暂走家庭宽带。';
 awgServerButtons();
}

function awgServerAction(action, payload) {
 if (action === 'server-down' && !confirm('停止服务端将断开所有回家设备。如果你正在远程连接本路由器，管理页面也可能断开。确定停止？')) return;
 if (action === 'server-add' && (!payload || !payload.name)) {
  awgMessage('请先填写设备名称。', true);
  awgEl('sv_name').focus();
  return;
 }
 if (action === 'server-status') {
  awgPollStatus('server-status', true);
  return;
 }
 if (awgServerDirty && ['server-up', 'server-add', 'server-export', 'server-route', 'server-import-legacy'].indexOf(action) !== -1) {
  awgMessage('请先保存服务端设置。', true);
  return;
 }
 if (action === 'server-import-legacy' && !confirm('从 0.5.3 归档导入设备到当前服务端？导入后请重新扫码或下载配置。')) return;
 var waiting = {
  'server-up': '正在启动服务端…', 'server-down': '正在停止服务端…',
  'server-add': '正在添加设备…', 'server-delete': '正在删除该设备…',
  'server-enable': '正在启用该设备…', 'server-disable': '正在禁用该设备…',
  'server-save': '正在保存设置…', 'server-route': '正在应用设备出口…',
  'server-import-legacy': '正在导入旧版设备…'
 };
 awgMessage(waiting[action] || '正在读取配置…', false);
 awgRequest(action, payload ? {amneziawg_payload: JSON.stringify(payload)} : {}, true);
}

function awgServerSave() {
 var settings = {};
 awgServerFields.forEach(function (field) {
  var el = awgEl('sv_' + field);
  settings[field] = el.type === 'checkbox' ? el.checked : el.value.trim();
 });
 settings.port = Number(settings.port);
 settings.fullv = settings.internet && settings.fullv;
 awgServerAction('server-save', settings);
}

function awgServerDownload(v) {
 var blob = new Blob([v.export], {type: 'text/plain;charset=utf-8'});
 var url = URL.createObjectURL(blob);
 var a = document.createElement('a');
 a.href = url;
 a.download = /^amneziawg-[a-f0-9]{16}\.conf$/.test(v.filename) ? v.filename : 'amneziawg-client.conf';
 document.body.appendChild(a);
 a.click();
 a.remove();
 setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
 v.export = '';
}
