/* SPDX-License-Identifier: MIT */
var awgServer=null,awgServerDirty=false;
var awgServerFields=['port','address','address6','endpoint_mode','endpoint','auto','allow_lan','internet','fullv','dns','extra'];
function awgServerInitial(){awgServerFields.forEach(function(k){['input','change'].forEach(function(ev){awgEl('sv_'+k).addEventListener(ev,function(){awgServerDirty=true;awgServerButtons();});});});}
function awgServerButtons(){
 var active=awgServer&&(awgServer.running||awgServer.pending),locked=awgBusy||!!active||!awgServer,peerLocked=awgBusy||!awgServer||!!awgServer.pending;
 awgServerFields.forEach(function(k){awgEl('sv_'+k).disabled=locked;});
 awgEl('sv_endpoint').disabled=locked||awgEl('sv_endpoint_mode').value==='auto';
 awgEl('sv_save').disabled=locked;awgEl('sv_add').disabled=peerLocked||!awgServer.configured||awgServer.clients.length>=10;awgEl('sv_name').disabled=peerLocked;
 awgEl('sv_start').disabled=awgBusy||!awgServer||!!active||!awgServer.configured||!awgServer.clients.some(function(p){return !p.disabled;});
 awgEl('sv_stop').disabled=awgBusy||(!active&&!(awgServer&&awgServer.wanted));
 awgEl('sv_add').textContent=awgBusy&&awgPendingAction==='server-add'?'添加中…':'添加设备';
 awgEl('sv_start').textContent=awgBusy&&awgPendingAction==='server-up'?'启动中…':'启动服务端';
 awgEl('sv_stop').textContent=awgBusy&&awgPendingAction==='server-down'?'停止中…':awgServer&&awgServer.recovering?'停止并取消重试':'停止服务端';
 document.querySelectorAll('[data-server-delete], [data-server-enable], [data-server-disable]').forEach(function(b){b.disabled=peerLocked;});
 document.querySelectorAll('[data-server-export], [data-server-view]').forEach(function(b){b.disabled=awgBusy;});
}
function awgServerRender(s){
 awgServer=s;awgEl('sv_status').textContent=s.pending?'运行异常 / 设备变更待处理':s.recovering?'恢复失败 / 等待自动重试':s.running?'服务端已启动':'服务端已停止';
 awgEl('sv_status').className='awg-state'+(s.running?' connected':'');
 awgEl('sv_ddns').textContent=s.ddns||'尚未设置 DDNS';awgEl('sv_detected').textContent=s.endpoint||'未获取到可用地址';
 awgEl('sv_lan').textContent=s.lan||'未识别';awgEl('sv_warning').textContent=s.warning||'';awgEl('sv_public').textContent=s.public||'首次保存后自动生成';
 if(!awgServerDirty){awgServerFields.forEach(function(k){var el=awgEl('sv_'+k);if(el.type==='checkbox')el.checked=!!s.settings[k];else el.value=s.settings[k]===undefined?'':s.settings[k];});}
 var body=awgEl('sv_clients');
 var signature=JSON.stringify((s.clients||[]).map(function(p){return [p.id,p.name,p.address,p.address6,!!p.disabled];}));
 if(body.getAttribute('data-peers')!==signature){body.setAttribute('data-peers',signature);body.textContent='';
 (s.clients||[]).forEach(function(p){var tr=document.createElement('tr');[p.name,p.address+(p.address6?' / '+p.address6:''),p.disabled?'已禁用':p.handshake?new Date(p.handshake*1000).toLocaleString():'尚未握手',awgBytes(p.rx||0)+' / '+awgBytes(p.tx||0)].forEach(function(text){var td=document.createElement('td');td.textContent=text;tr.appendChild(td);});
  var actions=document.createElement('td');[['二维码 / 配置','view'],['导出配置','export'],[p.disabled?'启用':'禁用',p.disabled?'enable':'disable'],['删除','delete']].forEach(function(pair){var b=document.createElement('button');b.textContent=pair[0];b.setAttribute('data-server-'+pair[1],p.id);b.onclick=function(){if(pair[1]==='view'){awgConfigOpen(p.id,p.name,b);return;}if(pair[1]==='delete'&&!confirm('删除设备“'+p.name+'”？仅该设备会立即断开，已导出的配置将失效。'))return;if(pair[1]==='disable'&&!confirm('禁用设备“'+p.name+'”？仅该设备会立即断开，其他设备保持连接。'))return;awgServerAction('server-'+pair[1],{id:p.id});};actions.appendChild(b);});tr.appendChild(actions);body.appendChild(tr);
 });
 }
 (s.clients||[]).forEach(function(p,i){var cells=body.children[i].children;cells[2].textContent=p.disabled?'已禁用':p.handshake?new Date(p.handshake*1000).toLocaleString():'尚未握手';cells[3].textContent=awgBytes(p.rx||0)+' / '+awgBytes(p.tx||0);});
 awgEl('sv_empty').hidden=!!s.clients.length;awgEl('sv_count').textContent=s.clients.length+' / 10';awgServerButtons();
}
function awgServerAction(action,payload){
 if(action==='server-down'&&!confirm('停止服务端将断开所有回家设备。如果你正在远程连接本路由器，管理页面也可能断开。确定停止？'))return;
 if(action==='server-add'&&(!payload||!payload.name)){awgMessage('请先填写设备名称。',true);awgEl('sv_name').focus();return;}
 if(action==='server-status'){awgPollStatus('server-status',true);return;}
 if(awgServerDirty&&['server-up','server-add','server-export'].indexOf(action)!==-1){awgMessage('请先保存服务端设置。',true);return;}
 awgMessage({'server-up':'正在启动服务端…','server-down':'正在停止服务端…','server-add':'正在添加设备…','server-delete':'正在删除该设备…','server-enable':'正在启用该设备…','server-disable':'正在禁用该设备…','server-save':'正在保存设置…'}[action]||'正在读取配置…',false);
 awgRequest(action,payload?{amneziawg_payload:JSON.stringify(payload)}:{},true);
}
function awgServerSave(){
 var s={};awgServerFields.forEach(function(k){var el=awgEl('sv_'+k);s[k]=el.type==='checkbox'?el.checked:el.value.trim();});s.port=Number(s.port);s.fullv=s.internet&&s.fullv;
 awgServerAction('server-save',s);
}
function awgServerDownload(v){
 var blob=new Blob([v.export],{type:'text/plain;charset=utf-8'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=/^amneziawg-[a-f0-9]{16}\.conf$/.test(v.filename)?v.filename:'amneziawg-client.conf';document.body.appendChild(a);a.click();a.remove();setTimeout(function(){URL.revokeObjectURL(url);},1000);v.export='';
}
