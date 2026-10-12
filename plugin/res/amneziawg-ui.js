/* SPDX-License-Identifier: MIT */
var awgQueuedPage=null;
var awgCurrentPage='server',awgEntryMode='form';
function awgPage(page){
 if(['home','server','settings','import','logs'].indexOf(page)===-1)return;
 if(typeof awgConfigClose==='function')awgConfigClose();
 awgCurrentPage=page;
 ['home','server','settings','import','logs'].forEach(function(p){awgEl('page_'+p).hidden=p!==page;awgEl('nav_'+p).classList.toggle('active',p===page);if(p===page)awgEl('nav_'+p).setAttribute('aria-current','page');else awgEl('nav_'+p).removeAttribute('aria-current');});
 if(awgBusy)awgQueuedPage=page;else if(page==='logs')awgRequest('logs',{},true);else if(page==='server')awgPollStatus('server-status',false);else awgPollStatus('status',false);
 window.scrollTo(0,0);
}
function awgImportMode(mode){awgEntryMode=mode;awgEl('awg_form_fields').hidden=mode!=='form';awgEl('awg_file_fields').hidden=mode!=='file';['form','file'].forEach(function(m){awgEl('method_'+m).classList.toggle('selected',m===mode);awgEl('method_'+m).setAttribute('aria-pressed',String(m===mode));});}
function awgConnect(){if(!awgLastStatus)return;if(awgLastStatus.running||awgLastStatus.protected||awgLastStatus.guard_pending){awgAction('down');return;}if(!awgLastStatus.configured){awgPage('import');return;}awgAction('up');}
function awgProfileSelect(){awgUICards(awgLastStatus);awgButtons();}
function awgUICards(s){
 var container=awgEl('awg_profile_cards');container.textContent='';
 (s&&s.profiles||[]).forEach(function(p){
  var b=document.createElement('button');b.type='button';b.className='profile-option';b.classList.toggle('selected',p.id===awgEl('awg_profile').value);b.setAttribute('aria-pressed',String(p.id===awgEl('awg_profile').value));
  var name=document.createElement('span');name.textContent=p.name;var note=document.createElement('small');note.textContent=p.id===s.settings.profile?'当前节点':'选择';b.appendChild(name);b.appendChild(note);
  b.onclick=function(){awgEl('awg_profile').value=p.id;awgProfileSelect();};b.disabled=awgBusy;container.appendChild(b);
 });
}
function awgUIButtons(){
 var s=awgLastStatus,changing=awgBusy&&awgPendingAction!=='status';
 awgEl('awg_start').disabled=awgBusy||!s;
 if(!s){awgEl('awg_connect_title').textContent='状态未知';awgEl('awg_connect_hint').textContent='请刷新状态';}
 else{var active=s.running||s.protected||s.guard_pending;awgEl('awg_connect_title').textContent=changing?'处理中…':s.running?'隧道已启动':active?'连接已保护':s.configured?'连接':'添加节点';awgEl('awg_connect_hint').textContent=changing?'请稍候':active?'点击停止并恢复直连':s.configured?'点击建立隧道':'导入文件或手动填写';}
 awgEl('awg_start').classList.toggle('connected',!!(s&&s.running));
 awgEl('awg_stop').hidden=!(s&&(s.running||s.protected||s.guard_pending));
 document.querySelectorAll('#awg_form_fields input,#awg_file_fields textarea').forEach(function(el){el.disabled=awgBusy;});
}
function awgUIRender(s){
 var active=(s.profiles||[]).filter(function(p){return p.id===s.settings.profile;})[0];
 awgEl('awg_active_name').textContent=active?active.name:s.configured?'默认节点':'尚未添加节点';
 awgEl('awg_endpoint').textContent=s.peers&&s.peers[0]&&s.peers[0].endpoint?'· '+s.peers[0].endpoint:'';
 awgEl('awg_home_hint').textContent=s.running?'隧道已启动。是否连通，请查看最近握手。':s.configured?'准备就绪，点击连接即可建立隧道。':'导入服务端配置，或像 WireGuard 一样填写信息。';
 awgEl('awg_route_badge').textContent=s.settings.mode==='lan'?'局域网分流'+(s.settings.ipv6?' · IPv4 + IPv6':' · IPv4'):'仅建立隧道';
 var rx=0,tx=0;(s.peers||[]).forEach(function(p){rx+=p.rx||0;tx+=p.tx||0;});awgEl('awg_total_rx').textContent=awgBytes(rx);awgEl('awg_total_tx').textContent=awgBytes(tx);
 awgEl('awg_protection_title').textContent=s.protected?'断线保护规则已安装':s.guard_pending?'断线保护待修复':'按需开启连接保护';
 awgEl('awg_protection_note').textContent=s.protected?'所选设备受保护，停止连接才恢复直连。':s.guard_pending?'请查看连接详情，或停止并恢复直连。':'在设置中配置 DNS 接管与断线保护。';
 awgUICards(s);
}
function awgFieldValue(id,label,required){var value=awgEl(id).value.trim();if(required&&!value)throw Error('请填写'+label+'。');if(/[\r\n\x00#]/.test(value))throw Error(label+'不能包含换行或 #。');return value;}
function awgFormConfig(){
 var host=awgFieldValue('awg_host','服务器地址',true),port=awgFieldValue('awg_port','服务器端口',true);
 if(/^\[.*\]$/.test(host))host=host.slice(1,-1);
 if(/[\s\/\[\]]/.test(host))throw Error('服务器地址只填写域名或 IP，不要填写网址或端口。');
 if(!/^\d+$/.test(port)||+port<1||+port>65535)throw Error('服务器端口应为 1–65535。');
 if(host.indexOf(':')!==-1)host='['+host+']';
 var privateKey=awgFieldValue('awg_private','客户端私钥',true),publicKey=awgFieldValue('awg_public','服务端公钥',true);
 function keyCheck(v,label){try{if(atob(v).length!==32)throw Error();}catch(e){throw Error(label+'格式不正确，应为 32 字节的 Base64 密钥。');}}
 keyCheck(privateKey,'客户端私钥');keyCheck(publicKey,'服务端公钥');
 var lines=['[Interface]','PrivateKey = '+privateKey,'Address = '+awgFieldValue('awg_address','客户端隧道地址',true)];
 function add(key,id,label){var value=awgFieldValue(id,label||key,false);if(value)lines.push(key+' = '+value);}
 add('DNS','awg_form_dns','DNS');add('MTU','awg_mtu','MTU');
 document.querySelectorAll('[data-awg-extra]').forEach(function(el){add(el.getAttribute('data-awg-extra'),el.id);});
 lines.push('','[Peer]','PublicKey = '+publicKey,'Endpoint = '+host+':'+port,'AllowedIPs = '+awgFieldValue('awg_allowed','AllowedIPs',true));
 var psk=awgFieldValue('awg_psk','预共享密钥',false);if(psk){keyCheck(psk,'预共享密钥');lines.push('PresharedKey = '+psk);}
 add('PersistentKeepalive','awg_keepalive','保活间隔');return lines.join('\n')+'\n';
}
function awgClearImport(){
 ['awg_config','awg_file','awg_name','awg_host','awg_address','awg_private','awg_public','awg_form_dns','awg_mtu','awg_psk'].forEach(function(id){awgEl(id).value='';});
 document.querySelectorAll('[data-awg-extra]').forEach(function(el){el.value='';});awgEl('awg_port').value='51820';awgEl('awg_allowed').value='0.0.0.0/0';awgEl('awg_keepalive').value='25';
}
