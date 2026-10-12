/* SPDX-License-Identifier: MIT */
var awgPoll=null,awgEpoch=0;
var awgPendingAction=null, awgBusy=false, awgTimer=null, awgDirty=false, awgLastStatus=null;
var awgFields=['awg_mode','awg_source','awg_auto','awg_ipv6','awg_source6','awg_dns_on','awg_kill','awg_failover','awg_fallbacks','awg_targets'];
function awgEl(id){return document.getElementById(id);}
function menu_hook(){tabtitle[tabtitle.length-1]=['','AmneziaWG'];tablink[tablink.length-1]=['','Module_amneziawg.asp'];}
function awgMessage(text,error){awgEl('awg_message').textContent=text;awgEl('awg_message').className=error?'error':'success';}
function awgInitial(){
 if(typeof show_menu==='function')show_menu(menu_hook);
 awgFields.forEach(function(id){awgEl(id).addEventListener('change',function(){awgDirty=true;});awgEl(id).addEventListener('input',function(){awgDirty=true;});});
 if(typeof awgServerInitial==='function')awgServerInitial();
 awgPage('server');awgTimer=setInterval(function(){if(!awgBusy&&awgCurrentPage!=='logs')awgPollStatus((awgCurrentPage==='core'||(typeof awgCore!=='undefined'&&awgCore&&awgCore.busy))?'core-status':awgCurrentPage==='server'?'server-status':'status',false);},10000);
}
function awgButtons(){
 var running=awgLastStatus&&awgLastStatus.running, protectedNow=awgLastStatus&&(awgLastStatus.protected||awgLastStatus.guard_pending);
 document.querySelectorAll('.awg-panel button:not([data-config-local]):not([data-local]):not(.nav-item)').forEach(function(b){b.disabled=awgBusy;});
 awgEl('awg_start').disabled=awgBusy||!!running||!awgLastStatus||!awgLastStatus.configured;
 awgEl('awg_save').disabled=awgBusy||!awgLastStatus||!!running||!!protectedNow;
 awgFields.forEach(function(id){awgEl(id).disabled=awgBusy||!awgLastStatus||!!running||!!protectedNow;});
 ['awg_import','awg_file','awg_config','awg_name'].forEach(function(id){awgEl(id).disabled=awgBusy;});
 awgEl('awg_switch').disabled=awgBusy||!awgEl('awg_profile').value;
 awgEl('awg_delete').disabled=awgBusy||!awgEl('awg_profile').value;
 if(typeof awgUIButtons==='function')awgUIButtons();
 if(typeof awgServerButtons==='function')awgServerButtons();
 if(typeof awgCoreButtons==='function')awgCoreButtons();
}
// Softcenter wraps http_response in a quoted result without escaping its contents.
// New backends return ASCII base64; also read the raw wrapper used by 0.1.1.
function awgDecodeResponse(text){
 var envelope;
 if(typeof text==='string'){
  try{envelope=JSON.parse(text);}catch(e){
   var legacy=/^\s*\{\s*"result"\s*:\s*"([\s\S]*)"\s*\}\s*$/.exec(text);
   if(!legacy)throw Error('响应格式错误');
   envelope={result:JSON.parse(legacy[1])};
  }
 }else{envelope=text;}
 var value=envelope&&envelope.result;
 if(typeof value==='string'){
  if(value.indexOf('AWG64:')===0){
   var bytes=atob(value.slice(6)),encoded='';
   for(var i=0;i<bytes.length;i++)encoded+='%'+('0'+bytes.charCodeAt(i).toString(16)).slice(-2);
   value=JSON.parse(decodeURIComponent(encoded));
  }else{value=JSON.parse(value);}
 }
 if(!value||typeof value.ok!=='boolean')throw Error('响应格式错误');
 return value;
}
function awgResponseError(text){
 if(awgPendingAction&&awgPendingAction.indexOf('server-')===0&&typeof awgServer!=='undefined'){awgServer=null;awgEl('sv_status').textContent='状态读取失败';}else if(awgPendingAction&&awgPendingAction.indexOf('core-')===0){}else if(awgPendingAction!=='logs'&&awgPendingAction!=='diagnose'){awgLastStatus=null;awgEl('awg_state').textContent='状态读取失败';}awgMessage(text,true);
}
function awgEncodeRequest(fields){
 var encoded={};Object.keys(fields||{}).forEach(function(k){encoded[k]=fields[k];});
 if(typeof encoded.amneziawg_payload==='string')encoded.amneziawg_payload='AWGREQ64:'+btoa(unescape(encodeURIComponent(encoded.amneziawg_payload)));
 return encoded;
}
function awgRequest(action,fields,loud){
 if(awgBusy){awgMessage('正在处理上一项操作，请稍候。',true);return;}
 awgEpoch++;if(awgPoll&&awgPoll.abort)awgPoll.abort();awgPoll=null;awgPendingAction=action;awgBusy=true;awgButtons();
 $.ajax({url:'/_api/',type:'POST',contentType:'application/json; charset=utf-8',cache:false,dataType:'text',timeout:90000,
 data:JSON.stringify({id:Math.floor(Math.random()*100000000),method:'amneziawg_api.sh',params:[action],fields:awgEncodeRequest(fields)}),
 success:function(r){try{
  var v=awgDecodeResponse(r);if(v.core&&typeof awgCoreRender==='function')awgCoreRender(v.core);
  if(v.ok&&action==='settings')awgDirty=false;
  if(v.ok&&action==='server-save')awgServerDirty=false;
  if(v.server&&typeof awgServerRender==='function')awgServerRender(v.server);
  if(v.ok&&action==='server-add')awgEl('sv_name').value='';
  if(v.ok&&v.export){if(typeof awgConfigResult==='function')awgConfigResult(v);else if(typeof awgServerDownload==='function')awgServerDownload(v);}
  if(typeof awgLogsRender==='function')awgLogsRender(v,action);
  if(v.status)awgRender(v.status);if(loud||!v.ok)awgMessage(v.message,!v.ok);
  if(v.ok&&action==='import'){awgEl('awg_config').value='';awgEl('awg_file').value='';awgEl('awg_name').value='';if(typeof awgClearImport==='function'){awgClearImport();awgPage('home');}}
 }catch(e){awgResponseError('无法读取插件响应，请刷新或检查安装。');}},
 error:function(xhr,reason){awgResponseError(reason==='timeout'?'请求超时，请刷新状态后再操作。':'状态接口请求失败'+(xhr&&xhr.status?'（HTTP '+xhr.status+'）':'')+'，请刷新状态后再操作。');},complete:function(){if(action==='server-export'&&typeof awgConfigComplete==='function')awgConfigComplete();awgBusy=false;awgPendingAction=null;awgButtons();if(typeof awgQueuedPage!=='undefined'&&awgQueuedPage){var page=awgQueuedPage;awgQueuedPage=null;awgPage(page);}}});
}
function awgRefresh(){awgPollStatus('status',true);}
// Polling never locks controls and a response begun before a mutation cannot overwrite it.
function awgPollStatus(action,loud){
 if(awgBusy)return;
 if(awgPoll){if(awgPoll.action===action)return;awgEpoch++;if(awgPoll.abort)awgPoll.abort();awgPoll=null;}
 var epoch=awgEpoch,token={action:action};awgPoll=token;
 var xhr=$.ajax({url:'/_api/',type:'POST',contentType:'application/json; charset=utf-8',dataType:'text',timeout:15000,cache:false,
 data:JSON.stringify({id:Math.floor(Math.random()*100000000),method:'amneziawg_api.sh',params:[action],fields:{}}),
 success:function(r){if(epoch!==awgEpoch)return;try{var v=awgDecodeResponse(r);if(v.core&&typeof awgCoreRender==='function')awgCoreRender(v.core);if(!v.ok)throw Error();if(v.server&&typeof awgServerRender==='function')awgServerRender(v.server);if(v.status)awgRender(v.status);awgButtons();if(loud)awgMessage('状态已刷新',false);}catch(e){awgPollError(action);}},
 error:function(xhr,reason){if(epoch===awgEpoch&&reason!=='abort')awgPollError(action);},
 complete:function(){if(awgPoll===token)awgPoll=null;}});
 if(xhr&&xhr.abort)token.abort=function(){xhr.abort();};
}
function awgPollError(action){
 if(action==='server-status'&&typeof awgServer!=='undefined'){awgServer=null;awgEl('sv_status').textContent='状态读取失败';}else if(action!=='core-status')awgLastStatus=null;
 awgMessage('状态读取失败；请刷新状态，或检查是否需要重新登录路由器。',true);awgButtons();
}
function awgAction(action){if(action==='up'&&awgDirty){awgMessage('请先保存运行设置。',true);return;}awgMessage(action==='up'?'正在启动并应用配置…':'正在停止并解除断线保护…',false);awgRequest(action,{},true);}
function awgSelected(id){return Array.prototype.filter.call(awgEl(id).options,function(o){return o.selected;}).map(function(o){return o.value;});}
function awgSave(){
 if(!awgLastStatus){awgMessage('请先成功读取状态，再保存设置。',true);return;}
 var s={mode:awgEl('awg_mode').value,source:awgEl('awg_source').value.trim(),auto:awgEl('awg_auto').checked,
 ipv6:awgEl('awg_ipv6').checked,source6:awgEl('awg_source6').value.trim(),dns:awgEl('awg_dns_on').checked,
 kill_switch:awgEl('awg_kill').checked,failover:awgEl('awg_failover').checked,fallbacks:awgSelected('awg_fallbacks'),
 health_targets:awgEl('awg_targets').value.split(',').map(function(v){return v.trim();}).filter(Boolean),profile:awgLastStatus.settings.profile||''};
 awgRequest('settings',{amneziawg_payload:JSON.stringify(s)},true);
}
function awgSwitch(){if(awgDirty){awgMessage('请先保存运行设置，再切换节点。',true);return;}awgRequest('switch',{amneziawg_payload:JSON.stringify({profile:awgEl('awg_profile').value})},true);}
function awgDelete(){var sel=awgEl('awg_profile');if(!sel.value)return;if(!confirm('删除所选配置？私钥文件会从路由器移除。请确认你已保留原始 .conf 文件。'))return;awgRequest('delete',{amneziawg_payload:JSON.stringify({profile:sel.value})},true);}
function awgReadFile(input){var f=input.files&&input.files[0];if(!f)return;if(f.size>32768){awgMessage('配置文件不能超过 32 KB。',true);input.value='';return;}var r=new FileReader();r.onload=function(){awgEl('awg_config').value=r.result;if(!awgEl('awg_name').value)awgEl('awg_name').value=f.name.replace(/\.(conf|txt)$/i,'');awgMessage('文件已读入，点击“校验并保存配置”完成导入。',false);};r.onerror=function(){awgMessage('无法读取文件。',true);};r.readAsText(f);}
function awgImport(){var s;try{s=typeof awgEntryMode!=='undefined'&&awgEntryMode==='form'?awgFormConfig():awgEl('awg_config').value;}catch(e){awgMessage(e.message,true);return;}if(!s.trim()){awgMessage('请选择文件或粘贴配置。',true);return;}try{var bytes=unescape(encodeURIComponent(s));if(bytes.length>32768)throw Error();awgRequest('import',{amneziawg_payload:JSON.stringify({name:awgEl('awg_name').value.trim(),config:btoa(bytes)})},true);}catch(e){awgMessage('配置编码错误或超过 32 KB。',true);}}
function awgBytes(n){if(n>=1048576)return(n/1048576).toFixed(2)+' MB';if(n>=1024)return(n/1024).toFixed(1)+' KB';return n+' B';}
function awgOptions(id,profiles,selected){var sel=awgEl(id);sel.textContent='';profiles.forEach(function(p){var o=document.createElement('option');o.value=p.id;o.textContent=p.name;o.selected=selected.indexOf(p.id)!==-1;sel.appendChild(o);});}
function awgRender(s){
 var previous=awgEl('awg_profile').value;awgLastStatus=s;
 awgEl('awg_state').textContent=(s.running?'隧道已启动':'隧道已停止')+(s.protected?' · 断线保护规则已安装':s.guard_pending?' · 断线保护待修复':' · 断线保护未启用');
 var active=(s.profiles||[]).filter(function(p){return p.id===s.settings.profile;})[0];
 awgEl('awg_configured').textContent=s.configured?'当前配置：'+(active?active.name:'默认配置'):'尚未导入配置';
 awgEl('awg_dns').textContent=(s.dns||[]).join(', ')||'未配置';
 awgEl('awg_health').textContent=s.health&&s.health.message?(s.health.message+' · '+new Date(s.health.last_check*1000).toLocaleString()):'自动切换尚无探测记录';
 awgOptions('awg_profile',s.profiles||[],[previous||s.settings.profile]);
 if(!awgDirty){
  awgEl('awg_mode').value=s.settings.mode;awgEl('awg_source').value=s.settings.source||'';awgEl('awg_auto').checked=!!s.settings.auto;
  awgEl('awg_ipv6').checked=!!s.settings.ipv6;awgEl('awg_source6').value=s.settings.source6||'';awgEl('awg_dns_on').checked=!!s.settings.dns;
  awgEl('awg_kill').checked=!!s.settings.kill_switch;awgEl('awg_failover').checked=!!s.settings.failover;
  awgEl('awg_targets').value=(s.settings.health_targets||[]).join(', ');awgOptions('awg_fallbacks',s.profiles||[],s.settings.fallbacks||[]);
 }
 var body=awgEl('awg_peers');body.textContent='';(s.peers||[]).forEach(function(p){var tr=document.createElement('tr');[p.endpoint||'未设置 Endpoint',p.handshake?new Date(p.handshake*1000).toLocaleString():'尚未握手',awgBytes(p.rx)+' / '+awgBytes(p.tx)].forEach(function(text){var td=document.createElement('td');td.textContent=text;tr.appendChild(td);});body.appendChild(tr);});
 awgEl('awg_peer_empty').style.display=(s.peers||[]).length?'none':'block';
 if(typeof awgUIRender==='function')awgUIRender(s);
}
