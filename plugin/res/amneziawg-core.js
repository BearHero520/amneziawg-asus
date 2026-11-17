/* SPDX-License-Identifier: MIT */
var awgCore=null,awgCoreChoice=null;
function awgCoreRender(s){
 awgCore=s;
 awgEl('core_current').textContent=s.version+' · '+s.arch;
 awgEl('core_plugin').textContent=s.plugin;
 var release=s.release;
 var pkg=release&&release.available&&release.package;
 awgEl('plugin_latest').textContent=release?release.version+(release.available?(pkg?' · 可下载':' · 当前架构的安装包未提供'):' · 无可用更新'):'尚未检查';
 var download=awgEl('plugin_download');
 download.hidden=!pkg;
 download.href=pkg?pkg.url:'';
 download.textContent='下载 '+(s.arch==='armv7'?'ARMv7':'ARM64')+' 离线包';
 awgEl('plugin_checksum_row').hidden=!pkg;
 awgEl('plugin_checksum').textContent=pkg?pkg.sha256:'';
 awgEl('core_latest').textContent=s.latest?s.latest+(s.available?' · 可升级':''):release?'请使用完整插件包':'尚未检查';
 awgEl('core_checked').textContent=s.checked?new Date(s.checked*1000).toLocaleString():'尚未检查';
 awgEl('core_backup').textContent=s.backup||'尚无备份（首次成功切换后生成）';
 awgEl('core_progress').textContent=s.message||'核心升级或回滚的进度会显示在这里。';
 awgEl('core_progress').className=s.phase==='failed'||s.phase==='recovery_required'?'error':'awg-note';
 awgEl('core_progress').setAttribute('aria-busy',String(!!s.busy));
 if(s.busy)awgCoreCancel();
 awgCoreButtons();
}
function awgCoreButtons(){
 var locked=awgBusy||!awgCore||awgCore.busy;
 awgEl('core_check').disabled=awgBusy||!!(awgCore&&awgCore.busy);
 awgEl('core_upgrade').disabled=locked||!awgCore.available;
 awgEl('core_rollback').disabled=locked||!awgCore.backup||awgCore.backup===awgCore.version;
 awgEl('core_ack').disabled=locked;
 awgEl('core_confirm').disabled=locked||!awgCoreChoice||!awgEl('core_ack').checked;
 // The backend serializes mutations too; keep navigation and status reads usable.
 if(awgCore&&awgCore.busy)document.querySelectorAll('.awg-panel button:not(.nav-item):not([data-local]):not([data-config-local]),.awg-panel input,.awg-panel select,.awg-panel textarea:not([readonly])').forEach(function(el){el.disabled=true;});
}
function awgCoreAsk(action){
 if(awgBusy||!awgCore||awgCore.busy)return;
 var version=action==='core-upgrade'?awgCore.latest:awgCore.backup;
 if(action==='core-upgrade'&&!awgCore.available)return;
 if(action==='core-rollback'&&(!version||version===awgCore.version))return;
 awgCoreChoice={action:action,version:version};awgEl('core_confirm_text').textContent=(action==='core-upgrade'?'升级至 ':'回滚至 ')+version+'？客户端与服务端会短暂断开，完成后恢复原先运行的服务。';
 awgEl('core_ack').checked=false;awgEl('core_confirmation').hidden=false;awgCoreButtons();awgEl('core_ack').focus();
}
function awgCoreCancel(){awgCoreChoice=null;awgEl('core_confirmation').hidden=true;awgEl('core_ack').checked=false;}
function awgCoreConfirm(){
 if(!awgCoreChoice||!awgEl('core_ack').checked||awgBusy||!awgCore||awgCore.busy)return;
 var choice=awgCoreChoice;if(choice.version!==(choice.action==='core-upgrade'?awgCore.latest:awgCore.backup)){awgCoreCancel();awgMessage('版本信息已改变，请重新确认。',true);return;}
 awgCoreCancel();awgRequest(choice.action,{amneziawg_payload:JSON.stringify({version:choice.version})},true);
}
