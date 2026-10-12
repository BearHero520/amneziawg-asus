/* SPDX-License-Identifier: MIT */
var awgConfigPending=null,awgConfigFile='',awgConfigReturn=null,awgConfigScroll='';
function awgConfigOpen(id,name,button){
 if(awgBusy)return;
 if(awgServerDirty){awgMessage('请先保存服务端设置。',true);return;}
 awgConfigPending={name:name,button:button};
 awgServerAction('server-export',{id:id});
}
function awgConfigComplete(){awgConfigPending=null;}
function awgConfigResult(v){
 if(!awgConfigPending){awgServerDownload(v);return;}
 var pending=awgConfigPending;awgConfigPending=null;
 awgConfigReturn=pending.button;awgConfigFile=v.filename;
 awgEl('sv_config_title').textContent=pending.name+' · 设备配置';
 awgEl('sv_config_text').value=v.export;
 awgEl('sv_config_feedback').textContent='';
 var canvas=awgEl('sv_config_qr'),note=awgEl('sv_config_qr_note');canvas.width=canvas.height=0;canvas.hidden=true;
 try{
  qrcode.stringToBytes=qrcode.stringToBytesFuncs['UTF-8'];
  var qr=qrcode(0,'M');qr.addData(v.export,'Byte');qr.make();
  var count=qr.getModuleCount(),scale=4,size=(count+8)*scale;
  canvas.width=canvas.height=size;var ctx=canvas.getContext('2d');
  ctx.fillStyle='#fff';ctx.fillRect(0,0,size,size);ctx.fillStyle='#000';
  for(var row=0;row<count;row++)for(var col=0;col<count;col++)if(qr.isDark(row,col))ctx.fillRect((col+4)*scale,(row+4)*scale,scale,scale);
  canvas.hidden=false;note.textContent='使用支持 AmneziaWG 的客户端扫码导入';
 }catch(e){note.textContent='配置较长或二维码组件不可用，请复制配置或下载 .conf 文件。';}
 v.export='';awgConfigScroll=document.body.style.overflow;document.body.style.overflow='hidden';
 awgEl('sv_config_modal').hidden=false;awgEl('sv_config_close').focus();
}
function awgConfigClose(){
 var modal=awgEl('sv_config_modal');if(!modal||modal.hidden)return;
 modal.hidden=true;awgEl('sv_config_text').value='';awgEl('sv_config_qr').width=awgEl('sv_config_qr').height=0;
 awgEl('sv_config_title').textContent='设备配置';awgEl('sv_config_feedback').textContent='';awgConfigFile='';
 document.body.style.overflow=awgConfigScroll;
 var target=awgConfigReturn&&awgConfigReturn.isConnected?awgConfigReturn:awgEl('sv_name');
 if(target&&!target.disabled)target.focus();awgConfigReturn=null;
}
function awgConfigCopy(){
 var text=awgEl('sv_config_text');if(!text.value)return;
 // ASUS management commonly uses HTTP, where Clipboard API is unavailable.
 text.focus();text.select();text.setSelectionRange(0,text.value.length);
 var copied=false;try{copied=document.execCommand('copy');}catch(e){}
 awgEl('sv_config_feedback').textContent=copied?'已复制配置':'配置已选中，请按 Ctrl+C 或长按复制。';
}
function awgConfigDownload(){
 if(awgEl('sv_config_text').value)awgServerDownload({export:awgEl('sv_config_text').value,filename:awgConfigFile});
}
function awgConfigKey(event){
 if(event.key==='Escape'){event.preventDefault();awgConfigClose();return;}
 if(event.key!=='Tab')return;
 var items=awgEl('sv_config_modal').querySelectorAll('button:not(:disabled), textarea');
 var first=items[0],last=items[items.length-1];
 if(event.shiftKey&&document.activeElement===first){event.preventDefault();last.focus();}
 else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first.focus();}
}
window.addEventListener('pagehide',awgConfigClose);
