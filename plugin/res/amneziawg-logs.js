/* SPDX-License-Identifier: MIT */
var awgLogText='',awgDiagnosticText='';
function awgLogsRender(v,action){
 if(action==='logs'&&v.ok){
  awgLogText=(v.logs||[]).map(function(e){return new Date(e.time*1000).toLocaleString()+'  '+(e.ok?'成功':'失败')+'  '+e.action+' · '+e.message;}).reverse().join('\n');
  awgEl('awg_logs').value=awgLogText||'暂无操作记录。升级前的操作不会补记。';
 }
 if(action==='diagnose'&&v.ok){
  var body=awgEl('awg_diagnostics');body.textContent='';
  var labels={pass:'通过',warn:'需确认',fail:'异常',skip:'未检查'};
  awgDiagnosticText='诊断时间：'+new Date().toLocaleString()+'\n'+(v.diagnostics||[]).map(function(d){return (labels[d.state]||'未知')+'  '+d.name+' · '+d.detail;}).join('\n');
  (v.diagnostics||[]).forEach(function(d){var tr=document.createElement('tr');[d.name,labels[d.state]||'未知',d.detail].forEach(function(t,i){var td=document.createElement('td');td.textContent=t;if(i===1)td.className='diagnostic-'+d.state;tr.appendChild(td);});body.appendChild(tr);});
  awgEl('awg_diag_time').textContent='检查时间：'+new Date().toLocaleString()+'（不会自动重复检查）';
 }
}
function awgLogReport(){return 'AmneziaWG 0.4.0 日志与诊断\n\n'+(awgLogText||'暂无操作日志')+'\n\n'+(awgDiagnosticText||'尚未执行诊断')+'\n';}
function awgLogsDownload(){var url=URL.createObjectURL(new Blob([awgLogReport()],{type:'text/plain;charset=utf-8'})),a=document.createElement('a');a.href=url;a.download='amneziawg-diagnostics.txt';document.body.appendChild(a);a.click();a.remove();setTimeout(function(){URL.revokeObjectURL(url);},1000);}
function awgLogsCopy(){
 var el=awgEl('awg_logs'),old=el.value;el.value=awgLogReport();el.focus();el.select();
 var ok=false;try{ok=document.execCommand('copy');}catch(e){}el.value=old;
 awgMessage(ok?'日志与诊断已复制。':'复制失败，请使用下载按钮。',!ok);
}
