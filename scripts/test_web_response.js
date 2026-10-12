'use strict';
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const elements=new Map();
function element(id){if(!elements.has(id))elements.set(id,{textContent:'',className:'',disabled:false,options:[],style:{},value:''});return elements.get(id);}
let ajax;
const context={document:{getElementById:element,querySelectorAll:()=>[]},$: {ajax: o=>{ajax=o;}},atob:s=>atob(s),btoa:s=>btoa(s),console};
vm.createContext(context);
vm.runInContext(fs.readFileSync(require('path').join(__dirname,'../plugin/res/amneziawg.js'),'utf8'),context);
const status={running:false,configured:false,settings:{mode:'tunnel',source:'',auto:false,profile:'',fallbacks:null,health_targets:null},peers:[],dns:[],version:'0.2.1',protected:false,guard_pending:false,profiles:[],health:{message:''}};
for(const message of ['状态已刷新','节点 "备用"\\路径\n错误\t说明','<script>alert(1)</script> 🌐']){
 const result={ok:true,message,status};const json=JSON.stringify(result);
 for(const wire of [JSON.stringify({result:'AWG64:'+Buffer.from(json).toString('base64')}),'{"result": "'+json+'"}',JSON.stringify({result:json}),JSON.stringify({result})]){
  assert.deepStrictEqual(JSON.parse(JSON.stringify(context.awgDecodeResponse(wire))),result);
  context.awgRequest('status',{},true);assert.equal(ajax.dataType,'text');ajax.success(wire);ajax.complete();
  assert.equal(element('awg_message').textContent,message);
  assert.equal(element('awg_state').textContent,'隧道已停止 · 断线保护未启用');
  assert.equal(element('awg_save').disabled,false);
  assert.equal(element('awg_start').disabled,true);
 }
}
context.awgRequest('status',{},true);ajax.success('<html>Login</html>');ajax.complete();
assert.equal(element('awg_state').textContent,'状态读取失败');assert.equal(element('awg_save').disabled,true);
context.awgSave();assert.match(element('awg_message').textContent,/请先成功读取状态/);
context.awgRequest('status',{},true);ajax.error({status:503},'error');ajax.complete();assert.match(element('awg_message').textContent,/HTTP 503/);
context.awgRequest('status',{},true);ajax.error({status:0},'timeout');ajax.complete();assert.match(element('awg_message').textContent,/请求超时/);
assert.throws(()=>context.awgDecodeResponse('{"result":"AWG64:***"}'));
assert.throws(()=>context.awgDecodeResponse('{"result":"{}"}'));
console.log('PASS base64 / legacy raw / escaped / object responses, Unicode and error-state UI');

const requestJSON=JSON.stringify({probe:'中文"引号"\\换行\n'});
const original={amneziawg_payload:requestJSON};
context.awgRequest('request-check',original,true);
const sent=JSON.parse(ajax.data).fields.amneziawg_payload;
assert.match(sent,/^AWGREQ64:[A-Za-z0-9+/]+=*$/);
assert.equal(Buffer.from(sent.slice(9),'base64').toString('utf8'),requestJSON);
assert.equal(original.amneziawg_payload,requestJSON);
console.log('PASS real AJAX request uses ASCII base64; Unicode, quotes, newline round-trip; caller fields unchanged');

ajax.complete();
let renders=0;context.awgRender=()=>renders++;
context.awgPollStatus('status',false);const stale=ajax;assert.equal(context.awgBusy,false,'poll must not lock actions');
context.awgRequest('server-add',{amneziawg_payload:JSON.stringify({name:'phone'})},true);const mutation=ajax;assert.equal(context.awgBusy,true);
stale.success(JSON.stringify({result:{ok:true,message:'old',status}}));stale.complete();assert.equal(renders,0,'old poll overwrote mutation');
mutation.success(JSON.stringify({result:{ok:true,message:'saved'}}));mutation.complete();assert.equal(context.awgBusy,false);
context.awgPollStatus('status',false);ajax.success(JSON.stringify({result:{ok:true,message:'fresh',status}}));ajax.complete();assert.equal(renders,1);
console.log('PASS background polling never locks buttons; stale poll response discarded across mutations');

context.awgPollStatus('status',false);const oldPage=ajax;
context.awgPollStatus('server-status',false);assert.equal(JSON.parse(ajax.data).params[0],'server-status','page change waited for old poll');
oldPage.success(JSON.stringify({result:{ok:true,message:'old page',status}}));oldPage.complete();assert.equal(renders,1);ajax.complete();
console.log('PASS page change replaces outstanding poll immediately');
