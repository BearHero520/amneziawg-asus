const fs=require('fs'),vm=require('vm'),assert=require('assert'),path=require('path');
class Node {
 constructor(id){this.id=id;this.value='';this.type='text';this.children=[];this.attributes={};this.disabled=false;this.classList={toggle(){}};}
 set textContent(v){this.text=v;this.children=[];} get textContent(){return this.text||'';}
 appendChild(n){this.children.push(n);}setAttribute(k,v){this.attributes[k]=v;}getAttribute(k){return this.attributes[k]??null;}focus(){}addEventListener(){}
}
const nodes=new Map();const el=id=>{if(!nodes.has(id))nodes.set(id,new Node(id));return nodes.get(id);};
let request,confirmation;
const c={document:{getElementById:el,createElement:()=>new Node(),querySelectorAll:()=>[]},awgEl:el,awgBusy:false,awgPendingAction:null,awgBytes:n=>n+' B',awgMessage(){},confirm:s=>{confirmation=s;return true;},awgRequest:(action,fields)=>request={action,fields},console};
vm.createContext(c);vm.runInContext(fs.readFileSync(path.join(__dirname,'../plugin/res/amneziawg-server.js'),'utf8'),c);
const s={configured:true,running:true,pending:false,settings:{},clients:[{id:'a',name:'<img onerror=evil()>',address:'10.77.0.2/32',disabled:false,rx:10,tx:20}]};
c.awgServerRender(s);assert(!el('sv_add').disabled);assert(el('sv_save').disabled);assert.equal(el('sv_clients').children[0].children[0].textContent,s.clients[0].name);
const row=el('sv_clients').children[0];s.clients[0].rx=33;c.awgServerRender(s);assert.strictEqual(el('sv_clients').children[0],row,'poll rebuilt focused peer buttons');assert.equal(row.children[3].textContent,'33 B / 20 B');
row.children[4].children[2].onclick();assert.equal(request.action,'server-disable');assert.equal(JSON.parse(request.fields.amneziawg_payload).id,'a');assert(confirmation.includes('仅该设备'));
s.clients[0].disabled=true;c.awgServerRender(s);assert.equal(el('sv_clients').children[0].children[2].textContent,'已禁用');el('sv_clients').children[0].children[4].children[2].onclick();assert.equal(request.action,'server-enable');
s.running=false;c.awgServerRender(s);assert(el('sv_start').disabled,'all disabled peers cannot start');s.pending=true;c.awgServerRender(s);assert(el('sv_add').disabled,'pending transaction must block writes');
c.awgBusy=true;c.awgServerButtons();assert(el('sv_add').disabled);
vm.runInContext(fs.readFileSync(path.join(__dirname,'../plugin/res/amneziawg-logs.js'),'utf8'),c);
c.awgLogsRender({ok:true,logs:[{time:1234,ok:false,action:'测试',message:'失败'}]},'logs');assert(el('awg_logs').value.includes('失败'));
c.awgLogsRender({ok:true,diagnostics:[{name:'DNS',state:'fail',detail:'<script>test</script>'}]},'diagnose');assert.equal(el('awg_diagnostics').children[0].children[2].textContent,'<script>test</script>');assert(c.awgLogReport().includes('DNS'));
console.log('PASS stable peer rows, safe names, target disable/enable, pending locks, all-disabled start guard, logs and diagnosis rendering');
