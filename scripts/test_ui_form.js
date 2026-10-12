'use strict';
const fs=require('fs'),vm=require('vm'),assert=require('assert'),path=require('path');
const nodes=new Map(),extras=['Jc','Jmin','Jmax','H1','I1','HeaderProtectionKey','RandomTrailers'];
function el(id){if(!nodes.has(id))nodes.set(id,{id,value:'',textContent:'',getAttribute:()=>id.replace('awg_extra_','')});return nodes.get(id);}
const context={document:{getElementById:el,querySelectorAll:selector=>selector==='[data-awg-extra]'?extras.map(k=>el('awg_extra_'+k)):[]},atob,btoa,console};
vm.createContext(context);vm.runInContext(fs.readFileSync(path.join(__dirname,'../plugin/res/amneziawg.js'),'utf8'),context);vm.runInContext(fs.readFileSync(path.join(__dirname,'../plugin/res/amneziawg-ui.js'),'utf8'),context);
function values(){const v={awg_name:'测试节点',awg_host:'vpn.example.com',awg_port:'51820',awg_address:'10.8.0.2/32',awg_private:Buffer.alloc(32,1).toString('base64'),awg_public:Buffer.alloc(32,2).toString('base64'),awg_allowed:'0.0.0.0/0',awg_keepalive:'25'};Object.entries(v).forEach(([id,value])=>el(id).value=value);}
values();let conf=context.awgFormConfig();assert.match(conf,/Endpoint = vpn.example.com:51820/);assert.match(conf,/Address = 10.8.0.2\/32/);assert(!conf.includes('DNS ='));
el('awg_host').value='2001:db8::10';el('awg_form_dns').value='1.1.1.1, 2606:4700:4700::1111';el('awg_extra_Jc').value='4';el('awg_extra_H1').value='10-20';conf=context.awgFormConfig();assert.match(conf,/Endpoint = \[2001:db8::10\]:51820/);assert.match(conf,/Jc = 4/);assert.match(conf,/H1 = 10-20/);
for(const [id,value] of [['awg_host','https://vpn.example.com'],['awg_host','vpn.example.com\nPostUp = evil'],['awg_port','70000'],['awg_address','10.0.0.2/32\n[Peer]'],['awg_extra_I1','hello\nPrivateKey = fake'],['awg_private','bad-key']]){
 const old=el(id).value;el(id).value=value;assert.throws(()=>context.awgFormConfig(),id);el(id).value=old;
}
let request;context.awgRequest=(action,fields)=>{request={action,fields};};context.awgImport();assert.equal(request.action,'import');assert.equal(Buffer.from(JSON.parse(request.fields.amneziawg_payload).config,'base64').toString('utf8'),context.awgFormConfig());
context.awgEntryMode='file';el('awg_config').value=conf;context.awgImport();assert.equal(Buffer.from(JSON.parse(request.fields.amneziawg_payload).config,'base64').toString('utf8'),conf);
context.awgClearImport();assert.equal(el('awg_private').value,'');assert.equal(el('awg_config').value,'');assert.equal(el('awg_extra_Jc').value,'');assert.equal(el('awg_port').value,'51820');
const html=fs.readFileSync(path.join(__dirname,'../plugin/webs/Module_amneziawg.asp'),'utf8');const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]);assert.equal(new Set(ids).size,ids.length,'duplicate IDs');for(const id of nodes.keys())assert(ids.includes(id),'missing element '+id);
console.log('PASS guided form, IPv6 endpoint, advanced fields, key validation, injection rejection, file mode, secret clearing, HTML IDs');
