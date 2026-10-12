const fs=require('fs'),vm=require('vm'),assert=require('assert');
const nodes={};function el(id){return nodes[id]||(nodes[id]={textContent:'',disabled:false,checked:false,hidden:true,setAttribute(){},focus(){}});}
let request;const c={awgEl:el,awgBusy:false,document:{querySelectorAll:()=>[]},awgRequest:action=>request=action,awgMessage(){}};
vm.createContext(c);vm.runInContext(fs.readFileSync(__dirname+'/../plugin/res/amneziawg-core.js','utf8'),c);
let s={version:'0.5.0',arch:'arm64',plugin:'0.5.0',latest:'0.5.1',available:true,backup:'0.4.9',busy:false};
c.awgCoreRender(s);assert(!el('core_upgrade').disabled);c.awgCoreAsk('core-upgrade');assert(!el('core_confirmation').hidden);c.awgCoreConfirm();assert.equal(request,undefined);el('core_ack').checked=true;c.awgCoreConfirm();assert.equal(request,'core-upgrade');assert(el('core_confirmation').hidden);
request=null;c.awgCoreAsk('core-rollback');c.awgCoreCancel();el('core_ack').checked=true;c.awgCoreConfirm();assert.equal(request,null);
c.awgCoreAsk('core-upgrade');el('core_ack').checked=true;s.latest='0.5.2';c.awgCoreRender(s);c.awgCoreConfirm();assert.equal(request,null,'changed offer must be reconfirmed');
s.busy=true;c.awgCoreRender(s);assert(el('core_upgrade').disabled);assert(el('core_check').disabled);assert(el('core_confirmation').hidden);c.awgCoreAsk('core-upgrade');assert(el('core_confirmation').hidden);
s.busy=false;s.available=false;s.backup=s.version;c.awgCoreRender(s);assert(el('core_upgrade').disabled);assert(el('core_rollback').disabled);
console.log('PASS update confirmation, cancel, changed-version guard, busy state, no-update and same-version rollback');
