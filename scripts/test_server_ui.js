'use strict';
const fs=require('fs'),vm=require('vm'),assert=require('assert'),path=require('path');
const nodes=new Map();let downloaded,revoked,blob;
function el(id){if(!nodes.has(id))nodes.set(id,{id,value:'',checked:false,type:['auto','allow_lan','internet','fullv'].some(k=>id==='sv_'+k)?'checkbox':'text',disabled:false});return nodes.get(id);}
const context={document:{getElementById:el,querySelectorAll:()=>[],body:{appendChild(){}},createElement:()=>({click(){downloaded={name:this.download,url:this.href};},remove(){}})},Blob:class{constructor(parts){blob=parts.join('');}},URL:{createObjectURL:()=> 'blob:test',revokeObjectURL:u=>revoked=u},setTimeout:fn=>fn(),console};vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(__dirname,'../plugin/res/amneziawg-server.js'),'utf8'),context);
context.awgEl=el;context.awgBusy=false;context.awgMessage=()=>{};
let request;context.awgRequest=(action,fields)=>request={action,fields};
el('sv_port').value='51830';el('sv_address').value='10.77.0.1/24';el('sv_endpoint_mode').value='auto';el('sv_allow_lan').checked=true;
context.awgServerSave();let s=JSON.parse(request.fields.amneziawg_payload);assert.equal(request.action,'server-save');assert.equal(s.port,51830);assert.equal(s.allow_lan,true);assert.equal(s.internet,false);
context.awgServer={configured:true,running:true,clients:[{}]};context.awgServerButtons();assert(el('sv_save').disabled);assert(!el('sv_add').disabled);assert(el('sv_start').disabled);assert(!el('sv_stop').disabled);
context.awgServer.running=false;context.awgServerButtons();assert(!el('sv_save').disabled);assert(!el('sv_add').disabled);assert(el('sv_endpoint').disabled);
request=null;context.awgServerDirty=true;context.awgServerAction('server-up');assert.equal(request,null);context.awgServerAction('server-export',{id:'1'});assert.equal(request,null);
let result={export:'[Interface]\nPrivateKey = test-only\n',filename:'amneziawg-1234567890abcdef.conf'};context.awgServerDownload(result);assert.equal(downloaded.name,result.filename);assert.equal(downloaded.url,'blob:test');assert.equal(revoked,'blob:test');assert(blob.includes('PrivateKey'));assert.equal(result.export,'');
const html=fs.readFileSync(path.join(__dirname,'../plugin/webs/Module_amneziawg.asp'),'utf8');for(const id of nodes.keys())assert(html.includes('id="'+id+'"'),'missing '+id);
assert(html.indexOf('/js/jquery.js')<html.indexOf('/state.js'));assert(html.includes('/require/require.min.js'));
console.log('PASS server settings, hot peer controls, settings locks, unsaved guards, configuration download and URL cleanup, firmware dependencies');
