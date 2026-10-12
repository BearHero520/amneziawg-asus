// Local synthetic data only; no router keys or external QR service.
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const nodes=new Map();let pixels,focused,copied,downloaded;
function el(id){if(!nodes.has(id))nodes.set(id,{hidden:true,value:'',width:0,height:0,disabled:false,isConnected:true,focus(){focused=this;},select(){},setSelectionRange(){},getContext(){const c=this;pixels=new Uint8ClampedArray(c.width*c.height*4);return {fillStyle:'#fff',fillRect(x,y,w,h){const v=this.fillStyle==='#fff'?255:0;for(let r=y;r<y+h;r++)for(let col=x;col<x+w;col++){let i=(r*c.width+col)*4;pixels[i]=pixels[i+1]=pixels[i+2]=v;pixels[i+3]=255;}}};}});return nodes.get(id);}
const c={console,window:{addEventListener(){}},document:{body:{style:{overflow:'auto'}},execCommand(){copied=el('sv_config_text').value;return true;}},awgEl:el,awgBusy:false,awgServerDirty:false,awgMessage(){},awgServerAction(){},awgServerDownload(v){downloaded=v.export;v.export='';}};
vm.createContext(c);vm.runInContext(fs.readFileSync('plugin/res/amneziawg-qrcode.js','utf8'),c);vm.runInContext(fs.readFileSync('plugin/res/amneziawg-config.js','utf8'),c);
const config='# 测试手机\n[Interface]\nPrivateKey = '+ 'A'.repeat(43)+'=\nAddress = 10.77.0.2/32\nDNS = 192.168.50.2\nJc = 4\n\n[Peer]\nPublicKey = '+'B'.repeat(43)+'=\nEndpoint = vpn.example.com:51830\nAllowedIPs = 0.0.0.0/0\n';
c.awgConfigOpen('id','<我的手机>',el('trigger'));let v={export:config,filename:'amneziawg-client.conf'};c.awgConfigResult(v);
assert.equal(el('sv_config_text').value,config);assert.equal(v.export,'');assert(!el('sv_config_modal').hidden);assert(!el('sv_config_qr').hidden);assert.equal(el('sv_config_title').textContent,'<我的手机> · 设备配置');
// Optional independent decoder, installed under work/ only for release QA.
if(fs.existsSync('work/test-deps/jsQR.js')){const decode=require('../work/test-deps/jsQR.js');const out=decode(pixels,el('sv_config_qr').width,el('sv_config_qr').height);assert(out);assert.equal(out.data,config);console.log('PASS independent QR decode: UTF-8 config bytes preserved');}
c.awgConfigCopy();assert.equal(copied,config);c.awgConfigDownload();assert.equal(downloaded,config);assert.equal(el('sv_config_text').value,config);
c.awgConfigClose();assert(el('sv_config_modal').hidden);assert.equal(el('sv_config_text').value,'');assert.equal(el('sv_config_qr').width,0);assert.equal(c.document.body.style.overflow,'auto');assert.equal(focused,el('trigger'));
c.awgConfigOpen('id','long',el('trigger'));v={export:'x'.repeat(5000)};c.awgConfigResult(v);assert(el('sv_config_qr').hidden);assert.equal(el('sv_config_text').value.length,5000);assert(el('sv_config_qr_note').textContent.includes('复制'));c.awgConfigClose();
c.awgBusy=true;c.awgConfigOpen('id','busy',el('trigger'));assert.equal(c.awgConfigPending,null);c.awgBusy=false;c.awgServerDirty=true;c.awgConfigOpen('id','dirty',el('trigger'));assert.equal(c.awgConfigPending,null);
c.awgServerDirty=false;c.awgConfigOpen('id','fail',el('trigger'));c.awgConfigComplete();assert.equal(c.awgConfigPending,null);c.awgConfigResult({export:config});assert.equal(downloaded,config);assert(el('sv_config_modal').hidden);
console.log('PASS config preview, copying, download, close secret cleanup, over-capacity fallback and failed/busy request isolation');
