// helpers
const $ = (sel) => document.querySelector(sel);
const enc = new TextEncoder();
const dec = new TextDecoder();
const toHex = (buf) => [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,'0')).join('');
function toB64(bytes){ return btoa(String.fromCharCode(...bytes)); }
function fromB64(b64){ const s = atob(b64); return new Uint8Array([...s].map(ch=>ch.charCodeAt(0))); }

// theme
const root = document.documentElement;
const themeBtns = { auto: $("#theme-auto"), light: $("#theme-light"), dark: $("#theme-dark") };
function setPressed(which){ Object.values(themeBtns).forEach(b=>b.setAttribute('aria-pressed','false')); themeBtns[which].setAttribute('aria-pressed','true'); }
function applyTheme(mode){
  if(mode==='light'){ root.classList.add('light'); setPressed('light'); localStorage.setItem('theme','light'); }
  else if(mode==='dark'){ root.classList.remove('light'); setPressed('dark'); localStorage.setItem('theme','dark'); }
  else { localStorage.setItem('theme','auto'); const mql = matchMedia('(prefers-color-scheme: light)'); if(mql.matches) root.classList.add('light'); else root.classList.remove('light'); setPressed('auto'); }
}
themeBtns.auto.addEventListener('click',()=>applyTheme('auto'));
themeBtns.light.addEventListener('click',()=>applyTheme('light'));
themeBtns.dark.addEventListener('click',()=>applyTheme('dark'));
applyTheme(localStorage.getItem('theme') || 'auto');

// tabs
const tabs = document.querySelectorAll('.tab');
const panels = document.querySelectorAll('.panel');
tabs.forEach(tab => tab.addEventListener('click', () => {
  tabs.forEach(t=>{t.classList.remove('active'); t.setAttribute('aria-selected','false');});
  tab.classList.add('active'); tab.setAttribute('aria-selected','true');
  panels.forEach(p=>p.classList.remove('active'));
  const target = document.getElementById('panel-'+tab.dataset.tab);
  target.classList.add('active');
  window.scrollTo({top:0, behavior:'smooth'});
}));

// DES (Feistel demo)
(function(){
  const keyEl = $("#des-key"), ptEl = $("#des-pt"), ctEl = $("#des-ct"), dtEl = $("#des-dt");
  function deriveSubkeys(keyBytes){
    const subs=[], rounds=16; let state=0x9e3779b9;
    for(let r=0;r<rounds;r++){
      let acc = state>>>0; for(const b of keyBytes){ acc = (acc ^ ((acc<<5)+b+(acc>>>2)))>>>0; }
      subs.push(acc>>>0); state = (acc ^ (acc<<13) ^ (acc>>>7))>>>0;
    } return subs;
  }
  function F(x,k){ let v=(x^k)>>>0; const S=[0xE,4,0xD,1,2,0xF,0xB,8,3,0xA,6,0xC,5,9,0,7]; let out=0;
    for(let i=0;i<8;i++){ const nib=(v>>> (i*4))&0xF; out |= (S[nib]<<(i*4)); } return ((out<<3)|(out>>>29))>>>0; }
  function blockCrypt8(bytes, subs, decrypt=false){
    const dv=new DataView(bytes.buffer, bytes.byteOffset, 8);
    let L=dv.getUint32(0,false), R=dv.getUint32(4,false);
    for(let i=0;i<16;i++){ const sk=subs[decrypt?(15-i):i]; const t=(F(R,sk)^L)>>>0; L=R; R=t; }
    const out=new Uint8Array(8); const dv2=new DataView(out.buffer); dv2.setUint32(0,R,false); dv2.setUint32(4,L,false); return out;
  }
  function padPKCS7(u8){ let pad=8-(u8.length%8); if(pad===0) pad=8; const out=new Uint8Array(u8.length+pad); out.set(u8,0); out.fill(pad,u8.length); return out; }
  function unpadPKCS7(u8){ if(!u8.length) return u8; const pad=u8[u8.length-1]; if(pad<1||pad>8) return u8; return u8.slice(0,u8.length-pad); }
  function encrypt(){ const key=enc.encode(keyEl.value||''); const subs=deriveSubkeys(key);
    const msg=enc.encode(ptEl.value||''); const padded=padPKCS7(msg); const out=new Uint8Array(padded.length);
    for(let i=0;i<padded.length;i+=8){ out.set(blockCrypt8(padded.slice(i,i+8), subs, false), i); }
    ctEl.value = toB64(out); dtEl.value=''; }
  function decrypt(){ const key=enc.encode(keyEl.value||''); const subs=deriveSubkeys(key); const c=ctEl.value.trim(); if(!c){dtEl.value=''; return;}
    const bytes=fromB64(c); const out=new Uint8Array(bytes.length);
    for(let i=0;i<bytes.length;i+=8){ out.set(blockCrypt8(bytes.slice(i,i+8), subs, true), i); }
    dtEl.value = dec.decode(unpadPKCS7(out)); }
  $("#des-encrypt").addEventListener('click', encrypt);
  $("#des-decrypt").addEventListener('click', decrypt);
  $("#des-clear").addEventListener('click', ()=>{ ptEl.value=''; ctEl.value=''; dtEl.value=''; });
})();

// RSA
(function(){
  let keyPair=null;
  async function gen(){ keyPair=await crypto.subtle.generateKey({name:"RSA-OAEP", modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:"SHA-256"}, true, ["encrypt","decrypt"]); alert("RSA keys generated"); }
  async function exportKeys(){ if(!keyPair) return alert("Generate keys first"); const pub=await crypto.subtle.exportKey("jwk", keyPair.publicKey); const priv=await crypto.subtle.exportKey("jwk", keyPair.privateKey); $("#rsa-jwk").value = JSON.stringify({public:pub, private:priv}, null, 2); }
  async function encrypt(){ if(!keyPair) return alert("Generate or import keys first"); const data=enc.encode($("#rsa-pt").value||''); const ct=new Uint8Array(await crypto.subtle.encrypt({name:"RSA-OAEP"}, keyPair.publicKey, data)); $("#rsa-ct").value = toB64(ct); $("#rsa-dt").value=''; }
  async function decrypt(){ if(!keyPair) return alert("Generate or import keys first"); try{ const c=fromB64($("#rsa-ct").value.trim()); const p=await crypto.subtle.decrypt({name:"RSA-OAEP"}, keyPair.privateKey, c); $("#rsa-dt").value = dec.decode(p); }catch(e){ $("#rsa-dt").value = "Decryption failed: "+e.message; } }
  function clearAll(){ $("#rsa-pt").value=''; $("#rsa-ct").value=''; $("#rsa-dt").value=''; $("#rsa-jwk").value=''; }
  $("#rsa-gen").addEventListener('click', gen);
  $("#rsa-export").addEventListener('click', exportKeys);
  $("#rsa-encrypt").addEventListener('click', encrypt);
  $("#rsa-decrypt").addEventListener('click', decrypt);
  $("#rsa-clear").addEventListener('click', clearAll);
})();

// ECDH + AES-GCM
(function(){
  let alice=null, bob=null, sharedKey=null, iv=null;
  async function genAlice(){ alice=await crypto.subtle.generateKey({name:"ECDH", namedCurve:"P-256"}, true, ["deriveKey","deriveBits"]); $("#dh-alice-pub").value = JSON.stringify(await crypto.subtle.exportKey("jwk", alice.publicKey), null, 2); }
  async function genBob(){ bob=await crypto.subtle.generateKey({name:"ECDH", namedCurve:"P-256"}, true, ["deriveKey","deriveBits"]); $("#dh-bob-pub").value = JSON.stringify(await crypto.subtle.exportKey("jwk", bob.publicKey), null, 2); }
  async function derive(){ if(!alice||!bob) return alert("Generate Alice and Bob keys first"); const bobPub=await crypto.subtle.importKey("jwk", JSON.parse($("#dh-bob-pub").value), {name:"ECDH", namedCurve:"P-256"}, true, []); sharedKey=await crypto.subtle.deriveKey({name:"ECDH", public:bobPub}, alice.privateKey, {name:"AES-GCM", length:256}, false, ["encrypt","decrypt"]); const bits=await crypto.subtle.deriveBits({name:"ECDH", public:bobPub}, alice.privateKey, 256); $("#dh-secret").value = toB64(new Uint8Array(bits)); iv = crypto.getRandomValues(new Uint8Array(12)); }
  async function encrypt(){ if(!sharedKey) return alert("Derive the shared secret first"); const data=enc.encode($("#dh-msg").value||''); const c=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM", iv}, sharedKey, data)); $("#dh-ct").value = toB64(c); $("#dh-dt").value=''; }
  async function decrypt(){ if(!sharedKey) return alert("Derive the shared secret first"); try{ const c=fromB64($("#dh-ct").value.trim()); const p=new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM", iv}, sharedKey, c)); $("#dh-dt").value = dec.decode(p); }catch(e){ $("#dh-dt").value = "Decryption failed: "+e.message; } }
  function clearAll(){ $("#dh-msg").value=''; $("#dh-ct").value=''; $("#dh-dt").value=''; $("#dh-secret").value=''; }
  $("#dh-alice-gen").addEventListener('click', genAlice);
  $("#dh-bob-gen").addEventListener('click', genBob);
  $("#dh-derive").addEventListener('click', derive);
  $("#dh-encrypt").addEventListener('click', encrypt);
  $("#dh-decrypt").addEventListener('click', decrypt);
  $("#dh-clear").addEventListener('click', clearAll);
})();

// ElGamal (educational)
(function(){
  const defaultP="FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
  const defaultG="05";
  const txtP=$("#elg-p"), txtG=$("#elg-g"), txtY=$("#elg-y"), txtX=$("#elg-x");
  const PT=$("#elg-pt"), CT=$("#elg-ct"), DT=$("#elg-dt");
  let p,g,x,y;
  const hexToBigInt=h=>BigInt("0x"+h.trim());
  function modPow(b,e,m){ let r=1n%m, base=b%m, exp=e; while(exp>0n){ if(exp&1n) r=(r*base)%m; base=(base*base)%m; exp>>=1n;} return r; }
  function modInv(a,m){ let t=0n,nT=1n,r=m,nR=a%m; while(nR){ const q=r/nR; [t,nT]=[nT,t-q*nT]; [r,nR]=[nR,r-q*nR]; } if(r>1n) throw new Error("not invertible"); if(t<0n) t+=m; return t; }
  function ensureParams(){ p=hexToBigInt((txtP.value&&txtP.value.trim())||defaultP); g=hexToBigInt((txtG.value&&txtG.value.trim())||defaultG); txtP.value=p.toString(16); txtG.value=g.toString(16); }
  function strToBlocks(s){ const bytes=enc.encode(s); let hex=[...bytes].map(b=>b.toString(16).padStart(2,'0')).join(''); const maxHexLen = p.toString(16).length - 2; const blocks=[]; for(let i=0;i<hex.length;i+=maxHexLen){ blocks.push(BigInt("0x"+(hex.slice(i,i+maxHexLen)||"0"))); } return blocks; }
  function blocksToStr(blocks){ let hex=blocks.map(b=>b.toString(16)).join(''); if(hex.length%2) hex='0'+hex; const out=new Uint8Array(hex.length/2); for(let i=0;i<out.length;i++) out[i]=parseInt(hex.substr(i*2,2),16); return dec.decode(out); }
  function gen(){ ensureParams(); const rand=crypto.getRandomValues(new Uint8Array(28)); const hex=[...rand].map(b=>b.toString(16).padStart(2,'0')).join(''); x=(BigInt("0x"+hex)%(p-2n))+1n; y=modPow(g,x,p); txtX.value=x.toString(16); txtY.value=y.toString(16); }
  function encrypt(){ ensureParams(); if(!y) return alert("Generate key first"); const blocks=strToBlocks(PT.value||''); const kBytes=crypto.getRandomValues(new Uint8Array(28)); const k=(BigInt("0x"+[...kBytes].map(b=>b.toString(16).padStart(2,'0')).join(''))%(p-2n))+1n; const c1=modPow(g,k,p); const yk=modPow(y,k,p); const c2Blocks=blocks.map(m=>(m*yk)%p); const payload={ c1:c1.toString(16), blocks:c2Blocks.map(b=>b.toString(16)) }; CT.value=btoa(unescape(encodeURIComponent(JSON.stringify(payload)))); DT.value=''; }
  function decrypt(){ ensureParams(); if(!x) return alert("Generate key first"); try{ const payload=JSON.parse(decodeURIComponent(escape(atob(CT.value.trim())))); const s=modPow(BigInt("0x"+payload.c1), x, p); const sInv=modInv(s,p); const blocks=payload.blocks.map(h=>(BigInt("0x"+h)*sInv)%p); DT.value = blocksToStr(blocks); }catch(e){ DT.value="Decryption failed: "+e.message; } }
  function clearAll(){ PT.value=''; CT.value=''; DT.value=''; }
  $("#elg-gen").addEventListener('click', gen);
  $("#elg-encrypt").addEventListener('click', encrypt);
  $("#elg-decrypt").addEventListener('click', decrypt);
  $("#elg-clear").addEventListener('click', clearAll);
  txtP.value=defaultP; txtG.value=defaultG;
})();

// SHA
(function(){
  async function hash(){ const algo=$("#sha-algo").value; const data=enc.encode($("#sha-input").value||''); const digest=await crypto.subtle.digest(algo, data); $("#sha-output").value = toHex(digest); }
  $("#sha-hash").addEventListener('click', hash);
  $("#sha-clear").addEventListener('click', ()=>{ $("#sha-input").value=''; $("#sha-output").value=''; });
})();
