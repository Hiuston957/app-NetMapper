function scanTarget(){return ($('#custom-cidr').value||'').trim() || $('#cidr').value}
const $=s=>document.querySelector(s),esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));let physical=false, confirmedEdges=[], devices=[],cidr='',zoom=1,pan={x:0,y:0},mapCtl=null,mapUnlocked=false;$('#theme').onclick=()=>document.documentElement.classList.toggle('light');
function links(d){return(d.web_panels||[]).map(p=>`<a class="panel-link" target="_blank" rel="noopener noreferrer" href="${esc(p.url)}">↗ ${esc(p.service)} :${p.port}</a>`).join('')||'—'}
function terminalAction(d){const ports=(d.ports||[]).filter(p=>p.port===22||p.port===23||/ssh|telnet/i.test(p.service||''));return ports.map(p=>{const protocol=(p.port===23||/telnet/i.test(p.service||''))?'telnet':'ssh';return `<button class="terminal-connect" data-protocol="${protocol}" data-ip="${esc(d.ip)}" data-port="${Number(p.port)}">▣ Terminal ${protocol.toUpperCase()} :${Number(p.port)}</button>`}).join('')}
async function launchTerminal(ip,port,protocol){
  openWebTerminal(ip,port,protocol);
}
document.addEventListener('click',e=>{let b=e.target.closest('.terminal-connect');if(b)launchTerminal(b.dataset.ip,Number(b.dataset.port),b.dataset.protocol)});
function details(d){$('#details').innerHTML=`<strong>${esc(d.hostname&&d.hostname!=='Nieznany'?d.hostname:d.ip)}</strong><div class="detailrow">IP: <b>${esc(d.ip)}</b></div><div class="detailrow">MAC: <b>${esc(d.mac)}</b></div><div class="detailrow">Producent MAC: <b>${esc(d.vendor)}</b></div><div class="detailrow">Rozpoznane urządzenie: <b>${esc(d.identified_vendor||"Nieustalone")}</b> (${esc(d.identification_method||"brak")}, ${esc(d.identification_confidence||"brak")})</div><div class="detailrow">HTTP: ${(d.fingerprint?.http||[]).map(h=>`<span class="pill">:${h.port} ${esc(h.title||h.headers?.server||"HTTP "+h.status)}</span>`).join("")||"brak"}</div><div class="detailrow">Banery: ${(d.fingerprint?.banners||[]).map(h=>`<span class="pill">:${h.port} ${esc(h.banner)}</span>`).join("")||"brak"}</div><div class="detailrow">Producent: <b>${esc(d.identified_vendor||d.vendor)} </b></div><div class="detailrow">Typ: <b>${esc(d.type)}</b></div><div class="detailrow">Dodatkowo sprawdzone porty: <b>${d.vendor_ports_checked||0}</b></div><div class="detailrow">Profile: <b>${esc((d.vendor_profiles||[]).join(', ')||'brak')}</b></div><div class="detailrow">Otwarte porty: ${(d.ports||[]).map(p=>`<span class="pill">${p.port} ${esc(p.service)}${p.vendor_specific?' ★':''}</span>`).join('')||'brak'}</div><div class="detailrow">Panele WWW:<br>${links(d)}</div><div class="detailrow">Terminal SSH / Telnet:<br>${terminalAction(d)||"Brak wykrytego SSH / Telnet"}</div>`}
let inventoryRenderKey=null;
function render(){let q=$('#filter').value.toLowerCase(),arr=devices.filter(d=>[d.ip,d.hostname,d.mac,d.vendor,d.identified_vendor,d.type,(d.ports||[]).map(p=>p.port+' '+p.service).join(' ')].some(s=>String(s||'').toLowerCase().includes(q)));$('#count').textContent=devices.length;const inventoryKey=JSON.stringify(arr);const inventoryWrap=document.querySelector('.tablewrap');const oldScroll=inventoryWrap?.scrollTop||0;if(inventoryKey!==inventoryRenderKey){inventoryRenderKey=inventoryKey;$('#rows').innerHTML=arr.map(d=>`<tr><td><span class="ip">${esc(d.ip)}</span><small>${esc(d.hostname)}</small></td><td>${esc(d.identified_vendor||d.vendor)}<small>${esc(d.mac)}</small></td><td>${esc(d.type)}</td><td>${(d.ports||[]).map(p=>`<span class="pill" title="${p.vendor_specific?'Port producenta':'Port standardowy'}">${p.port}${p.vendor_specific?' ★':''}</span>`).join('')||'—'}</td><td>${links(d)} ${terminalAction(d)}</td></tr>`).join('')||'<tr><td colspan="5">Brak urządzeń</td></tr>';if(inventoryWrap)inventoryWrap.scrollTop=Math.min(oldScroll,Math.max(0,inventoryWrap.scrollHeight-inventoryWrap.clientHeight));}draw(arr)}$('#filter').oninput=render;
async function init(){try{let nets=await(await fetch('/api/interfaces')).json();$('#cidr').innerHTML=nets.map(n=>`<option value="${esc(n.cidr)}">${esc(n.cidr)} (${esc(n.interface)})</option>`).join('');let d=await(await fetch('/api/results')).json();devices=d.devices||[];confirmedEdges=d.edges||[];cidr=d.cidr||$('#cidr').value;render()}catch(e){$('#message').textContent=e.message}}init();
let scanPollTimer=null;
let scanPollGeneration=0;
let lastScanTarget=localStorage.getItem('netmapper-last-target')||'';
function setScanning(running){$('#scan').disabled=running;$('#stop-scan').disabled=!running;$('#rescan').disabled=running;}
async function beginScan(target){
  target=(target||'').trim();
  if(!target){$('#message').textContent='Wybierz podsieć lub wpisz zakres adresów IP.';return;}
  try{
    let r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cidr:target})}),d=await r.json();
    if(!r.ok)throw Error(d.error||'Nie można uruchomić skanowania.');
    lastScanTarget=target;localStorage.setItem('netmapper-last-target',target);
    cidr=target;devices=[];confirmedEdges=[];render();setScanning(true);
    $('#progress').textContent='0%';$('#phase').textContent='Uruchamianie';$('#state').textContent='Skanowanie';
    $('#message').textContent='Skanowany zakres: '+target;
    clearTimeout(scanPollTimer);const generation=++scanPollGeneration;poll(generation);
  }catch(e){$('#message').textContent=e.message;}
}
$('#scan').onclick=()=>beginScan(scanTarget());
$('#rescan').onclick=()=>beginScan(lastScanTarget||scanTarget());
$('#stop-scan').onclick=async()=>{
  $('#stop-scan').disabled=true;
  try{
    let r=await fetch('/api/scan/stop',{method:'POST'}),d=await r.json();
    if(!r.ok)throw Error(d.error||'Nie udało się zatrzymać skanowania.');
    clearTimeout(scanPollTimer);++scanPollGeneration;setScanning(false);
    $('#state').textContent='Zatrzymano';$('#phase').textContent='Zatrzymano przez użytkownika';
    $('#message').textContent='Skanowanie zatrzymane. Możesz uruchomić ponowny skan.';
  }catch(e){$('#message').textContent=e.message;setScanning(true);}
};
async function poll(generation){
  if(generation!==scanPollGeneration)return;
  try{
    let response=await fetch('/api/status');if(!response.ok)throw Error('Błąd odczytu statusu skanowania');
    let d=await response.json();if(generation!==scanPollGeneration)return;
    $('#progress').textContent=d.total?Math.round(d.progress/d.total*100)+'%':'0%';
    $('#phase').textContent=d.phase||'Gotowe';
    $('#state').textContent=d.running?'Skanowanie':d.error?'Błąd':d.phase==='Zatrzymano przez użytkownika'?'Zatrzymano':'Gotowe';
    setScanning(!!d.running);
    if(d.running){scanPollTimer=setTimeout(()=>poll(generation),800)}
    else{devices=d.devices||[];confirmedEdges=d.edges||[];render();loadHistory();$('#message').textContent=d.error||`Zakończono ${d.finished||''}`}
  }catch(e){if(generation!==scanPollGeneration)return;$('#message').textContent=e.message;scanPollTimer=setTimeout(()=>poll(generation),1800)}
}
// Restore controls and active scan after a page reload.
(async()=>{try{const d=await(await fetch('/api/status')).json();setScanning(!!d.running);if(d.running){const generation=++scanPollGeneration;poll(generation)}}catch(e){setScanning(false)}})();
$('#export').onclick=async()=>{let d=await(await fetch('/api/results')).json(),u=URL.createObjectURL(new Blob([JSON.stringify(d,null,2)],{type:'application/json'})),a=document.createElement('a');a.href=u;a.download='netmapper.json';a.click();setTimeout(()=>URL.revokeObjectURL(u),1000)};
function draw(items){let root=$('#map');if(physical){root.innerHTML='<div class="empty">'+(confirmedEdges.length?'Połączenia potwierdzone: '+confirmedEdges.length:'Nie wykryto potwierdzonych połączeń fizycznych — bez LLDP/SNMP nie można ich wiarygodnie ustalić.')+'</div>';return;}root.innerHTML='';root.classList.toggle('map-unlocked',mapUnlocked);updateMapLockUI();if(!items.length){root.innerHTML='<div class="empty">Brak urządzeń — rozpocznij skanowanie</div>';return}let w=Math.max(root.clientWidth,320),h=root.clientHeight,n=items.length,cols=Math.max(1,Math.ceil(Math.sqrt(n/1.8))),rows=Math.ceil(n/cols),dx=244,dy=106,stageW=Math.max(500,cols*dx+220),stageH=175+rows*dy,ns='http://www.w3.org/2000/svg';function el(tag,attrs,parent){let e=document.createElementNS(ns,tag);Object.entries(attrs||{}).forEach(([k,v])=>e.setAttribute(k,v));parent?.appendChild(e);return e}let svg=el('svg',{viewBox:`0 0 ${w} ${h}`},root),stage=el('g',{},svg),lines=el('g',{class:'links'},stage),nodes=el('g',{},stage),cx=stageW/2;let net=el('g',{class:'network',transform:`translate(${cx-105},25)`},nodes);el('rect',{width:210,height:65,rx:12},net);let t=el('text',{x:16,y:27},net);t.textContent='◈  SIEĆ LOKALNA';t=el('text',{x:16,y:47,class:'sub'},net);t.textContent=cidr||'Podsieć';items.forEach((d,i)=>{let col=i%cols,row=Math.floor(i/cols),x=(stageW-cols*dx)/2+col*dx,y=175+row*dy;el('path',{d:`M ${cx} 90 V 117 H ${x+105} V ${y}`},lines);el('circle',{cx:x+105,cy:y,r:3},lines);let g=el('g',{class:'host',transform:`translate(${x},${y})`,tabindex:0,role:'button'},nodes);el('rect',{width:210,height:79,rx:11},g);let icon=el('text',{x:13,y:32,class:'icon'},g);icon.textContent=/kamera|camera|dahua|hikvision|axis/i.test((d.vendor||'')+' '+d.type)?'◉':/nas|synology|qnap/i.test((d.vendor||'')+' '+d.type)?'▤':'▣';let title=el('text',{x:44,y:28,class:'title'},g);title.textContent=(d.hostname&&d.hostname!=='Nieznany'?d.hostname:d.ip).slice(0,22);let sub=el('text',{x:44,y:47,class:'subtitle'},g);sub.textContent=d.ip;sub=el('text',{x:13,y:67,class:'subtitle'},g);sub.textContent=(d.identified_vendor||d.vendor||'Nieznany producent').slice(0,31);el('circle',{cx:196,cy:14,r:4,class:'statusdot'},g);g.onclick=()=>{root.querySelectorAll('.host').forEach(x=>x.classList.remove('selected'));g.classList.add('selected');details(d)};g.onkeydown=e=>{if(e.key==='Enter')g.onclick()}});function apply(){stage.setAttribute('transform',`translate(${pan.x} ${pan.y}) scale(${zoom})`)}function fit(){zoom=Math.min(1,(w-40)/stageW,(h-25)/stageH);pan={x:(w-stageW*zoom)/2,y:10};apply()}fit();mapCtl=a=>{if(a==='fit')return fit();zoom=Math.max(.15,Math.min(3,zoom*(a==='in'?1.2:1/1.2)));apply()};svg.addEventListener('wheel',e=>{if(!mapUnlocked)return;e.preventDefault();zoom=Math.max(.15,Math.min(3,zoom*(e.deltaY<0?1.1:.9)));apply()},{passive:false});let drag;svg.addEventListener('pointerdown',e=>{if(!mapUnlocked)return;if(e.target.closest('.host'))return;drag={x:e.clientX,y:e.clientY,px:pan.x,py:pan.y};svg.setPointerCapture(e.pointerId)});svg.addEventListener('pointermove',e=>{if(!mapUnlocked||!drag)return;let k=w/svg.getBoundingClientRect().width;pan.x=drag.px+(e.clientX-drag.x)*k;pan.y=drag.py+(e.clientY-drag.y)*k;apply()});svg.addEventListener('pointerup',()=>drag=null);svg.addEventListener('pointercancel',()=>drag=null)}$('#zoomin').onclick=()=>mapCtl?.('in');$('#zoomout').onclick=()=>mapCtl?.('out');$('#fit').onclick=()=>mapCtl?.('fit');

function updateMapLockUI(){
  $('#map').classList.toggle('map-unlocked',mapUnlocked);
  $('#maphint').textContent=mapUnlocked?'🔓 Mapa aktywna — kliknij poza mapą, aby ją zablokować.':'🔒 Mapa zablokowana — kliknij dwukrotnie tło mapy, aby przesuwać i przybliżać.';
}
$('#map').addEventListener('dblclick',e=>{
  if(e.target.closest('.host'))return;
  e.preventDefault();mapUnlocked=true;updateMapLockUI();
});
document.addEventListener('pointerdown',e=>{
  if(mapUnlocked && !e.target.closest('#map')){mapUnlocked=false;updateMapLockUI();}
},true);
updateMapLockUI();

$('#exportcsv').onclick=()=>{window.location.href='/api/export.csv'};
function switchView(isPhysical){physical=isPhysical;$('#logical').classList.toggle('viewactive',!physical);$('#physical').classList.toggle('viewactive',physical);$('#maptitle').textContent=physical?'Topologia fizyczna':'Mapa urządzeń';$('#toponote').hidden=!physical;render()}
$('#logical').onclick=()=>switchView(false);
$('#physical').onclick=()=>switchView(true);
async function loadHistory(){try{const rows=await(await fetch('/api/history')).json();$('#history').innerHTML=rows.map(r=>`<button class="historyentry" data-id="${r.id}"><b>${esc(r.finished)}</b><span>${esc(r.cidr)}</span><span>${r.devices} urządzeń</span></button>`).join('')||'Brak historii';$('#history').querySelectorAll('button').forEach(b=>b.onclick=async()=>{const r=await(await fetch('/api/history/'+b.dataset.id)).json();devices=r.devices||[];confirmedEdges=r.edges||[];cidr=r.cidr;render();$('#message').textContent='Wczytano skan z '+r.finished})}catch(e){$('#history').textContent='Nie można wczytać historii'}}
$('#refreshhistory').onclick=loadHistory;loadHistory();

