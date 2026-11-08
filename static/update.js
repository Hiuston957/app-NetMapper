(()=>{
const el=id=>document.getElementById(id);
const modal=el('update-modal'),status=el('update-status');
el('open-update').addEventListener('click',()=>{modal.hidden=false;status.textContent='';});
el('close-update').addEventListener('click',()=>modal.hidden=true);
modal.addEventListener('click',e=>{if(e.target===modal)modal.hidden=true});
fetch('/api/update/info').then(r=>r.json()).then(d=>{if(d.version)el('installed-version').textContent='NetMapper '+d.version}).catch(()=>{});
el('apply-update').addEventListener('click',async()=>{
 const file=el('update-file').files[0];
 if(!file){status.textContent='Wybierz plik ZIP.';return}
 if(!confirm('Zainstalować aktualizację? Serwer uruchomi się ponownie, a otwarte sesje terminalowe zostaną przerwane.'))return;
 const button=el('apply-update');button.disabled=true;status.textContent='Wgrywanie i sprawdzanie paczki...';
 try{
  const form=new FormData();form.append('package',file);
  const r=await fetch('/api/update',{method:'POST',headers:{'X-NetMapper-Update':'1'},body:form});
  const d=await r.json();if(!r.ok)throw Error(d.error||'Nie udało się zainstalować aktualizacji.');
  status.textContent='Zainstalowano '+d.version+'. Kopia: '+d.backup+'. Oczekiwanie na ponowne uruchomienie...';
  let count=0;const poll=setInterval(async()=>{count++;try{const r=await fetch('/api/update/info',{cache:'no-store'});if(r.ok){const v=await r.json();if(v.version===d.version){clearInterval(poll);location.reload()}}}catch(e){}if(count>45){clearInterval(poll);status.textContent+='\nOdśwież stronę ręcznie lub uruchom ponownie aplikację.'}},1500);
 }catch(e){status.textContent='Błąd: '+e.message;button.disabled=false}
});
})();
