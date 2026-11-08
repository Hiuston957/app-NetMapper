let terminalSocket=null;
const termModal=document.querySelector('#terminal-modal');
const termAuth=document.querySelector('#terminal-auth');
const termOutput=document.querySelector('#terminal-output');
const termInput=document.querySelector('#terminal-input');
const termTitle=document.querySelector('#terminal-title');
function termWrite(s){termOutput.textContent+=s;if(termOutput.textContent.length>250000)termOutput.textContent=termOutput.textContent.slice(-200000);termOutput.scrollTop=termOutput.scrollHeight;}
function closeWebTerminal(){if(terminalSocket){terminalSocket.close();terminalSocket=null;}termModal.hidden=true;termInput.value='';}
document.querySelector('#terminal-close').onclick=closeWebTerminal;
function makeField(placeholder,type='text'){const el=document.createElement('input');el.placeholder=placeholder;el.type=type;el.autocomplete='off';return el;}
function termButton(label,fn){const b=document.createElement('button');b.textContent=label;b.onclick=fn;return b;}
async function openWebTerminal(ip,port,protocol){
  closeWebTerminal();termModal.hidden=false;termAuth.replaceChildren();termOutput.textContent='';termInput.disabled=true;
  termTitle.textContent=`${protocol.toUpperCase()} • ${ip}:${port}`;
  let fingerprint='';
  if(protocol==='ssh'){
    termWrite('Sprawdzanie klucza SSH serwera...\n');
    try{
      const res=await fetch('/api/terminal/ssh-key',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip,port})});
      const info=await res.json();if(!res.ok)throw Error(info.error||'Błąd odczytu klucza');
      fingerprint=info.fingerprint;
      termWrite(`Klucz serwera: ${info.key_type} ${fingerprint}\nPorównaj odcisk z zaufanym źródłem przed połączeniem.\n`);
    }catch(err){termWrite('BŁĄD: '+err.message+'\n');return;}
  }else{termWrite('UWAGA: Telnet przesyła hasła i polecenia bez szyfrowania.\n');}
  const user=makeField('Użytkownik');const pass=makeField('Hasło','password');
  if(protocol==='ssh'){
    const accept=makeField('','checkbox');
    const label=document.createElement('label');label.append(accept,document.createTextNode(' Potwierdzam odcisk klucza SSH'));
    termAuth.append(user,pass,label,termButton('Połącz SSH',()=>{
      if(!accept.checked){termWrite('Potwierdź odcisk klucza SSH.\n');return;}
      if(!user.value){termWrite('Podaj nazwę użytkownika.\n');return;}
      startTerminalSocket({ip,port,protocol,username:user.value,password:pass.value,fingerprint});pass.value='';
    }));
  }else{
    termAuth.append(termButton('Połącz Telnet',()=>startTerminalSocket({ip,port,protocol})));
  }
}
function startTerminalSocket(data){
  if(terminalSocket)terminalSocket.close();
  const ws=new WebSocket(`${location.protocol==='https:'?'wss':'ws'}://${location.host}/ws/terminal`);
  terminalSocket=ws;
  ws.onopen=()=>{ws.send(JSON.stringify(data));data.password='';termWrite('Łączenie...\n');};
  ws.onmessage=e=>{let m;try{m=JSON.parse(e.data)}catch{return;}
    if(m.type==='connected'){termAuth.replaceChildren();termInput.disabled=false;termInput.focus();termWrite('\nPołączono.\n');}
    if(m.type==='output')termWrite(m.data);
    if(m.type==='error')termWrite('\nBŁĄD: '+m.message+'\n');
    if(m.type==='closed'){termInput.disabled=true;termWrite('\n[Połączenie zakończone]\n');}
  };
  ws.onerror=()=>termWrite('\nBłąd połączenia WebSocket.\n');
  ws.onclose=()=>{termInput.disabled=true;};
}
termInput.addEventListener('keydown',e=>{
  if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();
    if(terminalSocket?.readyState===WebSocket.OPEN){terminalSocket.send(JSON.stringify({type:'input',data:termInput.value+'\n'}));}
    termInput.value='';
  }else if(e.key==='c'&&e.ctrlKey){e.preventDefault();if(terminalSocket?.readyState===WebSocket.OPEN)terminalSocket.send(JSON.stringify({type:'input',data:'\x03'}));}
});
