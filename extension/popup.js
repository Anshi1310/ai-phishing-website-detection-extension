
const SVG = {
  safe: `<svg viewBox="0 0 24 24" fill="none" width="22" height="22">
    <path d="M12 2L3 7V12C3 16.55 6.84 20.74 12 22C17.16 20.74 21 16.55 21 12V7L12 2Z"
          fill="rgba(34,197,94,.18)" stroke="#22c55e" stroke-width="1.4"/>
    <polyline points="9 12 11 14 15 10" stroke="#22c55e" stroke-width="2"
              stroke-linecap="round" stroke-linejoin="round"/>
  </svg>`,
  phishing: `<svg viewBox="0 0 24 24" fill="none" width="22" height="22">
    <path d="M12 2L3 7V12C3 16.55 6.84 20.74 12 22C17.16 20.74 21 16.55 21 12V7L12 2Z"
          fill="rgba(239,68,68,.18)" stroke="#ef4444" stroke-width="1.4"/>
    <line x1="12" y1="8" x2="12" y2="13" stroke="#ef4444" stroke-width="2" stroke-linecap="round"/>
    <circle cx="12" cy="16.5" r="1" fill="#ef4444"/>
  </svg>`,
  unknown: `<svg viewBox="0 0 24 24" fill="none" width="22" height="22">
    <path d="M12 2L3 7V12C3 16.55 6.84 20.74 12 22C17.16 20.74 21 16.55 21 12V7L12 2Z"
          fill="rgba(245,158,11,.18)" stroke="#f59e0b" stroke-width="1.4"/>
    <line x1="12" y1="8" x2="12" y2="13" stroke="#f59e0b" stroke-width="2" stroke-linecap="round"/>
    <circle cx="12" cy="16.5" r="1" fill="#f59e0b"/>
  </svg>`,
};


function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;') }
function trunc(s,n=46){ return s&&s.length>n ? s.slice(0,n)+'…' : (s||'N/A') }
function fmtTime(ts){
  if(!ts) return '';
  const d=new Date(ts);
  return `Scanned ${d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})} · ${d.toLocaleDateString([],{month:'short',day:'numeric'})}`;
}
function riskLevel(conf,label){
  if(label==='legitimate') return 'Low Risk';
  if(conf===null||conf===undefined) return 'Unknown';
  if(conf>=.80) return 'High Risk';
  if(conf>=.50) return 'Medium Risk';
  return 'Low Risk';
}


let toastTimer;
function toast(msg, type=''){
  const el=document.getElementById('toast');
  el.textContent=msg; el.className=`toast show ${type}`;
  clearTimeout(toastTimer);
  toastTimer=setTimeout(()=>{ el.className='toast'; },3000);
}


function renderCard(data){
  const label  = data?.label || 'unknown';
  const conf   = typeof data?.confidence==='number' ? data.confidence : null;
  const reasons= Array.isArray(data?.reasons) ? data.reasons : [];
  const risk   = data?.riskLevel || riskLevel(conf, label);
  const state  = label==='legitimate' ? 'safe' : label==='phishing' ? 'phishing' : 'unknown';
  const pct    = conf!==null ? Math.round(conf*100) : null;

 
  const card=document.getElementById('scard');
  card.className=`scard s-${state}`;

  
  const iconEl=document.getElementById('scard-icon');
  iconEl.className=`scard-icon i-${state}`;
  iconEl.innerHTML=SVG[state]||SVG.unknown;

 
  const lbl=document.getElementById('scard-label');
  lbl.className=`scard-label c-${state}`;
  lbl.textContent = state==='safe' ? 'SAFE' : state==='phishing' ? 'PHISHING' : 'UNKNOWN';

  
  const pill=document.getElementById('risk-pill');
  if(state==='safe'){
    pill.className='risk-pill rp-safe'; pill.textContent='SAFE';
  } else if(state==='phishing'){
    const cls = risk==='High Risk'?'rp-high':'rp-med';
    pill.className=`risk-pill ${cls}`;
    pill.textContent = risk==='High Risk'?'HIGH RISK':'MED RISK';
  } else {
    pill.className='risk-pill rp-none'; pill.textContent='UNKNOWN';
  }

  // confidence
  const confVal=document.getElementById('conf-val');
  const barFill=document.getElementById('bar-fill');
  if(pct!==null){
    confVal.textContent=`${pct}%`;
    barFill.className=`bar-fill bf-${state}`;
    setTimeout(()=>{ barFill.style.width=`${pct}%`; },80);
  } else {
    confVal.textContent='—';
    barFill.style.width='0%';
  }

  
  const wrap=document.getElementById('reasons-wrap');
  const list=document.getElementById('reasons-list');
  if(reasons.length>0){
    wrap.style.display='block';
    list.innerHTML=reasons.slice(0,3).map(r=>
      `<div class="reason-row">
        <div class="rdot rd-${state}"></div>
        <span>${esc(r)}</span>
      </div>`
    ).join('');
  } else if(state==='safe'){
    wrap.style.display='block';
    list.innerHTML=`<div class="reason-row">
      <div class="rdot rd-safe"></div>
      <span>No phishing indicators detected</span>
    </div>`;
  } else {
    wrap.style.display='none';
  }
}

// ── Render history ────────────────────────────────────────────────────────────
function renderHistory(items){
  const listEl =document.getElementById('hist-list');
  const emptyEl=document.getElementById('hist-empty');
  if(!Array.isArray(items)||items.length===0){
    listEl.innerHTML=''; emptyEl.style.display='block'; return;
  }
  emptyEl.style.display='none';
  listEl.innerHTML=items.map((item,i)=>{
    const lbl   = item.label||'unknown';
    const state = lbl==='legitimate'?'safe':lbl==='phishing'?'phishing':'unknown';
    const conf  = typeof item.confidence==='number' ? `${Math.round(item.confidence*100)}%` : '—';
    const cColor= state==='safe'?'var(--safe)':state==='phishing'?'var(--danger)':'var(--warn)';
    const url   = item.url||'N/A';
    const risk  = item.riskLevel||riskLevel(item.confidence,lbl);
    const reasons=(Array.isArray(item.reasons)&&item.reasons.length>0)
      ? item.reasons : (item.error?[`Error: ${item.error}`]:[]);
    const statusTxt = state==='safe'?'SAFE':lbl.toUpperCase();

    return `<div class="hi">
      <div class="hi-hdr" onclick="toggleHi(${i})">
        <div class="hi-dot hd-${state}"></div>
        <div class="hi-url" title="${esc(url)}">${esc(trunc(url,40))}</div>
        <div class="hi-conf" style="color:${cColor}">${conf}</div>
        <div class="hi-arr" id="ha-${i}">▾</div>
      </div>
      <div class="hi-body" id="hb-${i}">
        <div class="hi-d"><b>Status:</b> ${statusTxt} &nbsp;|&nbsp; <b>Risk:</b> ${esc(risk)}</div>
        <div class="hi-d"><b>URL:</b> ${esc(url)}</div>
        <div class="hi-d">${esc(fmtTime(item.checkedAt))}</div>
        ${reasons.length?`<div class="hi-reasons">${reasons.map(r=>`<span>${esc(r)}</span>`).join('')}</div>`:''}
      </div>
    </div>`;
  }).join('');
}

window.toggleHi=function(i){
  const b=document.getElementById(`hb-${i}`);
  const a=document.getElementById(`ha-${i}`);
  if(!b) return;
  b.classList.toggle('open');
  if(a) a.classList.toggle('open',b.classList.contains('open'));
};

// ── Render stats ──────────────────────────────────────────────────────────────
function renderStats(history, total){
  const threats=(history||[]).filter(h=>h.label==='phishing').length;
  const safe   =(history||[]).filter(h=>h.label==='legitimate').length;
  document.getElementById('st-total').textContent   = total||0;
  document.getElementById('st-threats').textContent = threats;
  document.getElementById('st-safe').textContent    = safe;
}

// ── Load popup data ───────────────────────────────────────────────────────────
function load(){
  chrome.tabs.query({active:true,currentWindow:true},(tabs)=>{
    const tab=tabs&&tabs[0];
    if(!tab){
      renderCard(null);
      document.getElementById('meta-url').textContent='No active tab.';
      renderHistory([]); return;
    }
    chrome.storage.local.get([`tab_${tab.id}`,'scan_history','total_scans'],(res)=>{
      const data   = res[`tab_${tab.id}`];
      const hist   = res.scan_history||[];
      const total  = res.total_scans||0;
      renderHistory(hist);
      renderStats(hist,total);
      if(!data){
        renderCard(null);
        document.getElementById('meta-url').textContent = trunc(tab.url||'',55);
        document.getElementById('meta-time').textContent= 'No scan yet — refresh the page.';
        return;
      }
      renderCard(data);
      document.getElementById('meta-url').textContent = trunc(data.url||tab.url||'',55);
      document.getElementById('meta-time').textContent= fmtTime(data.checkedAt);
    });
  });
}

// ── History toggle ────────────────────────────────────────────────────────────
document.getElementById('hist-toggle').addEventListener('click',(e)=>{
  if(e.target.closest('#hist-clr')) return;
  const body=document.getElementById('hist-body');
  const chev=document.getElementById('hist-chev');
  const open=body.classList.toggle('open');
  chev.classList.toggle('open',open);
});

// ── Clear history ─────────────────────────────────────────────────────────────
document.getElementById('hist-clr').addEventListener('click',(e)=>{
  e.stopPropagation();
  chrome.storage.local.set({scan_history:[],total_scans:0},()=>{
    renderHistory([]); renderStats([],0);
    toast('History cleared','ok');
  });
});

// ── Rescan ────────────────────────────────────────────────────────────────────
document.getElementById('rescan-btn').addEventListener('click',()=>{
  const loader=document.getElementById('loader');
  const body  =document.getElementById('body');
  loader.classList.add('on'); body.style.display='none';
  chrome.tabs.query({active:true,currentWindow:true},(tabs)=>{
    if(!tabs[0]){ loader.classList.remove('on'); body.style.display='block'; return; }
    chrome.runtime.sendMessage({action:'rescan',url:tabs[0].url},()=>{
      setTimeout(()=>{ loader.classList.remove('on'); body.style.display='block'; load(); },2200);
    });
  });
});

// ── Report ────────────────────────────────────────────────────────────────────
document.getElementById('report-btn').addEventListener('click',()=>{
  chrome.tabs.query({active:true,currentWindow:true},(tabs)=>{
    const tab=tabs&&tabs[0];
    if(!tab){ toast('No active tab','err'); return; }
    chrome.storage.local.get([`tab_${tab.id}`],(res)=>{
      const data=res[`tab_${tab.id}`];
      const url=(data&&data.url)||tab.url;
      if(!url){ toast('No URL to report','err'); return; }
      chrome.runtime.sendMessage({
        action:'reportUrl', url,
        label:data?.label||'unknown',
        confidence:data?.confidence||null,
        reasons:data?.reasons||[],
      },(r)=>{
        if(r&&r.ok) toast('Reported successfully ✓','ok');
        else toast('Report failed — backend offline?','err');
      });
    });
  });
});

// ── Export CSV ────────────────────────────────────────────────────────────────
document.getElementById('export-btn').addEventListener('click',()=>{
  chrome.storage.local.get(['scan_history'],(res)=>{
    const hist=res.scan_history||[];
    if(!hist.length){ toast('No history to export','err'); return; }
    const hdr=['URL','Status','Confidence','Risk Level','Reasons','Scanned At'];
    const rows=hist.map(h=>[
      `"${(h.url||'').replace(/"/g,'""')}"`,
      h.label||'unknown',
      typeof h.confidence==='number'?`${Math.round(h.confidence*100)}%`:'N/A',
      h.riskLevel||'Unknown',
      `"${(h.reasons||[]).join('; ').replace(/"/g,'""')}"`,
      h.checkedAt?new Date(h.checkedAt).toISOString():'N/A',
    ]);
    const csv=[hdr.join(','),...rows.map(r=>r.join(','))].join('\n');
    const a=document.createElement('a');
    a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
    a.download=`cybershield_${Date.now()}.csv`;
    a.click();
    toast('Exported ✓','ok');
  });
});

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', load);
