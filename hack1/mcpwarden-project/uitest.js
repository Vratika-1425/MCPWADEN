const { JSDOM, VirtualConsole } = require('jsdom');
const fs = require('fs');
const vc = new VirtualConsole(); const errs=[];
vc.on('jsdomError', e => errs.push('jsdomError '+e.message)); vc.on('error', e=>errs.push('console.error '+e)); 
const html = fs.readFileSync('index.html','utf8');
const dom = new JSDOM(html, { url: 'https://example.test/', runScripts: 'dangerously', pretendToBeVisual: true, virtualConsole: vc,
  beforeParse(w){ Object.defineProperty(w,'crypto',{value:globalThis.crypto}); w.TextEncoder=TextEncoder; w.confirm=()=>true; } });
const w = dom.window; const $ = s => w.document.querySelector(s);
const sleep = ms => new Promise(r=>setTimeout(r,ms));
(async()=>{
  await sleep(800);
  console.log('landing h1:', $('.hero h1')?.textContent);
  await sleep(2500);
  console.log('hero verdict:', $('#hcv')?.textContent.slice(0,80));
  const pages=['command','playground','pipeline','lab','registry','policy','inspector','audit','analytics','settings'];
  for(const p of pages){ w.location.hash='#/'+p; await sleep(150); console.log(p, '->', $('#ttl')?.textContent, 'len', $('#view')?.innerHTML.length); }
  // playground run
  w.location.hash='#/playground'; await sleep(150);
  $('#task').value='Read https://blog.secure-ai.test/agent-tips and summarize it'; $('#go').click();
  await sleep(4000);
  console.log('pg decision:', $('#pg-dc .vd')?.textContent, '|', $('#trans .answer')?.textContent.slice(0,120));
  // approval
  w.document.querySelectorAll('[data-sc]')[8].click(); await sleep(2000);
  console.log('awaiting:', $('#pg-dc .vd')?.textContent); $('[data-approve]')?.click(); await sleep(2500);
  console.log('after approve:', $('#pg-dc .vd')?.textContent);
  // pipeline
  w.location.hash='#/pipeline'; await sleep(200);
  console.log('pipeline stages:', w.document.querySelectorAll('#pp-rail .st').length, $('#pp-dc .vd')?.textContent);
  w.document.querySelectorAll('#pp-rail .st')[4].click(); await sleep(50); console.log('detail:', $('#pp-detail')?.textContent.slice(0,90));
  // lab run all
  w.location.hash='#/lab'; await sleep(200); $('#runall').click();
  for(let i=0;i<60 && !$('#labprog')?.textContent.startsWith('Last');i++){ await sleep(1000); if(!$('#runall')?.disabled) break; }
  await sleep(500);
  console.log('lab metrics:', [...w.document.querySelectorAll('.metrics .v')].map(x=>x.textContent).join(' | '));
  w.document.querySelector('#labt tr.click').click(); await sleep(50); console.log('lab detail ok:', !!$('#labd .panel'));
  // registry compare drift: trigger drift and view
  w.location.hash='#/registry'; await sleep(200); console.log('registry panels:', w.document.querySelectorAll('.panel').length);
  // policy invalid save
  w.location.hash='#/policy'; await sleep(200); const pj=$('#pj'); const p=JSON.parse(pj.value); p.limits.allowedSchemes.push('gopher'); pj.value=JSON.stringify(p); pj.oninput(); $('#ps').click(); await sleep(200);
  console.log('policy msg:', $('#pmsg')?.textContent.slice(0,100));
  $('#dr').click(); await sleep(50); console.log('dry run:', $('#dres')?.textContent.replace(/\s+/g,' ').slice(0,160));
  w.location.hash='#/inspector'; await sleep(200); console.log('inspector rows:', w.document.querySelectorAll('[data-r]').length);
  $('#pastebtn').click(); await sleep(50); $('#pgo').click(); await sleep(50); console.log('paste:', $('#pout')?.textContent.replace(/\s+/g,' ').slice(0,200));
  w.location.hash='#/audit'; await sleep(200); $('#aver').click(); await sleep(400); console.log('verify:', $('#averr')?.textContent.trim().slice(0,80));
  $('#atamp').click(); await sleep(500); console.log('tamper:', $('#averr')?.textContent.trim().slice(0,90));
  w.location.hash='#/analytics'; await sleep(200); console.log('analytics:', [...w.document.querySelectorAll('.metrics .v')].map(x=>x.textContent).join(' | '));
  // check no secret leaked in DOM anywhere visited: audit storage
  const store = w.localStorage.getItem('mcpw:audit');
  console.log('secret in audit?', /AKIAZ3SYNTHETIC0DEMO|ghp_Synthetic|Synth3tic!Pass/.test(store));
  console.log('errors:', errs.slice(0,10));
  process.exit(0);
})();
