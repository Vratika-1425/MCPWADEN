const { JSDOM, VirtualConsole } = require('jsdom'); const fs = require('fs');
const vc = new VirtualConsole(); const errs = [];
vc.on('jsdomError', e => errs.push('jsdomError ' + e.message + (e.detail ? ' ' + e.detail : ''))); vc.on('error', e => errs.push('console.error ' + e));
const dom = new JSDOM(fs.readFileSync('index.html', 'utf8'), { url: 'https://example.test/', runScripts: 'dangerously', pretendToBeVisual: true, virtualConsole: vc,
  beforeParse(w) { Object.defineProperty(w, 'crypto', { value: globalThis.crypto }); w.TextEncoder = TextEncoder; w.confirm = () => true; } });
const w = dom.window; const $ = s => w.document.querySelector(s); const $$ = s => [...w.document.querySelectorAll(s)];
const sleep = ms => new Promise(r => setTimeout(r, ms));
const go = async h => { w.location.hash = h; await sleep(200); };
(async () => {
  await sleep(900);
  console.log('landing caps:', $$('.caps>div').length);
  for (const p of ['command','playground','pipeline','decisions','chains','intent','sentinel','registry','policy','inspector','lab','audit','analytics','settings']) { await go('#/' + p); console.log(p.padEnd(11), '->', $('#ttl')?.textContent, '| view', $('#view')?.innerHTML.length); }
  console.log('nav groups:', $$('.nav .ngrp').map(x => x.textContent).join(','), 'links', $$('.nav a').length);
  // playground manipulable scenario
  await go('#/playground');
  const chips = $$('[data-sc]'); chips[10].click(); await sleep(9000);
  console.log('pg calls:', $$('#pg-calls [data-call]').map(b => b.textContent.trim()).join(' | '));
  console.log('pg answer:', ($('#trans .answer')?.textContent || '').slice(0, 160).replace(/\s+/g, ' '));
  // intent page
  await go('#/intent'); console.log('intent rows:', $$('[data-i]').length, '| detail vd:', $('#idet .vd')?.textContent);
  $('#idemo').click(); await sleep(9000); console.log('intent after demo rows:', $$('[data-i]').length);
  // chains
  await go('#/chains'); console.log('chains listed:', $$('[data-c]').length, 'nodes', $$('.gnode').length);
  w.document.querySelectorAll('.gnode')[2]?.dispatchEvent(new w.MouseEvent('click', { bubbles: true })); await sleep(50);
  console.log('chain evidence:', ($('#cev')?.textContent || '').slice(0, 120).replace(/\s+/g, ' '));
  // decisions
  await go('#/decisions'); console.log('decisions rows:', $$('[data-d]').length, '| vd', $('#dexp .vd')?.textContent);
  $('#dverify')?.click(); await sleep(400); console.log('verify record:', $('#dverr')?.textContent);
  const deniedRow = $$('[data-d]').find(r => r.textContent.includes('DENIED')); deniedRow?.click(); await sleep(50);
  console.log('denied why panel:', ($$('#dexp .panel')[0]?.textContent || '').replace(/\s+/g, ' ').slice(0, 220));
  // sentinel simulate
  await go('#/sentinel'); const cb = $('[data-fx="confidential"]'); cb.checked = true; cb.dispatchEvent(new w.Event('change')); await sleep(500);
  console.log('sentinel pending cards:', $$('[data-sr]').length, 'approve btns', $$('[data-sa]').length, 'diff ins', $$('pre.diff ins').length);
  const cb2 = $('[data-fx="optionalParam"]'); cb2.checked = true; cb2.dispatchEvent(new w.Event('change')); await sleep(500);
  console.log('after 2nd change, pending:', $$('[data-sr]').length);
  $('#sreset').click(); await sleep(600); console.log('after reset pending:', $$('[data-sr]').length);
  // sandbox suite
  await go('#/lab'); $('#runall').click();
  for (let i = 0; i < 120; i++) { await sleep(1000); if (!$('#runall')?.disabled) break; }
  await sleep(300); console.log('suite metrics:', $$('.metrics .v').map(x => x.textContent).join(' | '));
  console.log('fail rows:', $$('#labt tr').filter(r => r.textContent.includes('FAIL')).map(r => r.cells[0].textContent).join(','));
  $$('#labt tr.click')[22]?.click(); await sleep(50); console.log('L23 detail:', ($('#labd')?.textContent || '').replace(/\s+/g, ' ').slice(0, 200));
  await go('#/analytics'); console.log('analytics:', $$('.metrics .v').map(x => x.textContent).join(' | '));
  await go('#/command'); await sleep(300); console.log('command:', $$('.metrics .v').map(x => x.textContent).join(' | '));
  console.log('errors:', errs.slice(0, 8));
  process.exit(0);
})();
