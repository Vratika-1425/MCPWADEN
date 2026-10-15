'use strict';
// Runs the original demo-mode suites unchanged. test.js, test_features.js, test_audit_storage.js and migtest.js
// exit non-zero on failure. uitest.js and uitest2.js only print results, so their output is checked here.
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const ROOT = path.join(__dirname, '..');
const SUITES = [
  ['test.js', out => /"passed":31,/.test(out) && /internal connections ever: 0/.test(out)],
  ['test_features.js', out => /37\/37 passed/.test(out)],
  ['test_audit_storage.js', out => !/^FAIL/m.test(out) && /PASS recovers/.test(out)],
  ['migtest.js', out => /call after migration: ALLOWED/.test(out)],
  ['uitest.js', out => /errors: \[\]/.test(out) && /lab metrics: 31\/31/.test(out) && /secret in audit\? false/.test(out)],
  ['uitest2.js', out => /errors: \[\]/.test(out) && /suite metrics: 31\/31/.test(out) && /fail rows: \n/.test(out)],
];
let failed = 0;
for (const [file, check] of SUITES) {
  const t0 = Date.now();
  const r = spawnSync(process.execPath, [path.join(ROOT, file)], { cwd: ROOT, encoding: 'utf8', timeout: 600000 });
  const out = (r.stdout || '') + (r.stderr || '');
  const ok = r.status === 0 && check(out);
  if (!ok) failed++;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${file} (${((Date.now() - t0) / 1000).toFixed(1)}s)`);
  if (!ok) console.log(out.split('\n').slice(-25).join('\n'));
}
console.log(`\ndemo suites: ${SUITES.length - failed}/${SUITES.length} passed`);
process.exit(failed ? 1 : 0);
