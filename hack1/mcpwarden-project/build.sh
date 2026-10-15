#!/bin/sh
set -e
{ cat head.html; echo "<script>"; cat engine.js sentinel.js intent.js lab.js ui.js ui2.js live-client.js boot.js; echo "</script></body></html>"; } > index.html
node -e "const s=require('fs').readFileSync('index.html','utf8');const m=s.match(/<script>([\s\S]*)<\/script><\/body>/);new Function(m[1]);console.log('syntax ok', s.length)"
