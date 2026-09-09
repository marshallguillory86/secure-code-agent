/* Every JavaScript rule in the offline profile must flag something here. */
const child_process = require('child_process');
const crypto = require('crypto');

function commandInjection(cmd) { child_process.exec(cmd); }
function codeInjection(input) { return eval(input); }
function dynamicCode(src) { return new Function(src); }
function weakHash(data) { return crypto.createHash('md5').update(data); }
function predictable() { return Math.random(); }
function disableTls() { process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; }
function htmlSink(el, value) { el.innerHTML = value; }
