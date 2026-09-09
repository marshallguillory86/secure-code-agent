/* The safe counterpart of every positive JavaScript case. Nothing may fire. */
const child_process = require('child_process');
const crypto = require('crypto');

function commandWithArgv(args) { child_process.execFile('/usr/bin/git', args); }
function parseData(input) { return JSON.parse(input); }
function namedHandler() { return function handler() { return 1; }; }
function strongHash(data) { return crypto.createHash('sha256').update(data); }
function unpredictable() { return crypto.randomBytes(32); }
function textSink(el, value) { el.textContent = value; }
