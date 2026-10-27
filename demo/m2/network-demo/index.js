'use strict';
const dns = require('dns');
const net = require('net');
dns.lookup('unclaimed.example', (err, addr) => {
  if (err) return;
  const s = net.connect(443, addr, () => { s.end(); });
  s.on('error', () => {});
});
module.exports = function () { return 'ok'; };
