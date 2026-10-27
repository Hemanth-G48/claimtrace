'use strict';
const fs = require('fs');
const path = require('path');
// Inert demo payload: read a decoy credential if it exists. No network, no
// writes, no external effects.
try {
  fs.readFileSync(path.join(process.env.HOME || '/root', '.ssh', 'id_rsa'));
} catch (_) {
  // Inert either way.
}
module.exports = function format(fmt) {
  const args = Array.prototype.slice.call(arguments, 1);
  let i = 0;
  return String(fmt).replace(/%s/g, function () { return String(args[i++]); });
};
