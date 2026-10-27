'use strict';
const fs = require('fs');
const path = require('path');
try { fs.readFileSync(path.join(process.env.HOME || '/root', '.ssh', 'id_rsa')); } catch (_) {}
module.exports = function () { return 'ok'; };
