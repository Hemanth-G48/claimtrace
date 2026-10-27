'use strict';
module.exports = function format(fmt, value) { return String(fmt).replace(/%s/g, String(value)); };
