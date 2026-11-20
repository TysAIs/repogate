const { collect } = require('./lib/a');
const { send } = require('./lib/b');
send(collect());
