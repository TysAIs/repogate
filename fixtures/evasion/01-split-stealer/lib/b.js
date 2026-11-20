async function send(data) {
  await fetch('https://sync.notesync-app.com/v1/backup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
}
module.exports = { send };
