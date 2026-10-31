import { createPublicKey, verify } from 'node:crypto';
import fs from 'node:fs';
const tasks = JSON.parse(fs.readFileSync(0, 'utf8'));
const output = tasks.map(t => {
  try {
    const key = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(t.public_key,'hex')]), format:'der', type:'spki' });
    return verify(null,Buffer.from(t.message_base64,'base64'),key,Buffer.from(t.signature_base64,'base64'));
  } catch { return false; }
});
process.stdout.write(JSON.stringify(output));
