import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { applyResolutions, renderOutputs } from '../skills/codehawk/scripts/lib/render.mjs';

const example = fileURLToPath(new URL('../docs/example/', import.meta.url));
const check = process.argv.includes('--check');
const read = (name) => JSON.parse(fs.readFileSync(path.join(example, name), 'utf8'));
const data = applyResolutions(read('snapshot.json'), { items: {} });
delete data.liveRev;
data.sarif = read('report.sarif');

const output = fs.mkdtempSync(path.join(os.tmpdir(), 'codehawk-example-'));
try {
  renderOutputs(output, data, { live: false });
  for (const name of ['report.html', 'summary.md']) {
    const generated = path.join(output, name);
    const destination = path.join(example, name);
    if (!check) fs.copyFileSync(generated, destination);
    else if (!fs.existsSync(destination) || !fs.readFileSync(generated).equals(fs.readFileSync(destination))) {
      console.error(`docs/example/${name} is stale. Run npm run example.`);
      process.exitCode = 1;
    }
  }
  if (!check) console.log('Refreshed docs/example/report.html and docs/example/summary.md.');
} finally {
  fs.rmSync(output, { recursive: true, force: true });
}
