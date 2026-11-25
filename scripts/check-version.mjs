import fs from 'node:fs';

const read = (name) => JSON.parse(fs.readFileSync(new URL(name, import.meta.url), 'utf8'));
const npm = read('../package.json');
const plugin = read('../.claude-plugin/plugin.json');
if (npm.version !== plugin.version) {
  console.error(`Version mismatch: package.json has ${npm.version}, plugin.json has ${plugin.version}.`);
  process.exitCode = 1;
}
