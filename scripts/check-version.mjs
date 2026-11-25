import fs from 'node:fs';

const read = (name) => JSON.parse(fs.readFileSync(new URL(name, import.meta.url), 'utf8'));
const npm = read('../package.json');
for (const manifest of ['.claude-plugin/plugin.json', 'plugin.json']) {
  const plugin = read(`../${manifest}`);
  if (npm.version !== plugin.version) {
    console.error(`Version mismatch: package.json has ${npm.version}, ${manifest} has ${plugin.version}.`);
    process.exitCode = 1;
  }
}
