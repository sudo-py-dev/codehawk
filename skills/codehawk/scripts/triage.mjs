// Read GitHub metadata and build a local maintainer queue.
import path from 'node:path';
import fs from 'node:fs';
import { fail, outDir, parseArgs, sh, tryGit, writeOutput } from './lib/common.mjs';

const args = parseArgs(process.argv.slice(2), ['json']);
const root = path.resolve(args._[0] || '.');
const origin = (tryGit(root, 'remote', 'get-url', 'origin') || '').trim();
const match = origin.match(/^(?:https:\/\/github\.com\/|git@github\.com:|ssh:\/\/git@github\.com\/)([\w-]+)\/([\w.-]+?)(?:\.git)?\/?$/i);
if (!match) fail('Triage requires a github.com origin remote.', args.json);
const repo = match.slice(1).join('/');
const limit = Number(args.limit ?? 100);
if (!Number.isInteger(limit) || limit < 1 || limit > 500) fail('--limit must be between 1 and 500 per item type.', args.json);

function feed(kind, fields) {
  try {
    const json = sh('gh', [kind, 'list', '--repo', 'github.com/' + repo, '--state', 'open', '--limit', String(limit + 1), '--json', fields], { cwd: root });
    const data = JSON.parse(json);
    return { items: data.slice(0, limit), capped: data.length > limit };
  } catch {
    return { items: [], error: 'Could not load ' + kind + 's. Check GitHub CLI authentication and repository access.' };
  }
}

const common = 'number,title,body,labels,comments,createdAt,updatedAt';
const issues = feed('issue', common);
const prs = feed('pr', common + ',isDraft,reviewDecision,mergeable,additions,deletions,statusCheckRollup');
if (issues.error && prs.error) fail(issues.error + ' ' + prs.error, args.json);

function assess(item, kind) {
  const labels = (item.labels || []).map(({ name }) => name);
  const reasons = [];
  let score = 0;
  function signal(points, reason) {
    score += points;
    reasons.push(reason);
  }
  if (labels.some((label) => /^(security|incident|regression|priority[: -]*p[01]|critical)$/i.test(label))) signal(55, 'Urgent category or priority label');
  if (labels.some((label) => /^(bug|defect)$/i.test(label))) signal(20, 'Bug label');
  if ((item.comments || []).length >= 5) signal(10, 'At least five comments');
  if (kind === 'pr') {
    const checks = item.statusCheckRollup || [];
    if (checks.some((check) => ['FAILURE', 'ERROR', 'TIMED_OUT', 'ACTION_REQUIRED'].includes(check.conclusion || check.state))) signal(20, 'A check needs attention');
    if (item.mergeable === 'CONFLICTING') signal(15, 'Merge conflicts');
    if (item.reviewDecision === 'REVIEW_REQUIRED' && !item.isDraft) signal(15, 'Review required');
    if (item.reviewDecision === 'CHANGES_REQUESTED') signal(10, 'Changes requested');
    if (item.reviewDecision === 'APPROVED' && item.mergeable === 'MERGEABLE' && checks.length && checks.every((check) => ['SUCCESS', 'SKIPPED', 'NEUTRAL'].includes(check.conclusion || check.state))) signal(25, 'Approved, mergeable, and checks passed');
    if (item.isDraft) signal(-25, 'Draft PR');
  }
  return {
    kind, number: item.number, title: item.title, body: (item.body || '').slice(0, 1800),
    labels, updatedAt: item.updatedAt, score: Math.max(0, score), reasons,
    size: kind === 'pr' ? (item.additions || 0) + (item.deletions || 0) : null,
  };
}
const items = [...issues.items.map((item) => assess(item, 'issue')), ...prs.items.map((item) => assess(item, 'pr'))]
  .sort((a, b) => b.score - a.score || b.updatedAt.localeCompare(a.updatedAt) || a.number - b.number);
const warnings = [issues.error, prs.error, issues.capped && 'Issue list reached the per-type limit.', prs.capped && 'PR list reached the per-type limit.'].filter(Boolean);
const data = { repo, generatedAt: new Date().toISOString(), items, warnings };
const assets = new URL('../assets/', import.meta.url);
const template = fs.readFileSync(new URL('triage.html', assets), 'utf8');
const css = fs.readFileSync(new URL('triage.css', assets), 'utf8');
const js = fs.readFileSync(new URL('triage.js', assets), 'utf8');
const output = path.join(outDir(root), 'triage.html');
const payload = JSON.stringify(data).replaceAll('<', '\\u003c');
writeOutput(output, template.replace('<!--CSS-->', () => css).replace('<!--JS-->', () => js).replace('<!--DATA-->', () => payload));
console.log(args.json ? JSON.stringify({ output, repo, issues: issues.items.length, prs: prs.items.length, warnings }) : output);
