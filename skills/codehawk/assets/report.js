(() => {
'use strict';
const D = JSON.parse(document.getElementById('codehawk-data').textContent);
const SEVS = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const icon = (n) => `<svg class="i" aria-hidden="true"><use href="#i-${n}"/></svg>`;
const sevVar = (s) => `--sc:var(--sev-${s})`;
const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
const QS = new URLSearchParams(location.search);
const isRes = (f) => !!f.resolution;
const isDone = (f) => !!f.resolution?.verified;              // fixed and all four checks passed
const needsAttention = (f) => !!f.resolution && !f.resolution.verified;
const METHOD = { patch: 'Fixed with CodeHawk patch', manual: 'Fixed manually' };
const STEPS = [['changed', 'Code changed'], ['gone', 'Problem gone'], ['everywhere', 'Fixed everywhere'], ['regression', 'No regression']];
const resTag = (r, big) => r.verified
  ? `<span class="res-tag" title="All four checks passed">${icon('check')}${big ? 'Resolved · verified' : 'Verified'}</span>`
  : `<span class="res-tag partial" title="${r.passed} of 4 checks passed">${icon('check')}${big ? `Resolved · ${r.passed}/4 checked` : `${r.passed}/4`}</span>`;
const P = D.progress || { total: D.findings.length, resolved: 0, verified: 0 };
const still = QS.has('still'); // ?still renders the final state with no motion (print, screenshots)
const reduced = still || matchMedia('(prefers-reduced-motion: reduce)').matches;
if (still) document.documentElement.classList.add('still');

/* ── theme ── */
const root = document.documentElement;
const THEME_KEY = 'codehawk:theme';
function applyTheme(t) {
  root.dataset.theme = t;
  $('#theme-btn').innerHTML = icon(t === 'dark' ? 'sun' : 'moon');
  $('#theme-btn').setAttribute('aria-label', `Switch to ${t === 'dark' ? 'light' : 'dark'} theme`);
}
applyTheme((['dark', 'light'].includes(QS.get('theme')) && QS.get('theme')) || localStorage.getItem(THEME_KEY) || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'));
$('#theme-btn').onclick = () => { const t = root.dataset.theme === 'dark' ? 'light' : 'dark'; localStorage.setItem(THEME_KEY, t); applyTheme(t); };

/* ── triage state (local to this browser) ── */
const TRIAGE_KEY = `codehawk:triage:${D.meta.repo}:${D.meta.ref || D.meta.head || ''}:${D.meta.label}`;
let triage = {};
try { triage = JSON.parse(localStorage.getItem(TRIAGE_KEY) || '{}'); } catch {}
const saveTriage = () => localStorage.setItem(TRIAGE_KEY, JSON.stringify(triage));
const QUEUE_KEY = TRIAGE_KEY.replace(':triage:', ':queue:');
let queue = new Set();
try { queue = new Set(JSON.parse(localStorage.getItem(QUEUE_KEY) || '[]').filter((id) => D.findings.some((f) => f.id === id && !isRes(f)))); } catch {}
const saveQueue = () => localStorage.setItem(QUEUE_KEY, JSON.stringify([...queue]));
function toggleQueue(id) {
  if (isRes(D.findings.find((f) => f.id === id) || {})) return toast(`${id} is already resolved`);
  queue.has(id) ? queue.delete(id) : queue.add(id);
  saveQueue(); tray();
  toast(queue.has(id) ? `${id} queued for fixing` : `${id} removed from queue`);
}
function fixRequest() {
  const ids = D.findings.map((f) => f.id).filter((id) => queue.has(id));
  return `Use CodeHawk to plan fixes for ${ids.join(', ')} in the latest report. Show me the changes for approval before applying them.`;
}
function tray() {
  const n = queue.size;
  $('#tray').classList.toggle('show', n > 0);
  document.body.classList.toggle('has-tray', n > 0);
  $('#tray-n').textContent = n;
  $('#tray-title').textContent = `${n} fix${n === 1 ? '' : 'es'} queued`;
  document.querySelectorAll('#list [data-id]').forEach((li) => { const q = li.querySelector('.q'); if (q) q.hidden = !queue.has(li.dataset.id); });
  const qb = document.querySelector('[data-act="queue"]');
  if (qb) { const on = queue.has(qb.dataset.id); qb.classList.toggle('queued', on); qb.innerHTML = on ? `${icon('check')}Queued for fix` : `${icon('wrench')}Queue fix`; qb.setAttribute('aria-pressed', on); }
}
$('#tray-clear').onclick = () => { queue.clear(); saveQueue(); tray(); toast('Fix queue cleared'); };
$('#tray-copy').onclick = () => copy(fixRequest(), 'Fix request copied');

/* ── filter state (in the URL hash so it's shareable) ── */
const state = { sev: new Set(), cat: null, file: null, q: '', status: 'open', sel: null, kind: 'all' };
const QLEVEL = { critical: 'Will break', high: 'Likely bug', medium: 'Should fix', low: 'Refactor', info: 'Nitpick' };
const sevLabel = (f) => (f.kind === 'quality' ? QLEVEL[f.severity] : f.severity);
function readHash() {
  const p = new URLSearchParams(location.hash.slice(1));
  state.sev = new Set((p.get('sev') || '').split(',').filter((s) => SEVS.includes(s)));
  state.cat = p.get('cat'); state.file = p.get('file'); state.q = p.get('q') || '';
  const st = p.get('status') === 'resolved' ? 'done' : p.get('status');
  state.status = ['open', 'done', 'all', 'triaged'].includes(st) ? st : 'open';
  state.kind = ['security', 'quality'].includes(p.get('kind')) ? p.get('kind') : 'all';
  state.sel = p.get('id');
}
function writeHash() {
  const p = new URLSearchParams();
  if (state.sel) p.set('id', state.sel);
  if (state.sev.size) p.set('sev', [...state.sev].join(','));
  if (state.cat) p.set('cat', state.cat);
  if (state.file) p.set('file', state.file);
  if (state.q) p.set('q', state.q);
  if (state.status !== 'open') p.set('status', state.status);
  if (state.kind !== 'all') p.set('kind', state.kind);
  history.replaceState(null, '', '#' + p.toString());
}

/* ── hero ── */
const GRADE_COLOR = { A: 'var(--ok)', B: 'var(--ok)', C: 'var(--sev-medium)', D: 'var(--sev-high)', F: 'var(--sev-critical)' };
const VERDICT = {
  block: ['Blocks merge', 'var(--sev-critical)'],
  review: ['Needs attention', 'var(--sev-medium)'],
  pass: ['Looks clean', 'var(--ok)'],
};
const modeWord = { pr: 'Pull request', commit: 'Commit', range: 'Commit range', branch: 'Branch', working: 'Uncommitted changes', repo: 'Repository' }[D.meta.mode] || 'Scan';

function renderGrades() {
  const showGrade = (id, label, grade, score) => {
    const row = $(id);
    row.style.setProperty('--grade', GRADE_COLOR[grade]);
    row.style.setProperty('--grade-fill', `${score}%`);
    row.setAttribute('aria-label', `${label} grade ${grade}, score ${score} out of 100`);
    row.querySelector('.label').textContent = label;
    row.querySelector('.grade').textContent = grade;
    row.querySelector('.score').textContent = `${score} / 100`;
    row.hidden = false;
  };
  if (D.focus !== 'quality') showGrade('#primary-grade', 'Security', D.grade, D.score);
  if (D.focus !== 'security') showGrade(D.focus === 'quality' ? '#primary-grade' : '#secondary-grade', 'Code quality', D.qualityGrade || 'A', D.qualityScore ?? 100);

  const [vt, vc] = VERDICT[D.verdict];
  $('#verdict').style.setProperty('--vc', vc);
  $('#verdict-text').textContent = vt;
}

function hero() {
  document.title = `CodeHawk · ${D.meta.label}`;
  $('#crumb-repo').textContent = D.meta.repo || '';
  $('#crumb-label').textContent = D.meta.label;
  const ref = D.meta.ref || D.meta.head;
  if (ref) { const c = $('#ref-chip'); c.hidden = false; c.textContent = ref.slice(0, 7); c.title = ref; }

  renderGrades();

  const titleBits = D.meta.pr?.title ? `${D.meta.pr.title}` : D.meta.commit?.title && D.meta.mode !== 'repo' ? D.meta.commit.title : `${modeWord} review`;
  $('#hero-title').textContent = titleBits;
  $('#summary').textContent = D.summary ? `At scan time. ${D.summary}` : (D.findings.length ? `${D.findings.length} security issue${D.findings.length > 1 ? 's' : ''} confirmed.` : 'No security issues were confirmed in this scope.');

  const facts = [];
  if (D.meta.pr?.url) facts.push(`<a href="${esc(D.meta.pr.url)}" target="_blank" rel="noopener">${icon('ext')} PR #${esc(D.meta.pr.number)}</a>`);
  else if (D.meta.mode !== 'repo') facts.push(`<span>${esc(modeWord)}</span>`);
  if (D.meta.pr?.author) facts.push(`<span>by <b>${esc(D.meta.pr.author)}</b></span>`);
  facts.push(`<span><b class="num">${D.meta.filesScanned.toLocaleString()}</b> files scanned</span>`);
  if (D.meta.mode !== 'repo' && D.meta.linesChanged) facts.push(`<span><b class="num">+${D.meta.linesChanged.toLocaleString()}</b> lines changed</span>`);
  else if (D.meta.linesScanned) facts.push(`<span><b class="num">${D.meta.linesScanned.toLocaleString()}</b> lines</span>`);
  facts.push(`<span><b class="num">${D.meta.candidates}</b> rule hits triaged</span>`);
  facts.push(`<time datetime="${esc(D.meta.generatedAt)}" title="${esc(new Date(D.meta.generatedAt).toLocaleString())}">${esc(relTime(D.meta.generatedAt))}</time>`);
  $('#facts').innerHTML = facts.join('');

  $('#sev-grid').innerHTML = SEVS.filter((s) => s !== 'unknown' || D.counts[s]).map((s) => `
    <button class="sev-tile" style="${sevVar(s)}" data-sev="${s}" aria-pressed="false" ${D.counts[s] ? '' : 'disabled'} title="Filter ${s} (${SEVS.indexOf(s) + 1})">
      <span class="n num ${D.counts[s] ? '' : 'zero'}">${D.counts[s]}</span><span class="l">${s}</span>
    </button>`).join('');
  $('#sev-grid').onclick = (e) => { const b = e.target.closest('[data-sev]'); if (b) toggleSev(b.dataset.sev); };
  progress();
  $('#foot-left').textContent = `Generated by CodeHawk · ${new Date(D.meta.generatedAt).toLocaleString()}${ref ? ' · ' + ref.slice(0, 12) : ''}`;
}

/* ── fix status board (hero): what's done, what needs attention, what's open ── updated in place */
function progress() {
  const el = $('#progress');
  const newN = (D.newIssues || []).length;
  if (!P.total || (!P.resolved && !newN)) { el.hidden = true; return; }
  const first = el.hidden || !el.firstElementChild;
  el.hidden = false;
  if (first) el.innerHTML = `
    <div class="board">
      <button class="tile ok" data-go="done"><span class="n num" id="b-done">0</span><span class="l">Fixed &amp; verified</span></button>
      <button class="tile warn" data-go="open"><span class="n num" id="b-att">0</span><span class="l">Need attention</span></button>
      <button class="tile" data-go="open"><span class="n num" id="b-open">0</span><span class="l">Not fixed yet</span></button>
    </div>
    <div class="p-bar" role="progressbar" aria-label="Findings fixed and verified" aria-valuemin="0"><span class="v" id="p-v"></span><span class="pending" id="p-u"></span></div>
    <div class="p-meta"><span id="p-pct"></span><a href="#fresh" class="p-new" id="p-new" hidden></a></div>`;
  el.querySelector('.board').onclick = (e) => { const b = e.target.closest('[data-go]'); if (b) { state.status = b.dataset.go; refresh(true); } };
  const set = (id, v) => { const n = $(id); const from = +(n.dataset.n || 0); n.dataset.n = v; if (first || reduced) n.textContent = v; else countUp(n, v, String, 500, from); };
  set('#b-done', P.verified); set('#b-att', P.attention ?? (P.resolved - P.verified)); set('#b-open', P.open ?? (P.total - P.resolved));
  el.querySelector('.tile.warn').classList.toggle('zero', !(P.attention ?? 0));
  const bar = el.querySelector('.p-bar');
  bar.setAttribute('aria-valuemax', P.total); bar.setAttribute('aria-valuenow', P.verified);
  const att = P.attention ?? (P.resolved - P.verified);
  const setW = () => { $('#p-v').style.width = `${(P.verified / P.total) * 100}%`; $('#p-u').style.width = `${(att / P.total) * 100}%`; };
  if (first && !reduced) { $('#p-v').style.width = $('#p-u').style.width = '0'; requestAnimationFrame(() => requestAnimationFrame(setW)); } else setW();
  $('#p-pct').textContent = `${Math.round((P.verified / P.total) * 100)}% done`;
  const pn = $('#p-new'); pn.hidden = !newN; pn.textContent = `${newN} new issue${newN === 1 ? '' : 's'} in your changes`;
}

/* ── new issues the fixes introduced (rule hits on lines changed since the scan) ── */
function freshPanel() {
  const list = D.newIssues || [];
  const el = $('#fresh-root');
  if (!list.length) { el.innerHTML = ''; return; }
  el.innerHTML = `<section class="panel fresh" id="fresh" aria-labelledby="fresh-h">
    <h2 id="fresh-h">${icon('alert')}New since the scan <span class="count">${list.length}</span></h2>
    <p class="muted-note">Rule hits on lines changed after the scan, probably introduced by the fixes. They aren't reviewed yet: fix them, or run a new scan to triage them.</p>
    <ul>${list.map((n) => `<li style="${sevVar(n.severity)}"><span class="sev-badge ${esc(n.severity)}"><span class="d"></span>${esc(n.severity)}</span><span class="mono loc">${esc(n.file)}:${n.line}</span><span class="t">${esc(n.title)}</span><code class="mono">${esc(n.code)}</code></li>`).join('')}</ul>
  </section>`;
}

function countUp(el, to, fmt, dur, from = 0) {
  if (reduced || (!to && !from)) { el.textContent = fmt(to); return; }
  const t0 = performance.now();
  const step = (t) => {
    const p = Math.min(1, (t - t0) / dur);
    el.textContent = fmt(Math.round(from + (to - from) * (1 - Math.pow(1 - p, 3))));
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}
function relTime(iso) {
  const s = (Date.now() - new Date(iso)) / 1000;
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  if (s < 60) return rtf.format(-Math.round(s), 'second');
  if (s < 3600) return rtf.format(-Math.round(s / 60), 'minute');
  if (s < 86400) return rtf.format(-Math.round(s / 3600), 'hour');
  return rtf.format(-Math.round(s / 86400), 'day');
}

/* ── trust / prompt-injection banner ── */
function trustBanner() {
  const t = D.meta.trust || { level: 'unknown', reasons: [] };
  const inj = D.meta.injectionHits || 0;
  const injFound = D.findings.filter((f) => f.category === 'prompt-injection').length;
  if (t.level === 'trusted' && !inj) return;
  const danger = t.level === 'untrusted' || injFound > 0;
  const head = injFound
    ? `${injFound} attempt${injFound > 1 ? 's' : ''} to manipulate AI reviewers`
    : t.level === 'untrusted' ? 'You reviewed untrusted code' : t.level === 'caution' ? 'Public code: review with care' : 'Code origin could not be verified';
  $('#trust-root').innerHTML = `<section class="trust reveal ${danger ? 'danger' : ''}" role="note" aria-label="Untrusted code warning">
    <span class="ti">${icon('alert')}</span>
    <div><b>${esc(head)}</b>
      <div class="trust-context" id="trust-why" hidden>
      <p>CodeHawk reads scanned content as data. Have a person verify security-critical results and run the scanned code only if you trust it.</p>
      <ul>${t.reasons.map((r) => `<li>${rich(r)}</li>`).join('')}${inj ? `<li>${inj} line${inj > 1 ? 's' : ''} matched prompt-injection or hidden-character rules${injFound ? '' : ' (all reviewed and cleared)'}.</li>` : ''}</ul></div>
    </div>
    <div class="trust-actions">
      ${injFound ? `<button class="btn tbtn" id="trust-show">${icon('eye')}View findings</button>` : ''}
      <button class="btn ghost tbtn" id="trust-more" aria-controls="trust-why" aria-expanded="false">Details</button>
    </div>
  </section>`;
  const more = $('#trust-more');
  if (more) more.onclick = () => { const u = $('#trust-why'); u.hidden = !u.hidden; more.setAttribute('aria-expanded', !u.hidden); more.textContent = u.hidden ? 'Details' : 'Hide details'; };
  const show = $('#trust-show');
  if (show) show.onclick = () => { state.sev.clear(); state.file = null; state.q = ''; state.kind = 'all'; state.status = 'all'; state.cat = 'prompt-injection'; $('#q').value = ''; refresh(true); };
}

/* ── insights ── */
function insights() {
  if (!D.findings.length) { $('#insights').hidden = true; return; }
  const maxC = Math.max(...D.categories.map((c) => c.count));
  const CAT_MAX = 7;
  $('#cat-bars').innerHTML = D.categories.map((c, i) => `
    <button class="bar-row" data-cat="${esc(c.key)}" aria-pressed="false" ${i >= CAT_MAX ? 'hidden data-more' : ''}>
      <span class="lbl">${esc(c.label)}</span>
      <span class="track"><span class="fill" style="width:${(c.count / maxC) * 100}%;animation-delay:${0.08 + Math.min(i, 5) * 0.025}s"></span></span>
      <span class="c">${c.count}</span>
    </button>`).join('');
  if (D.categories.length > CAT_MAX) {
    const more = document.createElement('button');
    more.className = 'btn ghost sm more-btn';
    const label = (open) => (open ? 'Show fewer' : `Show ${D.categories.length - CAT_MAX} more`);
    more.textContent = label(false);
    more.setAttribute('aria-expanded', 'false');
    more.onclick = () => {
      const open = more.getAttribute('aria-expanded') !== 'true';
      $('#cat-bars').querySelectorAll('[data-more]').forEach((b) => { b.hidden = !open; if (open && !reduced) b.animate?.([{ opacity: 0, transform: 'translateY(-4px)' }, { opacity: 1, transform: 'none' }], { duration: 240, easing: 'cubic-bezier(.22,1,.36,1)' }); });
      more.setAttribute('aria-expanded', open); more.textContent = label(open);
    };
    $('#cat-bars').after(more);
  }
  $('#file-bars').innerHTML = D.files.slice(0, 7).map((f) => {
    const pips = SEVS.flatMap((s) => Array(f.bySev[s] || 0).fill(s)).slice(0, 10).map((s) => `<i style="${sevVar(s)}" title="${s}"></i>`).join('');
    return `<button class="bar-row file-row" data-file="${esc(f.path)}" aria-pressed="false" title="${esc(f.path)}">
      <span class="lbl"><bdi>${esc(f.path)}</bdi></span><span class="pips">${pips}</span><span class="c">${f.count}</span></button>`;
  }).join('');
  $('#cat-bars').onclick = (e) => { const b = e.target.closest('[data-cat]'); if (b) { state.cat = state.cat === b.dataset.cat ? null : b.dataset.cat; refresh(true); } };
  $('#file-bars').onclick = (e) => { const b = e.target.closest('[data-file]'); if (b) { state.file = state.file === b.dataset.file ? null : b.dataset.file; refresh(true); } };
}

/* ── workspace ── */
function workspace() {
  const wr = $('#work-root');
  if (!D.findings.length) {
    $('#findings-count').textContent = '';
    wr.innerHTML = `<div class="clean reveal"><div class="big">${icon('shield-check')}</div>
      <h2>No security issues confirmed</h2>
      <p>CodeHawk read ${D.meta.filesScanned.toLocaleString()} file${D.meta.filesScanned === 1 ? '' : 's'} in this scope and triaged ${D.meta.candidates} rule hit${D.meta.candidates === 1 ? '' : 's'}. ${D.meta.candidates ? 'Every hit was checked and cleared; see the reasons below.' : ''}</p></div>`;
    return;
  }
  wr.innerHTML = `
  <div class="work">
    <section class="list-pane" aria-label="Findings list">
      <div class="toolbar">
        <div class="tabs" role="group" aria-label="Review track">
          <button data-kind="all">All <span class="n">${D.findings.length}</span></button>
          <button data-kind="security">Security <span class="n">${D.kindCounts?.security ?? D.findings.length}</span></button>
          <button data-kind="quality">Quality <span class="n">${D.kindCounts?.quality ?? 0}</span></button>
        </div>
        <label class="search"><span class="sr">Search findings</span>${icon('search')}<input id="q" type="search" placeholder="Search title, file, CWE…" autocomplete="off"><kbd>/</kbd></label>
        <div class="row-between">
          <div class="seg" role="group" aria-label="Status">
            <button data-status="open" title="Not fixed yet, or fixed with checks still missing">To do<span class="n" id="n-open"></span></button><button data-status="done" title="Fixed, with all four checks passed">Verified<span class="n" id="n-res">${P.verified}</span></button><button data-status="triaged">Triaged</button><button data-status="all">All</button>
          </div>
          <div class="chips" id="sev-chips" role="group" aria-label="Severity">${SEVS.filter((s) => D.counts[s]).map((s) => `<button class="chip" style="${sevVar(s)}" data-sev="${s}" aria-pressed="false" title="${cap(s)}"><span class="d"></span>${D.counts[s]}</button>`).join('')}</div>
        </div>
        <div class="active-filters" id="active-filters"></div>
      </div>
      <ul class="list" id="list" role="listbox" aria-label="Findings" tabindex="0"></ul>
      <div class="list-foot"><span id="list-count"></span><span><kbd>j</kbd>/<kbd>k</kbd> to move</span></div>
    </section>
    <article class="detail" id="detail" aria-live="polite"></article>
  </div>`;
  const q = $('#q');
  q.value = state.q;
  let qt;
  q.oninput = () => { clearTimeout(qt); qt = setTimeout(() => { state.q = q.value.trim(); refresh(false); }, 80); };
  $('.tabs').onclick = (e) => { const b = e.target.closest('[data-kind]'); if (b) { state.kind = b.dataset.kind; refresh(false); } };
  $('.seg').onclick = (e) => { const b = e.target.closest('[data-status]'); if (b) { state.status = b.dataset.status; refresh(false); } };
  $('#sev-chips').onclick = (e) => { const b = e.target.closest('[data-sev]'); if (b) toggleSev(b.dataset.sev); };
  $('#active-filters').onclick = (e) => {
    const b = e.target.closest('[data-clear]'); if (!b) return;
    const k = b.dataset.clear;
    if (k === 'all') return clearAll();
    else if (k === 'cat') state.cat = null; else if (k === 'file') state.file = null; else if (k === 'q') { state.q = ''; $('#q').value = ''; }
    else state.sev.delete(k);
    refresh(false);
  };
  $('#list').onclick = (e) => { const li = e.target.closest('[data-id]'); if (li) select(li.dataset.id, true); };
}

function clearAll() {
  state.sev.clear(); state.cat = state.file = null; state.q = ''; state.status = 'all'; state.kind = 'all';
  if ($('#q')) $('#q').value = '';
  refresh(false);
}

function toggleSev(s) {
  if (!D.counts[s]) return;
  state.sev.has(s) ? state.sev.delete(s) : state.sev.add(s);
  refresh(true);
}

function visible() {
  const q = state.q.toLowerCase();
  return D.findings.filter((f) => {
    const t = triage[f.id];
    if (state.kind !== 'all' && f.kind !== state.kind) return false;
    if (state.status === 'open' && (isDone(f) || (t && !isRes(f)))) return false;
    if (state.status === 'done' && !isDone(f)) return false;
    if (state.status === 'triaged' && (!t || isRes(f))) return false;
    if (state.sev.size && !state.sev.has(f.severity)) return false;
    if (state.cat && f.category !== state.cat) return false;
    if (state.file && f.file !== state.file) return false;
    if (q && !`${f.id} ${f.title} ${f.file} ${f.cwe} ${f.cweName || ''} ${f.owasp || ''} ${f.categoryLabel} ${f.description} ${f.dep ? `${f.dep.name} ${f.dep.advisories.map((a) => [a.id, ...a.aliases].join(' ')).join(' ')}` : ''}`.toLowerCase().includes(q)) return false;
    return true;
  });
}

let firstRender = true, pinSel = false;
function refresh(scrollToList) {
  if (!D.findings.length) return;
  document.querySelectorAll('[data-sev]').forEach((b) => b.setAttribute('aria-pressed', state.sev.has(b.dataset.sev)));
  document.querySelectorAll('[data-cat]').forEach((b) => b.setAttribute('aria-pressed', state.cat === b.dataset.cat));
  document.querySelectorAll('[data-file]').forEach((b) => b.setAttribute('aria-pressed', state.file === b.dataset.file));
  document.querySelectorAll('[data-status]').forEach((b) => b.setAttribute('aria-pressed', state.status === b.dataset.status));
  document.querySelectorAll('[data-kind]').forEach((b) => b.setAttribute('aria-pressed', state.kind === b.dataset.kind));

  const af = [];
  for (const s of state.sev) af.push(`<button class="chip" aria-pressed="true" style="${sevVar(s)}" data-clear="${s}"><span class="d"></span>${cap(s)}${icon('x')}</button>`);
  if (state.cat) af.push(`<button class="chip" aria-pressed="true" data-clear="cat">${esc(D.categories.find((c) => c.key === state.cat)?.label || state.cat)}${icon('x')}</button>`);
  if (state.file) af.push(`<button class="chip mono" aria-pressed="true" data-clear="file">${esc(state.file.split('/').pop())}${icon('x')}</button>`);
  if (state.q) af.push(`<button class="chip" aria-pressed="true" data-clear="q">“${esc(state.q)}”${icon('x')}</button>`);
  $('#active-filters').innerHTML = af.join('');

  const items = visible();
  const nTriaged = Object.keys(triage).filter((k) => D.findings.some((f) => f.id === k && !isRes(f))).length;
  const nOpen = D.findings.filter((f) => !isDone(f) && !(triage[f.id] && !isRes(f))).length;
  $('#n-open').textContent = nOpen;
  $('#n-res').textContent = P.verified;
  $('#findings-count').textContent = `${D.findings.length} total${P.resolved ? ` · ${P.resolved} resolved` : ''}${nTriaged ? ` · ${nTriaged} triaged by you` : ''}`;
  $('#list-count').textContent = `${items.length} of ${D.findings.length} shown`;
  const list = $('#list');
  const filtered = state.sev.size || state.cat || state.file || state.q || state.kind !== 'all';
  if (!items.length && state.status === 'open' && !filtered && P.verified) {
    list.innerHTML = `<li class="list-empty done"><div class="big">${icon('check')}</div><b>Nothing left to do</b>${P.verified} of ${P.total} findings fixed and verified${nTriaged ? `, ${nTriaged} triaged` : ''}.${(D.newIssues || []).length ? `<br><span class="p-new">${D.newIssues.length} new issue(s) in your changes, see above.</span>` : ''}<br><button class="btn" data-show="done" style="margin-top:10px">View verified</button></li>`;
    list.querySelector('[data-show]').onclick = () => { state.status = 'done'; refresh(false); };
  } else if (!items.length) {
    list.innerHTML = `<li class="list-empty"><b>No findings match</b>${state.status === 'open' && nTriaged ? 'Triaged findings are hidden. ' : ''}<br><button class="btn" data-clear="all" style="margin-top:10px">Clear filters</button></li>`;
    list.querySelector('[data-clear]').onclick = clearAll;
  } else {
    list.innerHTML = items.map((f, i) => {
      const t = triage[f.id], r = f.resolution;
      return `<li class="item ${r ? (r.verified ? 'resolved' : 'partial') : t ? 'dim' : ''}" role="option" id="finding-${esc(f.id)}" data-id="${esc(f.id)}" aria-selected="false" style="${sevVar(f.severity)};animation-delay:${firstRender ? Math.min(i, 5) * 0.025 : 0}s${firstRender ? '' : ';animation:none'}">
        <span class="rail"></span>
        <div><div class="t">${esc(f.title)}</div>
        <div class="m">${f.kind === 'quality' ? `<span class="kind">${QLEVEL[f.severity]}</span>` : ''}<span class="mono">${esc(f.file.split('/').pop())}:${f.line}</span>${f.kind === 'quality' && f.categoryLabel === QLEVEL[f.severity] ? '' : `<span>${esc(f.categoryLabel)}</span>`}${f.cwe ? `<span>${esc(f.cwe)}</span>` : ''}${r ? resTag(r) : t ? `<span class="tag">${t === 'fp' ? 'False positive' : 'Accepted'}</span>` : ''}<span class="q" ${queue.has(f.id) ? '' : 'hidden'}>${icon('wrench')}Queued</span></div></div>
      </li>`;
    }).join('');
  }
  firstRender = false;
  requestAnimationFrame(() => syncIndicators(document.querySelector('.toolbar') || document));
  // A finding that was just resolved while you were reading it stays in the detail pane.
  if (!state.sel || (!items.some((f) => f.id === state.sel) && !(pinSel && D.findings.some((f) => f.id === state.sel)))) state.sel = items[0]?.id || null;
  pinSel = false;
  renderDetail();
  writeHash();
  if (scrollToList) {
    closeDetail(false);
    $('#findings').focus();
  }
  if (!state.sel) closeDetail(false);
}

function select(id, fromUser) {
  state.sel = id;
  renderDetail();
  writeHash();
  if (fromUser) openDetail();
}

const compact = matchMedia('(max-width: 900px)');
function openDetail() {
  if (!compact.matches || !state.sel) return;
  document.body.classList.add('detail-open');
  syncIndicators($('#detail'), false);
  $('#back')?.focus({ preventScroll: true });
  $('#findings').scrollIntoView({ block: 'start' });
}

function closeDetail(restoreFocus = true) {
  if (!document.body.classList.contains('detail-open')) return;
  document.body.classList.remove('detail-open');
  if (restoreFocus && compact.matches) $('#list')?.focus();
}
compact.addEventListener('change', () => closeDetail(false));

/* ── detail ── */
let popCard = false, quietDetail = false, tickedNow = new Set(); // live updates re-render the detail without the swap animation
function renderDetail() {
  document.querySelectorAll('#list [data-id]').forEach((li) => {
    const on = li.dataset.id === state.sel;
    li.setAttribute('aria-selected', on);
    if (on) { // keep the selected row visible inside the list only; never scroll the page
      const list = li.parentElement, top = li.offsetTop - list.offsetTop;
      if (top < list.scrollTop) list.scrollTop = top - 6;
      else if (top + li.offsetHeight > list.scrollTop + list.clientHeight) list.scrollTop = top + li.offsetHeight - list.clientHeight + 6;
    }
  });
  const det = $('#detail');
  const previous = det.querySelector('.detail-inner');
  const animateSwap = !quietDetail && !popCard &&
    (previous?.dataset.finding !== state.sel || (compact.matches && !document.body.classList.contains('detail-open')));
  const selected = $('#list [aria-selected="true"]');
  if (selected) $('#list').setAttribute('aria-activedescendant', selected.id);
  else $('#list').removeAttribute('aria-activedescendant');
  const f = D.findings.find((x) => x.id === state.sel);
  if (!f) { det.innerHTML = `<div class="detail-inner list-empty"><b>Nothing selected</b>Pick a finding from the list.</div>`; return; }
  const t = triage[f.id], r = f.resolution;
  const confN = { high: 3, medium: 2, low: 1 }[f.confidence] || 2;
  const cweNum = f.cwe ? f.cwe.replace(/\D/g, '') : null;
  det.innerHTML = `<div class="detail-inner ${animateSwap ? 'swap' : ''} ${r ? 'is-resolved' : ''}" data-finding="${esc(f.id)}" style="${sevVar(f.severity)}">
    <button class="btn ghost back" id="back">${icon('back')}Findings</button>
    <div class="d-head"><span class="sev-badge ${f.severity}"><span class="d"></span>${sevLabel(f)}</span><span class="d-id">${esc(f.id)}</span>${r ? resTag(r, true) : ''}</div>
    <h3>${esc(f.title)}</h3>
    <div class="d-loc">${icon('file')}${f.link && safeUrl(f.link) !== '#' ? `<a href="${esc(safeUrl(f.link))}" target="_blank" rel="noopener">${esc(f.file)}:${f.line}${f.endLine > f.line ? '–' + f.endLine : ''}</a>` : `${esc(f.file)}:${f.line}${f.endLine > f.line ? '–' + f.endLine : ''}`}</div>
    <div class="meta-chips">
      <span class="mchip ${f.kind === 'quality' ? 'kind-q' : ''}">${f.kind === 'quality' ? 'Code quality' : 'Security'}</span>
      <span class="mchip">${esc(f.categoryLabel)}</span>
      ${Number.isFinite(f.scoreDeduction) ? `<span class="mchip">${r?.verified ? `Deduction cleared (${f.scoreDeduction} pts)` : `−${f.scoreDeduction} points`}</span>` : ''}
      ${f.cwe ? `<span class="mchip" title="${esc(f.cweName || f.cwe)}"><a href="https://cwe.mitre.org/data/definitions/${cweNum}.html" target="_blank" rel="noopener">${esc(f.cwe)}${f.cweName ? ` · ${esc(f.cweName)}` : ''}</a></span>` : ''}
      ${f.top25 ? `<span class="mchip t25" title="Ranked #${f.top25} in MITRE's 2024 CWE Top 25 Most Dangerous Software Weaknesses">CWE Top 25 #${f.top25}</span>` : ''}
      ${f.owasp ? `<span class="mchip" title="OWASP Top 10 (2021)"><a href="${esc(owaspUrl(f.owasp))}" target="_blank" rel="noopener">OWASP ${esc(f.owasp.slice(0, 3))} · ${esc(f.owaspName || '')}</a></span>` : ''}
      <span class="mchip" title="How sure the reviewer is that this is exploitable">Confidence <span class="conf">${[1, 2, 3].map((n) => `<i class="${n <= confN ? 'on' : ''}"></i>`).join('')}</span> ${esc(f.confidence)}</span>
      <span class="mchip">${icon(f.source === 'review' ? 'sparkle' : 'bolt')}${f.source === 'review' ? 'Found in review' : 'Rule + review'}</span>
    </div>
    ${r ? resolutionCard(r) : ''}
    <div class="actions">
      <div class="action-buttons">
        ${r ? '' : `<button class="btn primary" data-act="queue" data-id="${esc(f.id)}" aria-pressed="false">${icon('wrench')}Queue fix</button>`}
        ${r ? '' : `<button class="btn" data-act="prompt">${icon('sparkle')}Copy prompt</button>`}
        ${f.fix ? `<button class="btn icon" data-act="patch" title="Copy fixed code" aria-label="Copy fixed code">${icon('copy')}</button>` : ''}
        ${r ? `<button class="btn ghost" data-act="link">${icon('link')}Copy link</button>` : `<button class="btn icon" data-act="link" title="Copy link to this finding" aria-label="Copy link">${icon('link')}</button>`}
      </div>
      ${r ? '' : `<span class="tri" role="group" aria-label="Your triage">
        <button data-act="open" aria-pressed="${!t}">Open</button>
        <button data-act="fp" aria-pressed="${t === 'fp'}">False positive</button>
        <button data-act="accept" aria-pressed="${t === 'accepted'}">Accepted</button>
      </span>`}
    </div>
    ${r ? '' : `<div class="fix-note">${icon('lock')}${f.fix ? 'Has a ready patch.' : 'This fix needs a proposed change.'} Queued fixes are applied only after you approve each change; nothing is committed or merged automatically.</div>`}
    ${t && !r ? `<div class="triage-note">${icon('check')}You marked this as ${t === 'fp' ? 'a false positive' : 'an accepted risk'}. Stored only in this browser.</div>` : ''}

    <div class="d-section"><h4>What's wrong</h4><p>${rich(f.description)}</p></div>
    ${f.dep?.advisories?.length ? advisories(f.dep) : ''}
    ${f.snippet ? `<div class="d-section">${codeBlock(f)}</div>` : ''}
    ${(f.impact || f.exploit) ? `<div class="d-section two">
      ${f.impact ? `<div><h4>${icon('target')}${f.kind === 'quality' ? 'Why it matters' : 'Impact'}</h4><div class="callout"><p>${rich(f.impact)}</p></div></div>` : ''}
      ${f.exploit ? `<div><h4>${icon('bolt')}How it could be exploited</h4><div class="callout exploit"><p>${rich(f.exploit)}</p></div></div>` : ''}
    </div>` : ''}
    <div class="d-section"><h4>${icon('wrench')}${r ? 'Recommended fix' : f.kind === 'quality' ? 'Suggestion' : 'How to fix'}</h4><p>${rich(f.fixText)}</p></div>
    ${f.fix ? `<div class="d-section">${diffBlock(f)}</div>` : ''}
    ${f.references?.length ? `<div class="d-section"><h4>References</h4><ul class="refs">${f.references.map((r) => `<li><a href="${esc(safeUrl(r))}" target="_blank" rel="noopener">${icon('ext')}${esc(r)}</a></li>`).join('')}</ul></div>` : ''}
  </div>`;
  if (tickedNow.size) { tickedNow.forEach((k) => det.querySelector(`.checks [data-step="${k}"]`)?.classList.add('ticked')); tickedNow = new Set(); }
  if (popCard) det.querySelector('.resolution')?.classList.add('enter');
  popCard = quietDetail = false;
  syncIndicators(det, false);
  det.querySelector('#back').onclick = () => closeDetail();
  det.querySelector('.actions').onclick = (e) => {
    const b = e.target.closest('[data-act]'); if (!b) return;
    const a = b.dataset.act;
    if (a === 'prompt') copy(fixPrompt(f), 'Fix prompt copied');
    else if (a === 'patch') copy(f.fix.after.join('\n'), 'Fixed code copied');
    else if (a === 'link') copy(location.href.split('#')[0] + '#id=' + encodeURIComponent(f.id), 'Link copied');
    else if (a === 'queue') toggleQueue(f.id);
    else {
      const v = a === 'fp' ? 'fp' : a === 'accept' ? 'accepted' : null;
      if (!v || triage[f.id] === v) delete triage[f.id]; else triage[f.id] = v;
      if (v === 'fp' && queue.has(f.id)) { queue.delete(f.id); saveQueue(); }
      saveTriage();
      const keep = state.sel;
      refresh(false);
      if (D.findings.some((x) => x.id === keep) && visible().some((x) => x.id === keep)) select(keep);
      toast(triage[f.id] ? (v === 'fp' ? 'Marked as false positive' : 'Risk accepted') : 'Reopened');
    }
  };
  tray();
}

function resolutionCard(r) {
  const when = r.verifiedAt || r.at;
  return `<div class="resolution ${r.verified ? '' : 'partial'}" role="status">
    <span class="r-ic">${icon('check')}</span>
    <div>
      <div class="r-title">Resolved<span class="r-badge ${r.verified ? '' : 'pending'}">${r.verified ? 'Verified · 4 of 4 checks' : `${r.passed} of 4 checks`}</span></div>
      <div class="r-meta">${esc(METHOD[r.method] || 'Fixed')}${when ? ` · <time datetime="${esc(when)}" title="${esc(new Date(when).toLocaleString())}">${esc(relTime(when))}</time>` : ''} · in your working tree, not committed</div>
      ${r.note ? `<p class="r-note">${rich(r.note)}</p>` : ''}
      <ol class="checks" aria-label="Fix checklist">${STEPS.map(([k, label]) => {
        const st = r.steps?.[k] || {};
        const auto = st.ok && (st.by === 'rules' || (k === 'changed' && !/^fixed in /.test(st.detail || '')));
        return `<li class="${st.ok ? 'ok' : ''}" data-step="${k}"><span class="cb" aria-hidden="true">${st.ok ? icon('check') : ''}</span><div><div class="ch"><span class="sr">${st.ok ? 'Done' : 'Not done'}: </span><b>${label}</b>${auto ? '<span class="auto">auto</span>' : ''}</div><div class="cd">${rich(st.detail || '')}</div></div></li>`;
      }).join('')}</ol>
    </div>
  </div>`;
}

function owaspUrl(id) {
  const name = (D.standards?.owasp || []).find((o) => o.id === id)?.name || '';
  return `https://owasp.org/Top10/${id.replace(':', '_')}-${name.replace(/ /g, '_').replace('Server-Side_Request_Forgery', 'Server-Side_Request_Forgery_%28SSRF%29')}/`;
}
function advisories(d) {
  const rows = d.advisories.map((a) => `<tr>
    <td class="mono"><a href="${esc(safeUrl(a.url))}" target="_blank" rel="noopener">${esc(a.cves[0] || a.id)}</a>${a.cves[0] && a.cves[0] !== a.id ? `<br><small class="muted">${esc(a.id)}</small>` : ''}</td>
    <td><span class="sev-badge ${esc(a.severity)}" style="${sevVar(a.severity)}"><span class="d"></span>${esc(a.malicious ? 'malicious' : a.severity)}</span></td>
    <td class="cv" title="${esc(a.cvss?.vector || '')}">${a.cvss?.score != null ? a.cvss.score.toFixed(1) : a.cvss ? 'v' + esc(a.cvss.version) : '–'}</td>
    <td class="mono">${a.malicious ? '–' : a.fixed ? esc(a.fixed) : '<span class="muted">fixed release unverified</span>'}</td>
    <td class="sum">${esc(a.summary || '')}</td></tr>`).join('');
  return `<div class="d-section"><h4>${icon('shield')}Known vulnerabilities in <span class="mono">${esc(d.name)}@${esc(d.version)}</span>${d.dev ? ' <small class="muted">(dev dependency)</small>' : ''}</h4>
    <table class="adv"><thead><tr><th>Advisory</th><th>Severity</th><th>CVSS</th><th>Fixed in</th><th>Summary</th></tr></thead><tbody>${rows}</tbody></table>
    ${d.fixTo ? `<p class="upgrade">${icon('wrench')}Upgrade candidate for <span class="mono">${esc(d.name)}</span> <b class="mono">${esc(d.fixTo)}</b>. Recheck the exact version after upgrading.</p>` : ''}
    <p class="muted-note">From OSV.dev · ${esc(d.ecosystem)}${d.purl ? ` · <span class="mono">${esc(d.purl)}</span>` : ''}</p></div>`;
}
function standards() {
  const S = D.standards, dp = D.deps;
  const hasOwasp = S && S.owasp.some((o) => o.count);
  if (!hasOwasp && !S?.top25?.length && !(dp && dp.status !== 'skipped')) return;
  const el = $('#standards-root');
  el.hidden = false;
  const maxO = Math.max(1, ...(S?.owasp || []).map((o) => o.count));
  const owasp = (S?.owasp || []).map((o, i) => `
    <button class="bar-row owasp-row ${o.count ? '' : 'zero'}" data-q="${esc(o.id)}" ${o.count ? '' : 'disabled'} title="${esc(o.id)} ${esc(o.name)}${o.count ? ' — click to filter' : ''}">
      <span class="lbl"><b>${esc(o.id.slice(0, 3))}</b>${esc(o.name)}</span>
      <span class="track"><span class="fill" style="width:${(o.count / maxO) * 100}%;animation-delay:${0.08 + Math.min(i, 5) * 0.025}s"></span></span>
      <span class="c">${o.count}</span>
    </button>`).join('');
  const t25 = S?.top25?.length
    ? `<ul class="std-list">${S.top25.map((t) => `<li><span class="rk">#${t.rank}</span><span><a href="https://cwe.mitre.org/data/definitions/${t.cwe.replace(/\D/g, '')}.html" target="_blank" rel="noopener">${esc(t.cwe)}</a> ${esc(t.name || '')}</span><span class="c">${t.count}</span></li>`).join('')}</ul>`
    : `<p class="muted-note">None of the findings fall in the 2024 CWE Top 25.</p>`;
  let depHtml = '';
  if (dp && dp.status !== 'skipped') {
    const st = { ok: '', partial: `OSV lookup incomplete for ${dp.incomplete} coordinates. Retained ${dp.advisories} advisory matches.`, offline: 'Not checked for known vulnerabilities: the scan ran with --offline.', error: `The OSV.dev lookup failed (${dp.error || 'network error'}), so known vulnerabilities were not checked.`, none: 'No lockfiles found.', 'nothing-changed': 'This change does not touch any pinned dependency version.' }[dp.status] || '';
    depHtml = `<div class="std-sub">Dependencies</div>
      <div class="dep-stats"><span><b>${dp.packages || 0}</b> pinned in ${dp.lockfiles?.length || 0} lockfile${dp.lockfiles?.length === 1 ? '' : 's'}</span>${dp.status === 'ok' ? `<span><b>${dp.checked}</b> checked${dp.scope === 'changed' ? ' (changed)' : ''}</span><span><b>${dp.vulnerable}</b> vulnerable</span><span><b>${dp.advisories}</b> advisories</span>` : ''}</div>
      ${st ? `<p class="${dp.status === 'offline' || dp.status === 'error' ? 'dep-warn' : 'muted-note'}">${esc(st)}</p>` : ''}
      ${dp.vulnerable ? `<button class="btn sm" data-q="vulnerable-dependency" style="margin-top:10px">${icon('shield')}Show vulnerable dependencies</button>` : ''}
      ${dp.sbom ? `<p class="muted-note">SBOM (CycloneDX 1.5): <span class="mono">${esc(dp.sbom)}</span></p>` : ''}`;
  }
  el.innerHTML = `
    <div class="panel reveal"><h2>${icon('shield')}OWASP Top 10 (2021)</h2><div class="bars">${owasp}</div>${hasOwasp ? '' : '<p class="muted-note">No security findings to map.</p>'}</div>
    <div class="panel reveal"><h2>${icon('target')}CWE Top 25 (2024)</h2>${t25}${depHtml}</div>`;
  el.onclick = (e) => {
    const b = e.target.closest('[data-q]'); if (!b || b.disabled) return;
    if (b.dataset.q === 'vulnerable-dependency') { state.cat = state.cat === 'vulnerable-dependency' ? null : 'vulnerable-dependency'; state.q = ''; }
    else { state.q = state.q === b.dataset.q ? '' : b.dataset.q; const s = $('#q'); if (s) s.value = state.q; }
    refresh(true);
  };
}
function safeUrl(u) { return /^https?:\/\//i.test(u) ? u : '#'; }
// Minimal inline formatting: `code` spans, nothing else (content is model-written but escaped first).
function rich(s) { return esc(s).replace(/`([^`]+)`/g, '<code class="mono">$1</code>'); }

const KW = /\b(const|let|var|function|return|if|else|for|while|do|switch|case|break|continue|new|class|extends|import|from|export|default|async|await|try|catch|finally|throw|typeof|instanceof|in|of|this|super|null|undefined|true|false|def|lambda|pass|elif|with|as|yield|None|True|False|self|and|or|not|is|func|package|go|defer|chan|map|struct|interface|type|public|private|protected|static|final|void|int|string|bool|fn|let|mut|impl|pub|use|mod|match|unsafe|where|echo|require|include|end|then|fi|SELECT|FROM|WHERE|INSERT|UPDATE|DELETE|INTO|VALUES|AND|OR|FROM|RUN|ENV|USER|COPY|uses|run|with)\b/;
const TOK = /(\/\/.*$|#(?![{\[]).*$|\/\*.*?\*\/|--\s.*$)|("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`)|(\b\d[\d_.]*(?:e[+-]?\d+)?\b|\b0x[\da-f]+\b)|([A-Za-z_$][\w$]*)(?=\s*\()|([A-Za-z_$][\w$]*)/gi;
function hl(line, lang) {
  let out = '', last = 0, m;
  const hashComment = ['python', 'shell', 'ruby', 'yaml', 'gha', 'docker', 'terraform', 'env', 'text', 'config'].includes(lang);
  TOK.lastIndex = 0;
  while ((m = TOK.exec(line))) {
    out += esc(line.slice(last, m.index));
    const [t, com, str, num, fn, word] = m;
    if (com && (com[0] !== '#' || hashComment)) out += `<span class="tk-c">${esc(com)}</span>`;
    else if (com) out += esc(com);
    else if (str) out += `<span class="tk-s">${esc(str)}</span>`;
    else if (num) out += `<span class="tk-n">${esc(num)}</span>`;
    else if (fn) out += KW.test(fn) ? `<span class="tk-k">${esc(fn)}</span>` : `<span class="tk-f">${esc(fn)}</span>`;
    else if (word) out += KW.test(word) && word.match(KW)[0] === word ? `<span class="tk-k">${esc(word)}</span>` : esc(word);
    last = TOK.lastIndex;
    if (m[0] === '') TOK.lastIndex++;
  }
  return out + esc(line.slice(last));
}

function codeBlock(f) {
  const s = f.snippet;
  const rows = s.lines.map((l, i) => {
    const n = s.start + i;
    const on = n >= s.hl[0] && n <= s.hl[1];
    return `<div class="ln ${on ? 'hl' : ''}"><span class="no">${n}</span><span class="src">${hl(l, f.lang) || ' '}</span></div>`;
  }).join('');
  return `<div class="code"><div class="code-head"><span>${esc(f.file)}</span><button class="btn ghost" onclick="navigator.clipboard.writeText(${esc(JSON.stringify(s.lines.join('\n')))})">${icon('copy')}Copy</button></div><pre><code>${rows}</code></pre></div>`;
}
function diffBlock(f) {
  const { start, before, after } = f.fix;
  const rows = [
    ...before.map((l, i) => `<div class="ln del"><span class="no">${start + i}</span><span class="sg">−</span><span class="src">${hl(l, f.lang) || ' '}</span></div>`),
    ...after.map((l, i) => `<div class="ln add"><span class="no">${start + i}</span><span class="sg">+</span><span class="src">${hl(l, f.lang) || ' '}</span></div>`),
  ].join('');
  return `<div class="code diff"><div class="code-head"><span>Suggested change · ${esc(f.file)}</span><span class="muted">−${before.length} +${after.length}</span></div><pre><code>${rows}</code></pre></div>`;
}

function fixPrompt(f) {
  return [
    `Fix this ${f.kind === 'quality' ? 'code-quality' : 'security'} issue found by CodeHawk (${f.id}, ${sevLabel(f)}${f.cwe ? ', ' + f.cwe : ''}):`,
    ``,
    `**${f.title}** in \`${f.file}\` lines ${f.line}-${f.endLine}`,
    ``,
    f.description,
    f.impact ? `\nImpact: ${f.impact}` : '',
    ``,
    `Suggested fix: ${f.fixText}`,
    f.fix ? `\nProposed replacement for lines ${f.line}-${f.endLine}:\n\`\`\`\n${f.fix.after.join('\n')}\n\`\`\`` : '',
    ``,
    `Read the surrounding code first and fix the root cause (also check for the same pattern elsewhere). Keep behaviour otherwise unchanged, and add or update a test that proves the issue is fixed if the project has tests.`,
  ].filter((x) => x !== '').join('\n');
}

/* ── sliding indicators for segmented controls ── */
function syncIndicators(scope = document, animate = true) {
  scope.querySelectorAll('.tabs, .seg, .tri').forEach((g) => {
    let ind = g.querySelector(':scope > .ind');
    const shouldAnimate = animate && !!ind;
    if (!ind) { ind = document.createElement('span'); ind.className = 'ind'; ind.setAttribute('aria-hidden', 'true'); g.prepend(ind); }
    const on = g.querySelector('button[aria-pressed="true"]');
    if (!on) { ind.style.opacity = '0'; return; }
    if (!shouldAnimate) ind.style.transition = 'none';
    ind.style.opacity = '1';
    ind.style.width = `${on.offsetWidth}px`;
    ind.style.transform = `translateX(${on.offsetLeft}px)`;
    if (!shouldAnimate) { ind.offsetWidth; ind.style.transition = ''; }
  });
}
addEventListener('resize', () => syncIndicators(document, false));

/* ── walkthrough ── */
function walkthrough() {
  const w = D.walkthrough;
  if (!w) return;
  const eff = w.effort ? `<span class="effort" title="Estimated review effort">Review effort ${[1, 2, 3, 4, 5].map((n) => `<i class="${n <= w.effort ? 'on' : ''}"></i>`).join('')} ${w.effort}/5</span>` : '';
  $('#walk-root').innerHTML = `<section class="panel walk reveal" aria-labelledby="walk-h">
    <h2 id="walk-h">${icon('git')}Walkthrough${eff}</h2>
    <p class="lead">${rich(w.summary)}</p>
    ${w.changes?.length ? `<table><thead><tr><th scope="col">Files</th><th scope="col">Change summary</th></tr></thead><tbody>
      ${w.changes.map((c) => `<tr><td class="files">${c.files.map((x) => `<div>${esc(x)}</div>`).join('')}</td><td>${rich(c.summary)}</td></tr>`).join('')}
    </tbody></table>` : ''}
  </section>`;
}

/* ── notes & cleared ── */
function extras() {
  if (D.notes?.length) $('#notes-root').innerHTML = `<div class="panel notes"><h2>Coverage notes</h2><ul>${D.notes.map((n) => `<li>${rich(n)}</li>`).join('')}</ul></div>`;
  const n = D.dismissed.reduce((s, d) => s + d.items.length, 0);
  if (!n) return;
  $('#cleared-root').innerHTML = `<details class="cleared" ${D.findings.length ? '' : 'open'}>
    <summary><span class="ok-badge">${icon('check')}</span><span>Checked and cleared <span class="muted">· ${n} rule hit${n > 1 ? 's' : ''} reviewed and dismissed</span></span>${icon('down').replace('class="i"', 'class="i chev"')}</summary>
    <div class="cleared-body">${D.dismissed.map((d) => `<div class="reason"><p>${rich(d.reason)}</p><ul>${d.items.map((c) => `<li><span class="mono">${esc(c.file)}:${c.line}</span><span>${esc(c.title)}</span></li>`).join('')}</ul></div>`).join('')}</div>
  </details>`;
}

/* ── export ── */
const menu = $('#export-menu');
$('#export-btn').onclick = (e) => { e.stopPropagation(); const o = menu.classList.toggle('open'); $('#export-btn').setAttribute('aria-expanded', o); if (o) menu.querySelector('[role=menuitem]').focus(); };
document.addEventListener('click', (e) => { if (!menu.contains(e.target)) { menu.classList.remove('open'); $('#export-btn').setAttribute('aria-expanded', 'false'); } });
menu.querySelector('.menu-pop').onclick = (e) => {
  const b = e.target.closest('[data-export]'); if (!b) return;
  menu.classList.remove('open');
  const slug = (D.meta.repo || 'codehawk') + '-' + (D.meta.mode) + (D.meta.pr ? '-' + D.meta.pr.number : '');
  if (b.dataset.export === 'md') copy(markdown(), 'PR comment copied');
  if (b.dataset.export === 'json') download(`${slug}.codehawk.json`, JSON.stringify({ ...D, sarif: undefined }, null, 2), 'application/json');
  if (b.dataset.export === 'sarif') download(`${slug}.sarif`, JSON.stringify(sarif(), null, 2), 'application/sarif+json');
};
function markdown() {
  const open = D.findings.filter((f) => !triage[f.id] && !isRes(f));
  const done = D.findings.filter(isRes);
  const lab = (f) => '`' + sevLabel(f).toUpperCase() + '`';
  const L = ['## CodeHawk review', '', `**Security ${D.grade}** (${D.score}/100) · **Code quality ${D.qualityGrade}** (${D.qualityScore}/100) · ${VERDICT[D.verdict][0]}`, `<sub>${D.meta.label}</sub>`, ''];
  if (P.resolved) L.push(`**Resolved ${P.resolved} of ${P.total}**${P.verified ? ` (${P.verified} verified)` : ''}`, '');
  if (D.summary) L.push(D.summary, '');
  if ((D.meta.trust && D.meta.trust.level !== 'trusted') || D.meta.injectionHits) L.push('> [!WARNING]', '> Reviewed code from an untrusted source. AI-assisted reviews can be manipulated by prompt injection; a clean result is not a guarantee.', '');
  if (D.walkthrough) {
    L.push('### Walkthrough', '', D.walkthrough.summary, '');
    if (D.walkthrough.changes?.length) L.push('| Files | Change summary |', '|---|---|', ...D.walkthrough.changes.map((c) => `| ${c.files.map((x) => '`' + x + '`').join('<br>')} | ${String(c.summary).replace(/\|/g, '\\|')} |`), '');
  }
  const block = (f) => {
    L.push(`<details><summary>${lab(f)} <b>${esc(f.title)}</b> — <code>${esc(f.file)}:${f.line}</code>${f.cwe ? ' · ' + f.cwe : ''}${f.owasp ? ' · OWASP ' + f.owasp.slice(0, 3) : ''}</summary>`, '', f.description, '');
    if (f.dep?.advisories?.length) L.push(...f.dep.advisories.slice(0, 10).map((a) => `- [${a.cves[0] || a.id}](${a.url})${a.cvss?.score != null ? ' · CVSS ' + a.cvss.score : ''} · ${a.severity}${a.malicious ? ' · malicious' : a.fixed ? ' · fixed in ' + a.fixed : ' · fixed release unverified'}`), '');
    if (f.impact) L.push(`**${f.kind === 'quality' ? 'Why it matters' : 'Impact'}:** ${f.impact}`, '');
    L.push(`**${f.kind === 'quality' ? 'Suggestion' : 'Fix'}:** ${f.fixText}`, '');
    if (f.fix) L.push('```diff', ...f.fix.before.map((l) => '- ' + l), ...f.fix.after.map((l) => '+ ' + l), '```', '');
    L.push('</details>');
  };
  const sec = open.filter((f) => f.kind !== 'quality'), q = open.filter((f) => f.kind === 'quality' && f.severity !== 'info'), nits = open.filter((f) => f.kind === 'quality' && f.severity === 'info');
  if (sec.length) { L.push(`### Security — ${sec.length}`, ''); sec.forEach(block); L.push(''); }
  if (q.length) { L.push(`### Code quality — ${q.length} actionable`, ''); q.forEach(block); L.push(''); }
  if (nits.length) L.push(`<details><summary><b>Nitpicks (${nits.length})</b></summary>`, '', ...nits.map((f) => `- \`${f.file}:${f.line}\` — **${esc(f.title)}.** ${f.fixText}`), '', '</details>');
  if (done.length) L.push('', `### Resolved — ${done.length}`, '', ...done.map((f) => `- ${f.resolution.verified ? '✅' : `⚠️ ${f.resolution.passed}/4`} ~~${esc(f.title)}~~ — \`${f.file}:${f.line}\` · ${METHOD[f.resolution.method] || 'Fixed'} · ${STEPS.map(([k, l]) => `${f.resolution.steps?.[k]?.ok ? '☑' : '☐'} ${l}`).join(' ')}`));
  if (!open.length) L.push('', done.length ? '_Every finding from this review has been resolved._' : '_No open issues._');
  return L.join('\n');
}
function sarif() {
  // The build's SARIF (with CWE / OWASP taxonomies), minus resolved findings and ones you marked as false positives here.
  const out = JSON.parse(JSON.stringify(D.sarif || { version: '2.1.0', runs: [{ tool: { driver: { name: 'CodeHawk', rules: [] } }, results: [] }] }));
  const resolved = new Set(D.findings.filter(isRes).map((f) => f.id));
  for (const run of out.runs) run.results = run.results.filter((r) => triage[r.properties?.findingId] !== 'fp' && !resolved.has(r.properties?.findingId));
  return out;
}
function download(name, text, type) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  toast(`Downloaded ${name}`);
}
async function copy(text, msg) {
  try { await navigator.clipboard.writeText(text); toast(msg); }
  catch {
    const ta = Object.assign(document.createElement('textarea'), { value: text });
    document.body.append(ta); ta.select();
    try { document.execCommand('copy'); toast(msg); } catch { toast('Copy failed — select the text manually'); }
    ta.remove();
  }
}
let tt;
function toast(msg) {
  const t = $('#toast'); t.querySelector('span').textContent = msg; t.classList.add('show');
  clearTimeout(tt); tt = setTimeout(() => t.classList.remove('show'), 2200);
}

/* ── keyboard ── */
document.addEventListener('keydown', (e) => {
  if (e.metaKey || e.ctrlKey || e.altKey) return;
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName);
  if (e.key === 'Escape') {
    if (typing) document.activeElement.blur();
    closeDetail(); menu.classList.remove('open');
    return;
  }
  if (typing) return;
  if (e.key === 'Enter' && document.activeElement === $('#list')) { e.preventDefault(); openDetail(); }
  else if (e.key === '/' && $('#q')) { e.preventDefault(); closeDetail(false); $('#q').focus(); $('#q').select(); }
  else if (e.key === 't') $('#theme-btn').click();
  else if (e.key === 'f' && state.sel) toggleQueue(state.sel);
  else if (/^[1-5]$/.test(e.key)) toggleSev(SEVS[+e.key - 1]);
  else if ((e.key === 'j' || e.key === 'k' || e.key === 'ArrowDown' || e.key === 'ArrowUp') && D.findings.length) {
    if (e.key.startsWith('Arrow') && document.activeElement !== $('#list')) return;
    e.preventDefault();
    const items = visible(); if (!items.length) return;
    const i = items.findIndex((f) => f.id === state.sel);
    const n = (e.key === 'j' || e.key === 'ArrowDown') ? Math.min(items.length - 1, i + 1) : Math.max(0, i - 1);
    select(items[n].id);
  }
});
for (const link of document.querySelectorAll('a[href="#findings"]')) {
  link.addEventListener('click', (event) => {
    if (event.ctrlKey || event.metaKey || event.altKey || event.shiftKey) return;
    event.preventDefault();
    closeDetail(false);
    $('#findings').focus({ preventScroll: true });
    $('#findings').scrollIntoView({ block: 'start' });
  });
}
window.addEventListener('hashchange', () => {
  if (location.hash && !location.hash.includes('=')) return;
  readHash();
  if (D.findings.length) {
    refresh(false);
    if (state.sel) openDetail();
  }
});

/* ── live updates: `fix.mjs resolve` rewrites live.js next to this report; we pick it up ── */
let liveRev = D.liveRev || 0, liveFails = 0, liveOn = !!D.liveRev && !still;
window.__codehawkLive = (m) => {
  liveFails = 0;
  if (!m || m.rev <= liveRev) return;
  liveRev = m.rev;
  if (m.scanId !== (D.meta.scanId || null)) { liveOn = false; $('#live-note').classList.add('show'); return; }
  applyLive(m);
};
function poll() {
  if (!liveOn || document.hidden) return;
  const sc = document.createElement('script');
  sc.src = `live.js?r=${Date.now()}`;
  sc.onload = () => sc.remove();
  sc.onerror = () => { sc.remove(); if (++liveFails >= 3) liveOn = false; }; // report moved away from its .codehawk folder
  document.head.append(sc);
}
// Served by serve.mjs: changes are pushed the moment they're written. Polling stays as a fallback
// for while the stream is down (and is all a file:// report has).
let pushing = false;
if (liveOn && window.__codehawkPush && window.EventSource) {
  let fails = 0;
  const es = new EventSource('events');
  es.onopen = () => { pushing = true; fails = 0; };
  es.addEventListener('live', (e) => { try { window.__codehawkLive(JSON.parse(e.data)); } catch {} });
  es.onerror = () => { pushing = false; if (++fails >= 5) es.close(); }; // server stopped: fall back to polling
}
if (liveOn) { setInterval(() => { if (!pushing) poll(); }, 1500); document.addEventListener('visibilitychange', () => { if (!pushing) poll(); }); }

function applyLive(m) {
  const changed = [];
  for (const f of D.findings) {
    const now = m.resolutions[f.id] ?? null;
    if (JSON.stringify(f.resolution ?? null) !== JSON.stringify(now)) { changed.push({ f, was: f.resolution, now }); f.resolution = now; }
  }
  Object.assign(P, m.progress || {});
  if (typeof m.score === 'number') {
    const { score, grade, qualityScore, qualityGrade, verdict } = m;
    Object.assign(D, { score, grade, qualityScore, qualityGrade, verdict });
    renderGrades();
  }
  const freshBefore = (D.newIssues || []).length, freshChanged = JSON.stringify(D.newIssues || []) !== JSON.stringify(m.newIssues || []);
  D.newIssues = m.newIssues || [];
  if (freshChanged) freshPanel();
  progress();
  if (!changed.length) {
    if (freshChanged && D.newIssues.length > freshBefore) toast(`${D.newIssues.length - freshBefore} new issue${D.newIssues.length - freshBefore === 1 ? '' : 's'} in your changes`);
    return;
  }
  for (const c of changed) if (c.now) queue.delete(c.f.id);
  saveQueue(); tray();
  const verifiedNow = changed.filter((c) => c.now?.verified && !c.was?.verified).map((c) => c.f);
  const backToDo = changed.filter((c) => c.was?.verified && !c.now?.verified).map((c) => c.f); // reopened, or a check that failed again
  const touched = changed.filter((c) => !verifiedNow.includes(c.f) && !backToDo.includes(c.f)).map((c) => c.f);
  const selC = changed.find((c) => c.f.id === state.sel);
  if (selC) {
    popCard = !!selC.now && !selC.was;
    // Animate just the boxes that got ticked in this update.
    tickedNow = new Set(selC.now && selC.was ? STEPS.map(([k]) => k).filter((k) => selC.now.steps?.[k]?.ok && !selC.was.steps?.[k]?.ok) : []);
  }
  const flash = (ids, cls) => ids.forEach((id) => { const li = document.querySelector(`#list [data-id="${CSS.escape(id)}"]`); if (li) { li.classList.remove(cls); void li.offsetWidth; li.classList.add(cls); } });
  // Only a fully verified fix leaves "To do"; a fix with checks missing stays, tagged with how many passed.
  const leaving = state.status === 'open' && !reduced ? verifiedNow.map((f) => document.querySelector(`#list [data-id="${CSS.escape(f.id)}"]`)).filter(Boolean) : [];
  if (leaving.length) {
    for (const li of leaving) {
      const f = D.findings.find((x) => x.id === li.dataset.id);
      li.classList.remove('partial'); li.classList.add('resolved', 'just-resolved');
      li.querySelector('.m .tag')?.remove(); li.querySelector('.m .res-tag')?.remove();
      li.querySelector('.m .q')?.insertAdjacentHTML('beforebegin', resTag(f.resolution));
    }
    if (verifiedNow.some((f) => f.id === state.sel)) { pinSel = true; renderDetail(); }
    setTimeout(() => {
      leaving.forEach((li) => { li.style.height = `${li.offsetHeight}px`; li.classList.add('leaving'); });
      setTimeout(() => { pinSel = quietDetail = true; refresh(false); flash(touched.map((f) => f.id), 'just-resolved'); flash(backToDo.map((f) => f.id), 'just-reopened'); }, 340);
    }, 1100);
  } else {
    pinSel = quietDetail = true;
    refresh(false);
    flash([...verifiedNow, ...touched.filter((f) => f.resolution)].map((f) => f.id), 'just-resolved');
    flash([...backToDo, ...touched.filter((f) => !f.resolution)].map((f) => f.id), 'just-reopened');
  }
  const one = changed.length === 1 ? changed[0] : null;
  toast(one ? (!one.now ? `${one.f.id} reopened` : one.now.verified ? `${one.f.id} fixed and verified · 4/4` : one.was?.verified ? `${one.f.id} needs attention again · ${one.now.passed}/4` : `${one.f.id} · ${one.now.passed}/4 checks passed`)
    : `${verifiedNow.length ? `${verifiedNow.length} verified` : ''}${verifiedNow.length && (changed.length - verifiedNow.length) ? ' · ' : ''}${changed.length - verifiedNow.length ? `${changed.length - verifiedNow.length} updated` : ''}`);
}

/* ── boot ── */
const deepLink = /(^|[#&])id=/.test(location.hash);
readHash();
trustBanner();
hero();
walkthrough();
insights();
standards();
freshPanel();
workspace();
extras();
refresh(false);
tray();
$('#report-context').hidden = $('#insights').hidden && $('#standards-root').hidden && !$('#walk-root').firstElementChild;
if (deepLink && D.findings.length) requestAnimationFrame(() => {
  if (compact.matches) openDetail();
  else $('#findings').scrollIntoView({ block: 'start' });
});
})();
