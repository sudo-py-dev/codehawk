'use strict';
const data = JSON.parse(document.querySelector('#data').textContent);
const get = (id) => document.getElementById(id);
const make = (tag, content, className) => {
  const node = document.createElement(tag);
  node.textContent = content;
  if (className) node.className = className;
  return node;
};
const date = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
get('repo').textContent = data.repo;
get('snapshot').textContent = 'Snapshot ' + date.format(new Date(data.generatedAt));
get('warnings').hidden = !data.warnings.length;
get('warnings').replaceChildren(...data.warnings.map((warning) => make('li', warning)));
const controls = ['search', 'kind', 'sort'].map(get);
const params = new URLSearchParams(location.hash.slice(1));
for (const control of controls) {
  const value = params.get(control.id);
  if (value && (control.tagName === 'INPUT' || Array.from(control.options).some((option) => option.value === value))) control.value = value;
}

function render() {
  const query = get('search').value.trim().toLowerCase();
  const kind = get('kind').value;
  const visible = data.items.filter((item) => (!kind || item.kind === kind) &&
    [item.title, '#' + item.number, ...item.labels].join(' ').toLowerCase().includes(query));
  if (get('sort').value === 'updated') visible.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  get('count').textContent = visible.length ? visible.length + ' of ' + data.items.length + ' items'
    : data.items.length ? 'No items match these filters.' : 'No open items were returned.';
  get('queue').replaceChildren(...visible.map((item) => {
    const row = make('li', '');
    const detail = make('details', '');
    const summary = make('summary', '');
    const type = item.kind === 'pr' ? 'PR' : 'Issue';
    const title = make('span', item.title);
    title.dir = 'auto';
    summary.append(make('span', 'Score ' + item.score + ' · ', 'priority'), type + ' #' + item.number + ' · ', title);
    const meta = ['Updated ' + date.format(new Date(item.updatedAt)), ...item.labels];
    if (item.size !== null) meta.push(item.size.toLocaleString() + ' changed lines');
    const reasons = make('ul', '');
    reasons.append(...(item.reasons.length ? item.reasons : ['No priority signals found']).map((reason) => make('li', reason)));
    const body = make('p', item.body || 'No description provided.', 'body');
    body.dir = 'auto';
    const link = make('a', 'Open ' + type + ' on GitHub');
    link.href = 'https://github.com/' + data.repo + '/' + (item.kind === 'pr' ? 'pull' : 'issues') + '/' + item.number;
    detail.append(summary, make('p', meta.join(' · '), 'meta'), reasons, body, link);
    if (item.kind === 'pr') detail.append(make('p', 'Run a CodeHawk PR review with this GitHub URL.', 'meta'));
    row.append(detail);
    return row;
  }));
}

for (const control of controls) control.addEventListener('input', () => {
  const filters = new URLSearchParams();
  for (const field of controls) if (field.value) filters.set(field.id, field.value);
  history.replaceState(null, '', location.pathname + '#' + filters);
  render();
});
render();
