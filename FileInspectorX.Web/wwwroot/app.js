'use strict';
const byId = id => document.getElementById(id);
let selected = null, timer = null, searchTimer = null;
const make = (tag, text, cls) => { const el = document.createElement(tag); if (text !== undefined) el.textContent = text; if (cls) el.className = cls; return el; };
const api = async (url, options = {}) => {
  const response = await fetch(url, { ...options, headers: { 'X-FileInspector-Client': 'local', ...options.headers } });
  if (!response.ok) { const problem = await response.json().catch(() => null); throw new Error(problem?.error || `Request failed (${response.status}).`); }
  return response.status === 204 ? null : response.json();
};
const notice = (message, error = false) => { byId('notice').textContent = message; byId('notice').className = error ? 'error' : ''; };
async function list() {
  const jobs = await api('/api/reports?q=' + encodeURIComponent(byId('search').value));
  const nav = byId('reports'); nav.replaceChildren(); byId('count').textContent = `${jobs.length} saved report${jobs.length === 1 ? '' : 's'}`;
  for (const job of jobs) {
    const button = make('button', job.name || '(unnamed file)', job.id === selected ? 'selected' : '');
    button.append(make('small', `${job.state} · ${job.sizeBytes.toLocaleString()} bytes`));
    button.addEventListener('click', () => show(job.id)); nav.append(button);
  }
}
function section(parent, title, value) { parent.append(make('h3', title), make('p', value)); }
function table(parent, headers, rows) {
  const wrapper = make('div', undefined, 'table-wrap'), table = make('table'), head = make('thead'), tr = make('tr');
  for (const heading of headers) tr.append(make('th', heading)); head.append(tr); table.append(head);
  const body = make('tbody'); for (const row of rows) { const line = make('tr'); for (const cell of row) line.append(make('td', String(cell ?? '—'))); body.append(line); }
  table.append(body); wrapper.append(table); parent.append(wrapper);
}
async function show(id) {
  selected = id; clearTimeout(timer); const report = await api('/api/reports/' + id);
  if (selected !== id) return;
  const detail = byId('detail'); detail.replaceChildren();
  if (report.state) {
    detail.append(make('h2', report.name), make('p', report.state === 'failed' ? report.error : 'Analysis is ' + report.state + '.'));
    if (report.state === 'failed') deletion(detail, id);
    else timer = setTimeout(() => show(id).catch(error => notice(error.message, true)), 1000);
    await list(); return;
  }
  detail.append(make('h2', report.file.name || '(unnamed file)'));
  const facts = make('div', undefined, 'facts');
  for (const [label, value] of [['Detected type', report.analysis.detectedExtension || 'Unknown'], ['Size', report.file.sizeBytes.toLocaleString() + ' bytes'], ['Coverage', report.outcome]]) {
    const fact = make('div', undefined, 'fact'); fact.append(make('small', label), make('strong', value)); facts.append(fact);
  }
  detail.append(facts, make('div', 'SHA-256: ' + report.file.sha256, 'hash'));
  if (report.outcome !== 'Complete') detail.append(make('p', 'This report has limited coverage. Missing findings do not establish that a feature is absent.', 'coverage'));
  detail.append(make('h3', 'What the evidence says'));
  const observations = make('ul', undefined, 'observations');
  for (const item of report.observations) { const li = make('li', item.text); li.append(make('span', item.evidence, 'evidence')); observations.append(li); } detail.append(observations);
  section(detail, 'Content reader', report.content.reader);
  if (Object.keys(report.content.metadata).length) table(detail, ['Property', 'Value'], Object.entries(report.content.metadata));
  if (report.content.text) { detail.append(make('h3', 'Extracted text'), make('pre', report.content.text)); }
  if (report.content.entries.length) { detail.append(make('h3', 'Archive inventory')); table(detail, ['Name', 'Expanded bytes', 'SHA-256 (whole member)'], report.content.entries.map(e => [e.name, e.sizeBytes, e.sha256])); }
  detail.append(make('h3', 'Analysis coverage'));
  table(detail, ['Stage', 'Status', 'Issues'], (report.analysis.stageOutcomes || []).map(s => [s.stage, s.status, s.issues.join(', ')]));
  if (report.content.issues.length) section(detail, 'Content limits', report.content.issues.join(' · '));
  const matches = await api('/api/reports/' + id + '/similar');
  if (selected !== id) return;
  detail.append(make('h3', 'Related files'));
  if (!matches.length) detail.append(make('p', 'No matching bytes or comparable extracted text found in this local catalog.', 'muted'));
  for (const match of matches) { const button = make('button', `${match.job.name} · ${Math.round(match.score * 100)}% · ${match.basis}`, 'secondary'); button.addEventListener('click', () => show(match.job.id)); detail.append(button); }
  const actions = make('div', undefined, 'actions'), exportButton = make('button', 'Export JSON');
  exportButton.addEventListener('click', () => { const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })); const a = make('a'); a.href = url; a.download = report.file.sha256 + '.json'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); });
  actions.append(exportButton); deletion(actions, id); detail.append(actions); await list();
}
function deletion(parent, id) {
  const button = make('button', 'Delete file and report', 'secondary');
  button.addEventListener('click', async () => { try { await api('/api/reports/' + id, { method: 'DELETE' }); if (selected === id) { selected = null; byId('detail').replaceChildren(make('p', 'The file and report were deleted.')); } await list(); } catch (error) { notice(error.message, true); } }); parent.append(button);
}
byId('file').addEventListener('change', async event => {
  const file = event.target.files[0]; if (!file) return;
  try { notice('Uploading ' + file.name + '…'); const job = await api('/api/uploads', { method: 'POST', headers: { 'X-File-Name': encodeURIComponent(file.name), 'X-File-Name-Encoded': 'uri', 'Content-Type': 'application/octet-stream' }, body: file }); notice('Uploaded. Analysis runs in a separate process.'); await show(job.id); }
  catch (error) { notice(error.message, true); } finally { event.target.value = ''; }
});
byId('search').addEventListener('input', () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => list().catch(error => notice(error.message, true)), 200); });
list().catch(error => notice(error.message, true));
