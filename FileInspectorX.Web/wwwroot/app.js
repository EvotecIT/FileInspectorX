'use strict';
const byId = id => document.getElementById(id);
let selected = null, timer = null, searchTimer = null;
let accessToken = '';
try { accessToken = sessionStorage.getItem('fileinspector-access') || ''; } catch { }
function acceptAccessLink() {
  const token = new URLSearchParams(location.hash.slice(1)).get('token');
  if (token === null) return false;
  history.replaceState(null, '', location.pathname + location.search);
  if (!/^[0-9A-F]{64}$/.test(token)) return false;
  accessToken = token;
  try { sessionStorage.setItem('fileinspector-access', token); } catch { }
  return true;
}
acceptAccessLink();
const make = (tag, text, cls) => { const el = document.createElement(tag); if (text !== undefined) el.textContent = text; if (cls) el.className = cls; return el; };
const api = async (url, options = {}) => {
  if (!accessToken) throw new Error('Open the private link printed by the application to access local reports.');
  const response = await fetch(url, { ...options, headers: { 'Authorization': 'Bearer ' + accessToken, 'X-FileInspector-Client': 'local', ...options.headers } });
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
  if (headers.length >= 4) { table.className = headers.length >= 6 ? 'wide-table regions-table' : 'wide-table'; wrapper.tabIndex = 0; wrapper.setAttribute('aria-label', 'Scrollable evidence table'); }
  for (const heading of headers) tr.append(make('th', heading)); head.append(tr); table.append(head);
  const body = make('tbody'); for (const row of rows) { const line = make('tr'); for (const cell of row) { const value = String(cell ?? '—'), td = make('td', value); if (/^-?\d+(?:\.\d+)?$/.test(value)) td.className = 'number'; line.append(td); } body.append(line); }
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
  if (report.content.facts?.length) {
    detail.append(make('h3', 'Located facts'));
    table(detail, ['Property', 'Value', 'Origin', 'Source'], report.content.facts.map(f => [f.name,
      f.value + (f.truncated ? ' (prefix only)' : ''), f.origin,
      [f.source?.part, f.source?.record, f.source?.byteOffset != null ? `byte ${f.source.byteOffset}${f.source.byteLength ? ` + ${f.source.byteLength}` : ''}` : null].filter(Boolean).join(' · ')]));
  } else if (Object.keys(report.content.metadata).length) table(detail, ['Property', 'Value'], Object.entries(report.content.metadata));
  if (report.content.text) { detail.append(make('h3', 'Extracted text'), make('pre', report.content.text)); }
  if (report.content.entries.length) {
    detail.append(make('h3', 'Archive inventory'));
    table(detail, ['Member', 'Expanded bytes', 'SHA-256 (whole member)', 'Nested analysis'], report.content.entries.map(e => [
      `${e.ordinal ?? '—'} · ${e.name}${e.nameTruncated ? ' (name prefix)' : ''}`, e.sizeBytes, e.sha256,
      e.report ? `${e.report.analysis.detectedExtension || 'Unknown'} · ${e.report.outcome}` : 'Not analyzed']));
    nestedReports(detail, report.content.entries, 0);
  }
  if (report.content.regions?.length) {
    detail.append(make('h3', 'Binary region evidence'));
    table(detail, ['Region', 'Basis', 'Offset', 'Whole bytes', 'Bytes hashed', 'SHA-256', 'Coverage'], report.content.regions.map(r => [r.name, r.kind, r.byteOffset, r.byteLength, r.hashBytes, r.sha256, r.status]));
  }
  detail.append(make('h3', 'Analysis coverage'));
  table(detail, ['Stage', 'Status', 'Issues'], (report.analysis.stageOutcomes || []).map(s => [s.stage, s.status, s.issues.join(', ')]));
  if (report.content.issues.length) section(detail, 'Content limits', report.content.issues.join(' · '));
  const matches = await api('/api/reports/' + id + '/similar');
  if (selected !== id) return;
  detail.append(make('h3', 'Related files'));
  if (!matches.length) detail.append(make('p', 'No matching bytes, extracted text or inspected regions found in this local catalog.', 'muted'));
  for (const match of matches) {
    const button = make('button', `${match.job.name} · ${Math.round(match.score * 100)}% inspected overlap · ${match.basis}`, 'secondary');
    button.addEventListener('click', () => show(match.job.id)); detail.append(button);
    for (const evidence of match.evidence || []) {
      const coverage = evidence.partial ? ' · limited coverage' : '';
      detail.append(make('p', `${evidence.basis}: ${evidence.comparedLeft} / ${evidence.comparedRight} comparable items${coverage}. This describes the named evidence, not meaning or behavior.`, 'muted'));
      if (evidence.matches?.length) table(detail, ['This file', 'Other file', 'Matched bytes'], evidence.matches.map(m => [m.leftName, m.rightName, m.byteLength]));
    }
  }
  const actions = make('div', undefined, 'actions'), exportButton = make('button', 'Export JSON');
  exportButton.addEventListener('click', () => { const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })); const a = make('a'); a.href = url; a.download = report.file.sha256 + '.json'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); });
  actions.append(exportButton); deletion(actions, id); detail.append(actions); await list();
}
function nestedReports(parent, entries, depth) {
  if (depth > 8) return;
  for (const entry of entries) {
    if (!entry.report) continue;
    const report = entry.report, group = make('details'); group.append(make('summary', `${entry.name} · ${report.outcome}`));
    group.append(make('p', `SHA-256: ${report.file.sha256}`, 'hash'));
    if (report.content.text) group.append(make('pre', report.content.text));
    if (report.content.facts?.length) table(group, ['Property', 'Value', 'Origin'], report.content.facts.map(f => [f.name, f.value + (f.truncated ? ' (prefix only)' : ''), f.origin]));
    if (report.content.issues.length) group.append(make('p', report.content.issues.join(' · '), 'coverage'));
    nestedReports(group, report.content.entries || [], depth + 1); parent.append(group);
  }
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
window.addEventListener('hashchange', () => {
  if (acceptAccessLink()) { notice(''); list().catch(error => notice(error.message, true)); }
});
list().catch(error => notice(error.message, true));
