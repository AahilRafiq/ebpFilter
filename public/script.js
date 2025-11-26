const API_URL = '/api',
d = document,
domainInput = d.getElementById('domainInput'),
addBtn = d.getElementById('addBtn'),
domainList = d.getElementById('domainList'),
countBadge = d.getElementById('countBadge'),
statusMsg = d.getElementById('statusMsg');

d.addEventListener('DOMContentLoaded', fetchDomains);
addBtn.addEventListener('click', handleAddDomain);
domainInput.addEventListener('keypress', e => e.key === 'Enter' && handleAddDomain());

async function fetchDomains() {
  try {
    const r = await fetch(`${API_URL}/list`);
    if (!r.ok) throw 0;
    renderList(await r.json());
  } catch {
    domainList.innerHTML = `<li class="loading-state" style="color:var(--danger)">Error connecting to server.</li>`;
  }
}

async function handleAddDomain() {
  const domain = domainInput.value.trim().toLowerCase();
  if (!domain) return showStatus('Please enter a domain', 'error');
  if (!isValidDomain(domain)) return showStatus('Invalid domain format', 'error');

  addBtn.disabled = true;
  addBtn.textContent = 'Adding...';

  try {
    const r = await fetch(`${API_URL}/add`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: domain
    });
    if (!r.ok) throw new Error(await r.text() || 'Failed to add domain');
    showStatus(`Blocked ${domain}`, 'success');
    domainInput.value = '';
    fetchDomains();
  } catch (e) {
    showStatus(e.message, 'error');
  } finally {
    addBtn.disabled = false;
    addBtn.textContent = 'Block Domain';
  }
}

async function removeDomain(domain) {
  if (!confirm(`Are you sure you want to unblock ${domain}?`)) return;
  try {
    const r = await fetch(`${API_URL}/remove`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: domain
    });
    if (!r.ok) throw 0;
    fetchDomains();
  } catch {
    showStatus('Could not remove domain', 'error');
  }
}

function renderList(domains) {
  domainList.innerHTML = '';
  countBadge.textContent = domains.length;
  if (!domains.length) {
    domainList.innerHTML = '<li class="loading-state">No domains blocked yet.</li>';
    return;
  }
  domains.sort().forEach(domain => {
    const li = d.createElement('li'),
      span = d.createElement('span'),
      btn = d.createElement('button');
    span.textContent = domain;
    btn.textContent = 'Remove';
    btn.className = 'delete-btn';
    btn.onclick = () => removeDomain(domain);
    li.append(span, btn);
    domainList.appendChild(li);
  });
}

function showStatus(msg, type) {
  statusMsg.textContent = msg;
  statusMsg.className = `status-msg ${type}`;
  setTimeout(() => {
    statusMsg.textContent = '';
    statusMsg.className = 'status-msg';
  }, 3000);
}

function isValidDomain(s) {
  return /^(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}?$/.test(s);
}
