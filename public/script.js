// Configuration
const API_URL = '/api'; // Assumes server hosts API at relative path /api

// DOM Elements
const domainInput = document.getElementById('domainInput');
const addBtn = document.getElementById('addBtn');
const domainList = document.getElementById('domainList');
const countBadge = document.getElementById('countBadge');
const statusMsg = document.getElementById('statusMsg');

// --- Event Listeners ---

document.addEventListener('DOMContentLoaded', fetchDomains);

addBtn.addEventListener('click', handleAddDomain);

domainInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') handleAddDomain();
});

// --- Core Functions ---

/**
 * Fetch the current blocklist from the server
 * Expected API: GET /api/list (returns JSON array of strings)
 */
async function fetchDomains() {
    try {
        const response = await fetch(`${API_URL}/list`);
        if (!response.ok) throw new Error('Failed to fetch list');
        
        // Assumes the server still returns a JSON array for the list
        const domains = await response.json(); 
        renderList(domains);
    } catch (error) {
        console.error(error);
        domainList.innerHTML = `<li class="loading-state" style="color: var(--danger)">Error connecting to server.</li>`;
    }
}

/**
 * Add a new domain
 * Expected API: POST /api/add (body: Raw text/bytes containing the domain)
 */
async function handleAddDomain() {
    const domain = domainInput.value.trim().toLowerCase();

    // Basic Validation
    if (!domain) return showStatus('Please enter a domain', 'error');
    if (!isValidDomain(domain)) return showStatus('Invalid domain format', 'error');

    addBtn.disabled = true;
    addBtn.textContent = 'Adding...';

    try {
        const response = await fetch(`${API_URL}/add`, {
            method: 'POST',
            // IMPORTANT: We set Content-Type to text/plain and pass the string directly as body
            headers: { 'Content-Type': 'text/plain' }, 
            body: domain // Sending the raw domain string
        });

        if (!response.ok) {
            // If server returns error details, try to read them.
            const errorText = await response.text();
            throw new Error(errorText || 'Failed to add domain');
        }

        showStatus(`Blocked ${domain}`, 'success');
        domainInput.value = ''; // Clear input
        fetchDomains(); // Refresh list
    } catch (error) {
        showStatus(error.message, 'error');
    } finally {
        addBtn.disabled = false;
        addBtn.textContent = 'Block Domain';
    }
}

/**
 * Remove a domain
 * Expected API: POST /api/remove (body: Raw text/bytes containing the domain)
 */
async function removeDomain(domain) {
    if (!confirm(`Are you sure you want to unblock ${domain}?`)) return;

    try {
        const response = await fetch(`${API_URL}/remove`, {
            method: 'POST',
            // IMPORTANT: We set Content-Type to text/plain and pass the string directly as body
            headers: { 'Content-Type': 'text/plain' },
            body: domain // Sending the raw domain string
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(errorText || 'Failed to remove domain');
        }

        fetchDomains(); // Refresh list
    } catch (error) {
        showStatus('Could not remove domain', 'error');
    }
}

// --- UI Helpers ---

function renderList(domains) {
    domainList.innerHTML = '';
    countBadge.textContent = domains.length;

    if (domains.length === 0) {
        domainList.innerHTML = '<li class="loading-state">No domains blocked yet.</li>';
        return;
    }

    // Sort alphabetically for easier reading
    domains.sort().forEach(domain => {
        const li = document.createElement('li');
        
        const span = document.createElement('span');
        span.textContent = domain;
        
        const btn = document.createElement('button');
        btn.textContent = 'Remove';
        btn.className = 'delete-btn';
        btn.onclick = () => removeDomain(domain);

        li.appendChild(span);
        li.appendChild(btn);
        domainList.appendChild(li);
    });
}

function showStatus(msg, type) {
    statusMsg.textContent = msg;
    statusMsg.className = `status-msg ${type}`;
    
    // Clear message after 3 seconds
    setTimeout(() => {
        statusMsg.textContent = '';
        statusMsg.className = 'status-msg';
    }, 3000);
}

function isValidDomain(str) {
    // Simple regex for domain validation
    const pattern = /^(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}?$/;
    return pattern.test(str);
}