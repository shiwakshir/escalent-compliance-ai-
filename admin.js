// ==============================================================================
// Enterprise Security & Compliance AI — Dedicated Administration Backend Logic
// Enforces Server-Side Least Privilege, Threat Telemetry, and Circuit Breakers
// ==============================================================================

const ADMIN_STATE = {
  currentUser: null,
  token: null,
  users: [],
  policies: [],
  circuitBroken: false
};

const adminEls = {
  personaSelect: document.getElementById('admin-persona-select'),
  userName: document.getElementById('admin-user-name'),
  roleBadge: document.getElementById('admin-role-badge'),
  jurBadge: document.getElementById('admin-jur-badge'),
  buBadge: document.getElementById('admin-bu-badge'),
  clearanceBadge: document.getElementById('admin-clearance-badge'),
  userAvatar: document.getElementById('admin-user-avatar'),
  btnRevoke: document.getElementById('btn-admin-revoke'),
  forbiddenScreen: document.getElementById('admin-forbidden-screen'),
  forbiddenRole: document.getElementById('forbidden-user-role'),
  btnSimSwitchAdmin: document.getElementById('btn-simulate-switch-admin'),
  tabBtns: document.querySelectorAll('.admin-tabs .tab-btn'),
  tabContents: document.querySelectorAll('.app-main .tab-content'),
  totalAuditCount: document.getElementById('admin-total-audit-count'),
  btnToggleCircuit: document.getElementById('btn-admin-toggle-circuit'),
  alertsCount: document.getElementById('admin-alerts-count'),
  threatsBadgeCount: document.getElementById('threats-badge-count'),
  threatsFeed: document.getElementById('admin-threats-feed'),
  btnRefreshThreats: document.getElementById('btn-refresh-threats'),
  auditTbody: document.getElementById('admin-audit-tbody'),
  btnRefreshAudit: document.getElementById('btn-refresh-audit-table'),
  btnRunTests: document.getElementById('btn-admin-run-tests'),
  statPassed: document.getElementById('admin-stat-passed'),
  statFailed: document.getElementById('admin-stat-failed'),
  statStatus: document.getElementById('admin-stat-status'),
  testsTbody: document.getElementById('admin-tests-tbody'),
  usersTbody: document.getElementById('admin-users-tbody'),
  policiesGrid: document.getElementById('admin-policies-grid')
};

// API Helper
async function adminApi(endpoint, method = 'GET', body = null) {
  const headers = { 'Content-Type': 'application/json' };
  if (ADMIN_STATE.token) {
    headers['Authorization'] = `Bearer ${ADMIN_STATE.token}`;
  }
  const options = { method, headers };
  if (body) options.body = JSON.stringify(body);

  try {
    const res = await fetch(endpoint, options);
    const data = await res.json();
    return { ok: res.ok, status: res.status, data, error: data.error };
  } catch (err) {
    return { ok: false, status: 0, error: err.message };
  }
}

async function initAdmin() {
  setupAdminTabs();

  // Load all synthetic users
  const usersRes = await adminApi('/api/auth/users');
  if (usersRes.ok && usersRes.data.users) {
    ADMIN_STATE.users = usersRes.data.users;
    renderAdminPersonaSelect(ADMIN_STATE.users);

    // Default to Marcus Reed (IT_ADMIN) for the Admin Backend
    const itAdmin = ADMIN_STATE.users.find(u => u.role === 'IT_ADMIN') || ADMIN_STATE.users[0];
    await switchAdminPersona(itAdmin.email);
  }

  // Hook button events
  adminEls.btnRunTests.addEventListener('click', runAdminTestRunner);
  adminEls.btnRefreshThreats.addEventListener('click', loadSecurityThreats);
  adminEls.btnRefreshAudit.addEventListener('click', loadAuditTrail);
  adminEls.btnToggleCircuit.addEventListener('click', toggleAdminCircuitBreaker);
  adminEls.btnRevoke.addEventListener('click', toggleCurrentAdminRevocation);
  adminEls.btnSimSwitchAdmin.addEventListener('click', () => {
    switchAdminPersona('marcus.reed@enterprise.internal');
  });

  setupSimulatorPresets();
  setupBenchmarkDemo();
}

function setupAdminTabs() {
  adminEls.tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.dataset.tab;
      adminEls.tabBtns.forEach(b => b.classList.remove('active'));
      adminEls.tabContents.forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const targetEl = document.getElementById(targetId);
      if (targetEl) targetEl.classList.add('active');

      if (targetId === 'tab-sec-events') loadSecurityThreats();
      if (targetId === 'tab-audit-trail') loadAuditTrail();
      if (targetId === 'tab-users-mgmt') loadUsersManagement();
      if (targetId === 'tab-policy-governance') loadPolicyGovernance();
    });
  });
}

function renderAdminPersonaSelect(users) {
  adminEls.personaSelect.innerHTML = users.map(u => `
    <option value="${u.email}">
      ${u.name} (${u.role} &bull; ${u.clearance_level})
    </option>
  `).join('');

  adminEls.personaSelect.addEventListener('change', (e) => {
    switchAdminPersona(e.target.value);
  });
}

async function switchAdminPersona(email) {
  const loginRes = await adminApi('/api/auth/login', 'POST', { email });
  if (loginRes.ok) {
    ADMIN_STATE.token = loginRes.data.token;
    ADMIN_STATE.currentUser = loginRes.data.user;
    updateAdminUserDisplay(ADMIN_STATE.currentUser);

    // Sync select element
    adminEls.personaSelect.value = email;

    // Check Least-Privilege Access Barrier
    if (ADMIN_STATE.currentUser.role === 'EMPLOYEE') {
      // Forbidden barrier
      adminEls.forbiddenRole.textContent = `EMPLOYEE (${ADMIN_STATE.currentUser.name})`;
      adminEls.forbiddenScreen.classList.remove('hidden');
    } else {
      adminEls.forbiddenScreen.classList.add('hidden');
      // Load current view data
      loadSecurityThreats();
      loadAuditTrail();
      loadUsersManagement();
      loadPolicyGovernance();
    }
  }
}

function updateAdminUserDisplay(user) {
  adminEls.userName.textContent = user.name;
  adminEls.roleBadge.textContent = user.role;
  adminEls.jurBadge.textContent = user.jurisdiction;
  adminEls.buBadge.textContent = user.business_unit;
  adminEls.clearanceBadge.textContent = user.clearance_level;

  const initials = user.name.split(' ').map(n => n[0]).join('');
  adminEls.userAvatar.textContent = initials;
}

async function toggleCurrentAdminRevocation() {
  if (!ADMIN_STATE.currentUser) return;
  const isRevoked = adminEls.btnRevoke.textContent.includes('Restore');
  const res = await adminApi('/api/auth/revoke', 'POST', {
    user_id: ADMIN_STATE.currentUser.id,
    revoke: !isRevoked
  });

  if (res.ok) {
    if (!isRevoked) {
      adminEls.btnRevoke.textContent = 'Restore Account';
      adminEls.btnRevoke.className = 'btn btn-sm btn-outline-warning';
      alert(`Account suspended: ${ADMIN_STATE.currentUser.name} access revoked on server.`);
    } else {
      adminEls.btnRevoke.textContent = 'Revoke Account';
      adminEls.btnRevoke.className = 'btn btn-sm btn-outline-danger';
      alert(`Account restored: ${ADMIN_STATE.currentUser.name} access re-enabled.`);
    }
    loadUsersManagement();
  }
}

// Security Events / Threat Interceptions
async function loadSecurityThreats() {
  const res = await adminApi('/api/admin/security-events');
  if (res.ok && res.data.events) {
    const events = res.data.events;
    adminEls.alertsCount.textContent = events.length;
    adminEls.threatsBadgeCount.textContent = `${events.length} Intercepted Threats`;

    if (events.length === 0) {
      adminEls.threatsFeed.innerHTML = `
        <p class="text-muted text-sm">No critical security events recorded yet in this session.</p>
      `;
      return;
    }

    adminEls.threatsFeed.innerHTML = events.map(ev => `
      <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.35); border-radius: 8px; padding: 14px; margin-bottom: 12px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 6px;">
          <strong style="color: #f87171; font-size: 13px;">${escapeHtml(ev.category)}</strong>
          <span style="font-family:'JetBrains Mono'; font-size: 11px; color: #94a3b8;">${ev.timestamp.replace('T', ' ').replace('Z', '')}</span>
        </div>
        <p style="font-size: 13px; color: #f1f5f9; margin-bottom: 6px;">${escapeHtml(ev.details)}</p>
        <div style="font-size: 11px; color: #94a3b8; display:flex; gap: 12px;">
          <span>User: <strong>${escapeHtml(ev.user_id)}</strong> (${escapeHtml(ev.user_role)})</span>
          <span>Rule: <code>${escapeHtml(ev.rule)}</code></span>
          <span style="color:#34d399;">Status: ${escapeHtml(ev.status)}</span>
        </div>
      </div>
    `).join('');
  } else if (res.status === 403) {
    adminEls.threatsFeed.innerHTML = `<p style="color:#f87171;">Access Denied: ${res.error}</p>`;
  }
}

// Operational Audit Trail
async function loadAuditTrail() {
  const res = await adminApi('/api/admin/audit-logs');
  if (res.ok && res.data.logs) {
    const logs = res.data.logs;
    adminEls.totalAuditCount.textContent = logs.length;
    adminEls.auditTbody.innerHTML = logs.map(l => `
      <tr>
        <td style="font-family:'JetBrains Mono'; font-size:11px;">${l.id}</td>
        <td style="font-size:11px; color:#94a3b8;">${l.timestamp.split('T')[1].replace('Z','')}</td>
        <td>${l.user_id}</td>
        <td><span class="badge badge-blue">${l.role}</span></td>
        <td>${l.jurisdiction}</td>
        <td><code>${l.action}</code></td>
        <td>
          <span class="badge ${l.guardrail_result.startsWith('BLOCKED') ? 'badge-red' : l.guardrail_result.includes('CONFIDENTIAL') ? 'badge-purple' : 'badge-green'}">
            ${l.guardrail_result}
          </span>
        </td>
        <td class="text-sm">${escapeHtml(l.triggered_rules)}</td>
        <td class="text-sm">${escapeHtml(l.query_summary)}</td>
        <td style="font-family:'JetBrains Mono'; font-size:11px;">${l.latency_ms}ms</td>
      </tr>
    `).join('');
  } else if (res.status === 403) {
    adminEls.auditTbody.innerHTML = `<tr><td colspan="10" style="color:#f87171; text-align:center;">${res.error}</td></tr>`;
  }
}

// Mandatory Guardrail Test Suite Runner
async function runAdminTestRunner() {
  adminEls.btnRunTests.disabled = true;
  adminEls.btnRunTests.textContent = 'Running 12 Assertions...';
  adminEls.statStatus.textContent = 'Executing...';
  adminEls.testsTbody.innerHTML = `
    <tr><td colspan="5" style="text-align:center; padding:24px;">Executing automated security test suite against backend API...</td></tr>
  `;

  const res = await adminApi('/api/admin/run-tests', 'POST');
  adminEls.btnRunTests.disabled = false;
  adminEls.btnRunTests.innerHTML = `
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
    Run All 12 Guardrail Tests
  `;

  if (res.ok) {
    const data = res.data;
    adminEls.statPassed.textContent = data.passed_tests;
    adminEls.statFailed.textContent = data.failed_tests;
    adminEls.statStatus.textContent = data.all_passed ? 'ALL PASSED (12/12)' : 'FAILURES DETECTED';
    adminEls.statStatus.style.color = data.all_passed ? '#34d399' : '#f87171';

    adminEls.testsTbody.innerHTML = data.tests.map(t => `
      <tr>
        <td><strong>${t.id}</strong></td>
        <td>
          <div style="font-weight:600;">${escapeHtml(t.title)}</div>
          <div class="text-sm text-muted">${escapeHtml(t.details)}</div>
        </td>
        <td><span class="badge badge-blue">${escapeHtml(t.guardrail)}</span></td>
        <td class="text-sm">${escapeHtml(t.expected)}</td>
        <td>
          <span class="badge ${t.passed ? 'badge-green' : 'badge-red'}">
            ${t.passed ? '✔ PASS' : '✖ FAIL'}
          </span>
        </td>
      </tr>
    `).join('');
  }
}

// User Management Table
async function loadUsersManagement() {
  const res = await adminApi('/api/auth/users');
  if (res.ok) {
    const users = res.data.users;
    const revokedMap = res.data.revoked_users || {};

    adminEls.usersTbody.innerHTML = users.map(u => {
      const isRevoked = revokedMap[u.id] === true;
      return `
        <tr>
          <td style="font-family:'JetBrains Mono'; font-size:11px;">${u.id}</td>
          <td>
            <div style="font-weight:600;">${escapeHtml(u.name)}</div>
            <div class="text-sm text-muted">${escapeHtml(u.email)}</div>
          </td>
          <td><span class="badge ${u.role === 'IT_ADMIN' ? 'badge-purple' : u.role === 'COMPLIANCE_OFFICER' ? 'badge-blue' : 'badge-amber'}">${u.role}</span></td>
          <td>${escapeHtml(u.business_unit)}</td>
          <td><strong>${u.jurisdiction}</strong></td>
          <td><span class="clearance-badge">${u.clearance_level}</span></td>
          <td>
            <span class="badge ${isRevoked ? 'badge-red' : 'badge-green'}">
              ${isRevoked ? 'SUSPENDED' : 'ACTIVE'}
            </span>
          </td>
          <td>
            <button class="btn btn-sm ${isRevoked ? 'btn-outline-warning' : 'btn-outline-danger'}" onclick="toggleUserRevocation('${u.id}', ${!isRevoked})">
              ${isRevoked ? 'Restore' : 'Suspend'}
            </button>
          </td>
        </tr>
      `;
    }).join('');
  }
}

window.toggleUserRevocation = async function(userId, revoke) {
  const res = await adminApi('/api/auth/revoke', 'POST', {
    user_id: userId,
    revoke: revoke
  });
  if (res.ok) {
    loadUsersManagement();
  }
};

// Policy Governance
async function loadPolicyGovernance() {
  const res = await adminApi('/api/policies');
  if (res.ok && res.data.policies) {
    adminEls.policiesGrid.innerHTML = res.data.policies.map(p => `
      <div class="policy-card">
        <div>
          <div style="display:flex; justify-content:space-between; margin-bottom:8px;">
            <span class="badge badge-green">Effective</span>
            <span style="font-family:'JetBrains Mono'; font-size:10px;">${p.id}</span>
          </div>
          <h4>${escapeHtml(p.title)}</h4>
          <div class="policy-meta">
            <span>Jurisdiction: <strong>${p.jurisdiction}</strong></span> &bull;
            <span>Min. Clearance: <strong>${p.minimum_clearance}</strong></span>
          </div>
          <p class="text-sm text-muted" style="margin-bottom:8px;">Version: ${escapeHtml(p.version)}</p>
          <div class="text-sm" style="color:#94a3b8;">
            Allowed Roles: <code>${p.allowed_roles.join(', ')}</code>
          </div>
        </div>
      </div>
    `).join('');
  }
}

// Toggle Circuit Breaker
async function toggleAdminCircuitBreaker() {
  ADMIN_STATE.circuitBroken = !ADMIN_STATE.circuitBroken;
  const res = await adminApi('/api/admin/toggle-model-offline', 'POST', { offline: ADMIN_STATE.circuitBroken });
  if (res.ok) {
    if (ADMIN_STATE.circuitBroken) {
      adminEls.btnToggleCircuit.textContent = 'Restore AI Model Online';
      adminEls.btnToggleCircuit.className = 'btn btn-outline-danger';
      alert('Simulation: Enterprise AI Gateway model endpoint set to OFFLINE. All queries will fail-safe safely.');
    } else {
      adminEls.btnToggleCircuit.textContent = 'Simulate Model Outage (Circuit Breaker)';
      adminEls.btnToggleCircuit.className = 'btn btn-outline-warning';
      alert('Simulation: Enterprise AI Gateway model endpoint restored to ONLINE.');
    }
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Interactive Threat & Guardrail Attack Simulator Logic
function setupSimulatorPresets() {
  document.querySelectorAll('.sim-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const prompt = btn.dataset.prompt;
      const doc = btn.dataset.doc || '';

      const queryDisplay = document.getElementById('sim-query-display');
      if (queryDisplay) queryDisplay.textContent = prompt;

      const docRow = document.getElementById('sim-doc-row');
      const docDisplay = document.getElementById('sim-doc-display');
      if (doc) {
        if (docRow) docRow.style.display = 'block';
        if (docDisplay) docDisplay.textContent = doc;
      } else {
        if (docRow) docRow.style.display = 'none';
      }

      const verdictBadge = document.getElementById('sim-verdict-badge');
      if (verdictBadge) {
        verdictBadge.textContent = 'Evaluating Pipeline...';
        verdictBadge.className = 'badge badge-amber';
      }

      const answerBox = document.getElementById('sim-answer-box');
      if (answerBox) {
        answerBox.innerHTML = '<span class="text-muted">Passing through Guardrails A-E and ABAC filters...</span>';
      }

      const res = await adminApi('/api/chat', 'POST', {
        message: prompt,
        document_content: doc
      });

      if (res.ok && res.data) {
        const d = res.data;
        const colorClass = `badge-${d.badge_color || 'green'}`;
        if (verdictBadge) {
          verdictBadge.textContent = d.badge || 'Response Generated';
          verdictBadge.className = `badge ${colorClass}`;
        }

        if (answerBox) {
          answerBox.innerHTML = `
            <div style="font-weight:600; margin-bottom:4px; color:${d.status === 'BLOCKED' ? '#f87171' : d.status === 'CONFIDENTIAL_ROUTED' ? '#c084fc' : '#34d399'};">
              ${escapeHtml(d.badge)}
            </div>
            <p style="font-size:13px; margin-bottom:8px;">${escapeHtml(d.answer)}</p>
            <div style="font-size:11px; color:#94a3b8;">
              <strong>Next Step:</strong> ${escapeHtml(d.next_step)}
            </div>
          `;
        }

        const ruleEl = document.getElementById('sim-rule-code');
        if (ruleEl) ruleEl.textContent = d.guardrail_triggered || 'NONE';
        const statusEl = document.getElementById('sim-status-code');
        if (statusEl) statusEl.textContent = `${res.status} OK`;
        const sourceEl = document.getElementById('sim-source-meta');
        if (sourceEl) sourceEl.textContent = d.source || 'Enterprise Knowledge Base';
        const routingEl = document.getElementById('sim-routing-meta');
        if (routingEl) routingEl.textContent = d.human_support || 'People Operations';

        // Render agent trace if present
        const simTraceRow = document.getElementById('sim-trace-row');
        const simTraceBox = document.getElementById('sim-trace-box');
        if (simTraceRow && simTraceBox) {
          if (d.execution_trace && d.execution_trace.length > 0) {
            simTraceRow.style.display = 'block';
            simTraceBox.innerHTML = `
              <div class="trace-intro-note">
                <strong>Autonomous ReAct Trace:</strong> ${d.execution_trace.length} tools executed with state verification.
              </div>
              ${d.execution_trace.map(s => `
                <div class="trace-step-item">
                  <div class="trace-step-header">
                    <span class="trace-step-num">Step ${s.step}</span>
                    <span class="trace-step-tool">${escapeHtml(s.tool)}</span>
                    <span class="trace-step-latency">${s.latency_ms || 12}ms</span>
                  </div>
                  <div class="trace-step-thought"><em>Thought:</em> ${escapeHtml(s.thought)}</div>
                  ${s.input ? `<div class="trace-step-io"><span class="io-label">Input:</span><code>${escapeHtml(typeof s.input === 'object' ? JSON.stringify(s.input) : String(s.input))}</code></div>` : ''}
                  ${s.output ? `<div class="trace-step-io"><span class="io-label">Result:</span><code>${escapeHtml(typeof s.output === 'object' ? JSON.stringify(s.output) : String(s.output))}</code></div>` : ''}
                </div>
              `).join('')}
            `;
          } else {
            simTraceRow.style.display = 'none';
          }
        }
      } else {
        if (verdictBadge) {
          verdictBadge.textContent = `HTTP ${res.status} Error`;
          verdictBadge.className = 'badge badge-red';
        }
        if (answerBox) {
          answerBox.innerHTML = `<p style="color:#f87171;">${escapeHtml(res.error || 'Server Error')}</p>`;
        }
        const simTraceRow = document.getElementById('sim-trace-row');
        if (simTraceRow) simTraceRow.style.display = 'none';
      }

      // Refresh threat log and audit trail if event logged
      loadSecurityThreats();
      loadAuditTrail();
    });
  });
}

// ==============================================================================
// BENCHMARK SHOWCASE: GENUINE AGENTIC ARCHITECTURE VS NAIVE CHATBOT
// ==============================================================================
const BENCHMARK_SCENARIOS = {
  leave: {
    title: 'UK Statutory Parental Leave & Pay Math',
    user: 'sophie.clarke@enterprise.internal',
    prompt: 'I am expecting a baby in the UK. What are my parental leave benefits and statutory pay?',
    chatbotOutput: '"According to our company handbook, maternity and parental leave is granted to employees. Eligible mothers can take time off. Please check the intranet for statutory rates. I have submitted a note to HR regarding your leave request."',
    chatbotFailures: 'Failed to discover Sophie\'s UK jurisdiction or 3.2-year tenure. Did not calculate statutory pay weeks (18 wks full pay vs 21 wks SMP). Falsely hallucinated submitting a ticket to HR without manager authorization (Violates Guardrail E).'
  },
  stipend: {
    title: 'Home Office $500 Stipend & Concur Pre-Auth',
    user: 'john.doe@enterprise.internal',
    prompt: 'How do I claim the 500 dollar home office equipment stipend and monthly internet allowance?',
    chatbotOutput: '"Our company offers various remote work allowances. You may be eligible for equipment reimbursement. Go ahead and purchase your monitor and submit an expense report on Concur."',
    chatbotFailures: 'Did not verify John\'s entitlement database ($500 claimed status). Did not enforce mandatory pre-authorization workflow. Failed to inform about 60-day receipt window or automated $60 monthly payroll disbursement.'
  },
  telematics: {
    title: 'OEM Connected Vehicle Telematics & CAN-Bus Review',
    user: 'john.doe@enterprise.internal',
    prompt: 'Can I export OEM connected vehicle telematics data to our external cloud analytics repository?',
    chatbotOutput: '"Yes, you can upload research data to cloud repositories as long as your project manager approves it. Make sure your cloud account has proper passwords."',
    chatbotFailures: 'Catastrophic Security Violation: Did not verify Project DPA or CAN-bus sanitization protocol (POL-AUT-005). Raw vehicle telemetry export is strictly illegal under client NDA without differential privacy and MAC hashing. Zero compliance gate.'
  }
};

let activeBenchmarkScenario = 'leave';

function setupBenchmarkDemo() {
  const scenarioBtns = document.querySelectorAll('.btn-bench-scenario');
  const btnRun = document.getElementById('btn-run-benchmark-live');
  const chatOutputText = document.getElementById('bench-chatbot-text');
  const chatFailures = document.getElementById('bench-chatbot-failures');
  const agentStatus = document.getElementById('bench-agent-status');
  const agentAnswer = document.getElementById('bench-agent-answer');
  const agentTrace = document.getElementById('bench-agent-trace');

  scenarioBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      scenarioBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeBenchmarkScenario = btn.dataset.scenario;
      const sc = BENCHMARK_SCENARIOS[activeBenchmarkScenario];
      if (chatOutputText) chatOutputText.textContent = sc.chatbotOutput;
      if (chatFailures) chatFailures.innerHTML = `<strong>Critical Failures:</strong> ${escapeHtml(sc.chatbotFailures)}`;
      if (agentStatus) {
        agentStatus.textContent = 'Ready to Run';
        agentStatus.className = 'badge badge-green';
      }
      if (agentAnswer) agentAnswer.innerHTML = 'Click "Run Live Agentic Workflow" above to execute multi-step tool orchestration in real time.';
      if (agentTrace) agentTrace.innerHTML = '';
    });
  });

  if (btnRun) {
    btnRun.addEventListener('click', async () => {
      const sc = BENCHMARK_SCENARIOS[activeBenchmarkScenario];
      if (agentStatus) {
        agentStatus.textContent = 'Executing Multi-Step ReAct Tools...';
        agentStatus.className = 'badge badge-amber';
      }
      if (agentAnswer) {
        agentAnswer.innerHTML = '<span class="text-muted">Agent reasoning in progress: querying ABAC identity, dispatching tools, enforcing boundaries...</span>';
      }

      // Login as target user for this scenario
      const loginRes = await adminApi('/api/auth/login', 'POST', { email: sc.user });
      const token = loginRes.ok ? loginRes.data.token : ADMIN_STATE.token;

      // Invoke chat with token
      const headers = { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` };
      const chatRes = await fetch('/api/chat', {
        method: 'POST',
        headers,
        body: JSON.stringify({ message: sc.prompt })
      });
      const data = await chatRes.json();

      if (agentStatus) {
        agentStatus.textContent = `${data.status} • Completed`;
        agentStatus.className = 'badge badge-green';
      }

      if (agentAnswer) {
        agentAnswer.innerHTML = `
          <div style="font-weight:600; margin-bottom:6px; color:#34d399;">${escapeHtml(data.badge || 'Verified Response')}</div>
          <p style="font-size:13px; margin-bottom:8px;">${escapeHtml(data.answer)}</p>
          <div style="font-size:11px; color:#94a3b8; margin-bottom:4px;"><strong>Policy Citation:</strong> ${escapeHtml(data.source)} (${escapeHtml(data.version)})</div>
          <div style="font-size:11px; color:#94a3b8; margin-bottom:4px;"><strong>Applies to:</strong> ${escapeHtml(data.applies_to)}</div>
          <div style="font-size:11px; color:#94a3b8;"><strong>Next Step:</strong> ${escapeHtml(data.next_step)}</div>
        `;
      }

      if (agentTrace && data.execution_trace && data.execution_trace.length > 0) {
        agentTrace.innerHTML = `
          <div class="trace-steps-container" style="border-radius:6px; margin-top:10px;">
            <div class="trace-intro-note">
              <strong>Live Traceability:</strong> ${data.execution_trace.length} autonomous steps executed with deterministic tool calls and latency tracking:
            </div>
            ${data.execution_trace.map(s => `
              <div class="trace-step-item">
                <div class="trace-step-header">
                  <span class="trace-step-num">Step ${s.step}</span>
                  <span class="trace-step-tool">${escapeHtml(s.tool)}</span>
                  <span class="trace-step-latency">${s.latency_ms || 12}ms</span>
                </div>
                <div class="trace-step-thought"><em>Thought:</em> ${escapeHtml(s.thought)}</div>
                ${s.input ? `<div class="trace-step-io"><span class="io-label">Input:</span><code>${escapeHtml(typeof s.input === 'object' ? JSON.stringify(s.input) : String(s.input))}</code></div>` : ''}
                ${s.output ? `<div class="trace-step-io"><span class="io-label">Result:</span><code>${escapeHtml(typeof s.output === 'object' ? JSON.stringify(s.output) : String(s.output))}</code></div>` : ''}
              </div>
            `).join('')}
          </div>
        `;
      }
    });
  }
}

document.addEventListener('DOMContentLoaded', initAdmin);
