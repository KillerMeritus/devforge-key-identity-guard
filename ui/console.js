const byId = id => document.getElementById(id);
const text = (id, value) => { byId(id).textContent = value; };
const state = (id, value) => {
  byId('check-' + id).dataset.state = value.toLowerCase();
  text('check-' + id, value);
};
const measured = (id, condition) => state(id, condition ? 'PASS' : 'FAIL');
const allNodes = ['A', 'B'];
let active = false;

function showEvidence(summary, evidence) {
  text('evidence-summary', summary);
  text('evidence', JSON.stringify(evidence, null, 2));
}

function row(parent, source, title, action) {
  const button = document.createElement('button');
  button.className = 'event';
  const badge = document.createElement('span');
  badge.textContent = source;
  const name = document.createElement('span');
  name.textContent = title;
  button.append(badge, name);
  button.addEventListener('click', () => {
    action();
    if (parent !== 'timeline') byId('evidence-panel').focus();
  });
  byId(parent).append(button);
}

async function runScenario(route, statusId, checks, render) {
  if (active) return;
  active = true;
  const controls = ['run', 'run-detection', 'run-archive'].map(byId);
  controls.forEach(button => { button.disabled = true; });
  checks.forEach(check => state(check, 'PENDING'));
  text(statusId, 'Running the local scenario…');
  try {
    const response = await fetch('/run/' + route, {
      method: 'POST', headers: {'X-Recovery-Console': 'run', ...(['pre','post'].includes(route) && byId('challenge').value ? {'X-Verification-Challenge': byId('challenge').value} : {})}
    });
    const result = await response.json();
    if (!response.ok) {
      const error = new Error(result.error);
      error.verificationFailed = result.verification_failed === true;
      throw error;
    }
    render(result);
  } catch (error) {
    checks.forEach(check => state(check, 'UNAVAILABLE'));
    if (error.verificationFailed) {
      text(statusId, 'FAIL · ' + error.message);
    } else {
      text(statusId, 'UNAVAILABLE · ' + error.message);
    }
    if (checks.includes('revocation')) {
      allNodes.forEach(node => text('node' + node, 'Unavailable'));
    }
  } finally {
    controls.forEach(button => { button.disabled = false; });
    active = false;
  }
}

byId('run').addEventListener('click', () => {
  if (active) return;
  const prediction = Number(byId('prediction').value);
  const phase = byId('phase').value;
  byId('timeline').replaceChildren();
  showEvidence('Awaiting observed events.', null);
  text('version', '—');
  text('recovery-time', '');
  allNodes.forEach(node => {
    text('node' + node, 'Running');
    text('details' + node, '');
  });
  runScenario(phase, 'result', ['revocation', 'access', 'audit'], result => {
    text('version', 'v' + result.active_version);
    text('recovery-time', result.recovery_ms + ' ms to first verified read on Node A');
    const nodes = result.nodes;
    allNodes.forEach(node => {
      const observation = nodes[node];
      const denied = observation.revoked_status === 403 && observation.revoked_reason === 'revoked_device';
      text('node' + node, observation.health === 200 && denied ? 'Revocation verified' : 'See observed result');
      const old = result.cutoff[node];
      text('details' + node, 'Health ' + observation.health + ' · Teammate ' +
        observation.teammate_status + ' · Revoked device ' + observation.revoked_status +
        (old ? ' · v' + old.requested_version + ' rejected with HTTP ' + old.status +
          ' in ' + old.observed_ms + ' ms' : ''));
    });
    measured('revocation', allNodes.every(node =>
      nodes[node].revoked_status === 403 && nodes[node].revoked_reason === 'revoked_device'));
    measured('access', allNodes.every(node => nodes[node].teammate_status === 200));
    measured('audit', result.audit_verified === true);
    for (const [id, details] of Object.entries({revocation: nodes, access: nodes, audit: result.evidence})) {
      const button = document.createElement('button');
      button.textContent = byId('check-' + id).textContent;
      button.onclick = () => showEvidence(id, details);
      byId('check-' + id).replaceChildren(button);
    }
    const prefix = prediction === result.active_version ? 'Prediction verified.' : 'Prediction differed.';
    text('result', prefix + ' Predicted v' + prediction + ', observed v' + result.active_version +
      '. Last denial ' + result.last_denial_ms + ' ms after revoke commit.');
    const evidence = new Map(result.evidence.map(event => [event.request_id, event]));
    for (const event of result.timeline) {
      const audit = evidence.get(event.request_id);
      row('timeline', event.source, event.label, () => showEvidence(event.label, audit ? {
        ...event, audit: result.audit_verified ? 'verified' : 'unverified',
        event_id: audit.id, actor: audit.actor, action: audit.action, decision: audit.decision,
        reason: audit.reason, timestamp: audit.timestamp
      } : event));
    }
  });
});

byId('run-detection').addEventListener('click', () => {
  if (active) return;
  byId('detections').replaceChildren();
  runScenario('detection', 'detection-status', ['detector'], result => {
    text('detection-status', result.findings.length + ' findings · ' + result.timing_notes.length +
      ' timing notes · ' + result.source_ingestion.median_ms + ' ms median source ingestion');
    const sources = new Map(result.sources.map(source => [source.event_id, source]));
    if (result.findings.length) {
      measured('detector', result.findings.every(item => item.receipt.state === 'CONFIRMED' &&
        item.event.source_ids.every(ref => {
          const source = result.source_receipts[ref.event_id];
          return source?.state === 'CONFIRMED' && source.producer === ref.producer &&
            source.sequence < item.receipt.sequence;
        })));
    }
    for (const item of result.findings) {
      const kind = item.event.detector_context.classification === 'policy_violation' ? 'Violation' : 'Investigate';
      row('detections', kind, item.event.actor + ' · ' + item.event.rule_id.replaceAll('_', ' '), () =>
        showEvidence(item.event.rule_id.replaceAll('_', ' '), {
          ...item.event, explanation: item.explanation, services: item.services,
          service_edges: item.service_edges, uncertainty_ms: item.uncertainty_ms, receipt: item.receipt,
          sources: item.event.source_ids.map(ref => ({ ...ref, observation: sources.get(ref.event_id), receipt: result.source_receipts[ref.event_id] }))
        }));
    }
    for (const note of result.timing_notes) {
      row('detections', 'Timing', note.reason.replaceAll('_', ' '), () =>
        showEvidence('Timing uncertainty', { ...note, observation: sources.get(note.event) }));
    }
  });
});

byId('run-archive').addEventListener('click', () => {
  if (active) return;
  byId('archive-events').replaceChildren();
  runScenario('archive', 'archive-status', ['archive'], result => {
    measured('archive', allNodes.every(node => result.quarantine[node].status === 503));
    text('archive-status', 'Current snapshot verified · ' + result.recovery_ms + ' ms through both node checks');
    for (const node of allNodes) {
      const blocked = result.quarantine[node];
      row('archive-events', 'Node ' + node, 'Stale read → HTTP ' + blocked.status,
        () => showEvidence('Stale snapshot quarantine', blocked));
    }
    row('archive-events', 'Archive', 'Historical receipt · ' + result.historical.lifecycle,
      () => showEvidence('Independently retained historical event', result.historical));
    for (const node of allNodes) {
      const recovered = result.recovered[node];
      row('archive-events', 'Node ' + node, 'Recovered · teammate ' + recovered.teammate.status +
        ' · revoked ' + recovered.revoked.status, () => showEvidence('Verified current snapshot', recovered));
    }
  });
});
