const byId = id => document.getElementById(id);
const text = (id, value) => { byId(id).textContent = value; };
const state = (id, value) => {
  byId('check-' + id).dataset.state = value.toLowerCase();
  text('check-' + id, value);
};
const measured = (id, condition) => state(id, condition ? 'PASS' : 'FAIL');
const allNodes = ['A', 'B'];
const runControls = () => ['run', 'run-detection', 'run-archive', 'run-lab', 'run-monitor'].map(byId);
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

async function runScenario(route, statusId, checks, render, challenge) {
  if (active) return;
  active = true;
  const controls = runControls();
  controls.forEach(button => { button.disabled = true; });
  checks.forEach(check => state(check, 'PENDING'));
  text(statusId, 'Running the local scenario…');
  try {
    const response = await fetch('/run/' + route, {
      method: 'POST', headers: {'X-Recovery-Console': 'run', ...(challenge ? {'X-Verification-Challenge': challenge} : {})}
    });
    const result = await response.json();
    if (!response.ok) {
      const error = new Error(response.status === 400 ? 'Use a 64-digit lowercase hexadecimal challenge.' : result.error);
      error.invalidInput = response.status === 400;
      error.verificationFailed = result.verification_failed === true;
      throw error;
    }
    render(result);
  } catch (error) {
    checks.forEach(check => state(check, 'UNAVAILABLE'));
    if (error.verificationFailed) {
      text(statusId, 'FAIL · ' + error.message);
    } else {
      text(statusId, (error.invalidInput ? 'NOT TESTED' : 'UNAVAILABLE') + ' · ' + error.message);
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
      button.onclick = () => showEvidence(
        id === 'audit' ? 'Authenticated audit history' : 'Harness observations and signed worker decisions',
        details
      );
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
  }, byId('challenge').value);
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

const labSpecs = {
  revocation: ['Two granted devices before revocation.', 'Both workers explicitly deny the revoked device and serve the teammate.', 'A and B'],
  approval: ['Version 1, one expired and one active approval.', 'An expired approval fails, an active approval rotates once, and reuse fails.', 'A and B'],
  competing: ['Version 1 and two approvals bound to that version.', 'Exactly one competing rotation commits. Both workers serve v2 and reject v1.', 'A and B'],
  pre: ['Version 1 and a rotation paused before commit.', 'After terminating and restarting A, both nodes retain v1 and preserve revocation.', 'A restarted, B observed'],
  post: ['Version 1 and a rotation paused after commit.', 'After terminating and restarting A, both nodes serve v2 and reject v1.', 'A restarted, B observed'],
  backup: ['Authenticated backup of the committed key version and a one-byte changed copy.', 'Accept the original backup and reject the damaged copy.', 'Node A verification'],
  quarantine: ['Experimental archive fixture restored to a stale working snapshot.', 'Both nodes deny access while stale and preserve revocation after verified restore.', 'A and B · experimental'],
  passport: ['Two worker statements and public keys provisioned independently of the envelopes.', 'Authenticate each original statement and reject a copy with a changed signed version.', 'A and B']
};

function updateLabSpec() {
  const scenario = byId('lab-choice').value;
  const [pre, expected, nodes] = labSpecs[scenario];
  byId('lab-challenge').disabled = scenario !== 'passport';
  text('lab-preconditions', pre);
  text('lab-expected', expected);
  text('lab-nodes', nodes);
  text('lab-status', 'NOT TESTED');
  byId('lab-outcome').replaceChildren();
}
byId('lab-choice').addEventListener('change', updateLabSpec);
updateLabSpec();

function labRecord(title, record, container = 'lab-outcome') {
  const details = document.createElement('details');
  const summary = document.createElement('summary');
  summary.textContent = title;
  const data = document.createElement('pre');
  data.textContent = JSON.stringify(record, null, 2);
  details.append(summary, data);
  byId(container).append(details);
}

byId('run-lab').addEventListener('click', async () => {
  if (active) return;
  const choice = byId('lab-choice');
  const name = choice.value;
  const challenge = name === 'passport' ? byId('lab-challenge').value : undefined;
  choice.disabled = true;
  byId('lab-outcome').replaceChildren();
  try {
    await runScenario('lab/' + name, 'lab-status', [], result => {
      const data = result.observations;
      if (name === 'passport') {
        for (const node of allNodes) {
          const {statement, modified_statement, trusted_public_key_base64, ...inputs} = data[node];
          labRecord('Node ' + node + ' · ' + inputs.original + ' · modified copy ' + inputs.modified, inputs);
          labRecord('Node ' + node + ' independently provisioned public key', {trusted_public_key_base64});
          labRecord('Node ' + node + ' original signed statement', statement);
          labRecord('Node ' + node + ' controlled modified copy', modified_statement);
        }
        labRecord('Independent policy appraisal across both workers', result.claims);
        text('lab-status', result.status + ' · Historical claims and modified-copy rejection');
      } else if (data.before) {
        labRecord('Before · observed starting state', data.before);
        labRecord('After · observed worker state', data.after || data.nodes);
        const {before, after, nodes, ...remaining} = data;
        labRecord('Supporting decisions and evidence', remaining);
        text('lab-status', result.status + (data.active_version ? ' · Recovered v' + data.active_version : ' · Both workers observed'));
      } else {
        if (name === 'revocation') {
          for (const node of allNodes) labRecord('Node ' + node + ' · HTTP ' + data[node].denial_status + ' · ' + data[node].denial_reason, data[node]);
        } else if (name === 'quarantine') {
          labRecord('Before verified restore · quarantined nodes', data.quarantine);
          labRecord('After verified restore · worker outcomes', data.recovered);
          labRecord('Retained historical receipt', data.historical);
        } else {
          labRecord('Backup verification · original accepted, damaged copy rejected', data);
        }
        text('lab-status', result.status + ' · Expected outcome observed');
      }
    }, challenge);
  } finally {
    choice.disabled = false;
  }
});

byId('run-monitor').addEventListener('click', async () => {
  if (active) return;
  active = true;
  const controls = runControls();
  controls.forEach(button => { button.disabled = true; });
  byId('monitor-events').replaceChildren();
  text('monitor-status', 'Waiting for authenticated audit observations…');
  try {
    const response = await fetch('/run/monitor', {method: 'POST', headers: {'X-Recovery-Console': 'run'}});
    if (!response.ok) throw new Error('Cannot start the monitor.');
    const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
    let buffer = '';
    let completed = false;
    while (true) {
      const {value, done} = await reader.read();
      if (done) break;
      buffer += value;
      let boundary;
      while ((boundary = buffer.indexOf('\n')) !== -1) {
        const record = JSON.parse(buffer.slice(0, boundary));
        buffer = buffer.slice(boundary + 1);
        if (record.type === 'complete') {
          completed = true;
          text('monitor-status', record.status + (record.error ? ' · ' + record.error : ' · Monitored fixtures complete'));
          if (record.report) labRecord('Final findings, containment and poll measurements', record.report, 'monitor-events');
        } else if (record.type === 'fixture_started') {
          text('monitor-status', 'Observing the ' + record.fixture + ' fixture…');
        } else {
          const title = record.type === 'finding' ? record.node + ' · ' + record.reason :
            record.type === 'containment' ? record.node + ' · Denial and withheld body confirmed' :
            record.type === 'administrative_response' ? 'Scripted operator response · ' + record.action :
            record.rule.replaceAll('_', ' ');
          labRecord(record.fixture + ' · ' + title, record, 'monitor-events');
        }
      }
    }
    if (!completed) throw new Error('The monitor ended before reporting completion.');
  } catch (error) {
    text('monitor-status', 'UNAVAILABLE · ' + error.message);
  } finally {
    controls.forEach(button => { button.disabled = false; });
    active = false;
  }
});
