const byId = id => document.getElementById(id);
const run = byId('run');
run.addEventListener('click', async () => {
  run.disabled = true;
  byId('result').textContent = 'Starting both nodes and running the recovery scenario…';
  byId('timeline').replaceChildren();
  byId('evidence').textContent = 'Awaiting verified evidence.';
  byId('nodeA').textContent = 'Running';
  byId('nodeB').textContent = 'Running';
  byId('version').textContent = '—';
  const prediction = Number(byId('prediction').value);
  try {
    const response = await fetch('/run/' + byId('phase').value, {
      method: 'POST', headers: {'X-Recovery-Console': 'run'}
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error);
    byId('version').textContent = 'v' + result.active_version;
    for (const node of ['A', 'B']) {
      byId('node' + node).textContent = 'Revocation verified';
    }
    const prefix = prediction === result.active_version ? 'Prediction verified.' : 'Prediction differed.';
    byId('result').textContent = prefix + ' Teammate read verified. Last denial: ' +
      result.last_denial_ms + ' ms after revoke commit.';
    const evidence = new Map(result.evidence.map(event => [event.request_id, event]));
    for (const event of result.timeline) {
      const button = document.createElement('button');
      button.className = 'event';
      const source = document.createElement('span');
      source.textContent = event.source;
      const label = document.createElement('span');
      label.textContent = event.label;
      button.append(source, label);
      button.addEventListener('click', () => {
        const audit = evidence.get(event.request_id);
        byId('evidence').textContent = JSON.stringify(audit ? {
          ...event, audit: 'verified', event_id: audit.id, actor: audit.actor,
          action: audit.action, decision: audit.decision, reason: audit.reason
        } : event, null, 2);
      });
      byId('timeline').append(button);
    }
  } catch (error) {
    byId('result').textContent = 'Run unavailable. ' + error.message;
    byId('nodeA').textContent = 'Unavailable';
    byId('nodeB').textContent = 'Unavailable';
  } finally {
    run.disabled = false;
  }
});
