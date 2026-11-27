"""Browser regression for the visual simulator. Default uses real backend.
--mock tests UI rendering/transport only using fabricated contract fixtures.
It is NOT cryptographic or release verification.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys
from contextlib import ExitStack
from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]


def mock_data(route):
    def row(node, version, status=200, reason='read', rid='r'):
        return dict(node=node, requested_version=version, status=status, reason=reason,
                    request_id=f'{node}-{rid}', body_withheld=status != 200)
    n = ('A','B')
    if route in ('pre','post'):
        v = 1 if route=='pre' else 2
        return dict(active_version=v, before=dict(node='B',version=1,status=200,request_id='start'),
                    recovery_ms=1.5,last_denial_ms=0.7,audit_verified=True,
                    timeline=[dict(source='A',label='Device revoked',request_id='rev'),dict(source='Harness',label='Node A killed'),dict(source='A',label='Teammate read verified',version=v)],
                    evidence=[dict(request_id='rev',reason='device_revoked',actor='operator')],
                    nodes={k:dict(health=200,teammate_status=200,revoked_status=403,revoked_reason='revoked_device',old_version_status=403,passport={'event':{'reason':'revoked_device'}}) for k in n})
    if route in ('lab/approval','lab/competing'):
        outcomes=[row('A',1,403,'approval_expired','x'),row('A',1,200,'version_rotated','y'),row('B',1,403,'approval_missing','z')] if route.endswith('approval') else [row('B',1,200,'version_rotated','x'),row('A',1,403,'wrong_version','y')]
        return dict(status='PASS',observations=dict(before=[row(k,1) for k in n],after=[row(k,v,200 if v==2 else 403,'read' if v==2 else 'wrong_version',str(v)) for k in n for v in (1,2)],outcomes=outcomes,evidence=outcomes))
    if route=='lab/revocation':
        return dict(status='PASS',observations={k:dict(denial_status=403,denial_reason='revoked_device',teammate_status=200,statement={'event':{'reason':'revoked_device'}}) for k in n})
    if route=='lab/backup':
        return dict(status='PASS',observations=dict(version=2,intact_accepted=True,damaged_accepted=False,audit_records=[{'reason':'verified_backup'},{'reason':'rejected_backup'}]))
    if route=='lab/passport':
        return dict(status='PASS',observations={k:dict(original='STATEMENT AUTHENTICATED',modified='REJECTED',statement={'signature':'mock-only'},modified_statement={'signature':'mock-only'}) for k in n},claims={x:'VERIFIED' for x in ('revoked-device','teammate-read','retired-version')})
    if route=='archive':
        return dict(quarantine={k:dict(status=503) for k in n},historical=dict(lifecycle='CONFIRMED',event=dict(reason='revoked_device')),recovered={k:dict(teammate=dict(status=200),revoked=dict(status=403,reason='revoked_device')) for k in n},recovery_ms=1.5)
    if route=='detection':
        receipt=dict(state='CONFIRMED',producer='replay-detector',sequence=1)
        return dict(findings=[dict(event=dict(actor='test',rule_id='unexpected_role',source_ids=[dict(event_id='e1',producer='replay-detector')],detector_context=dict(classification='policy_violation')),receipt={**receipt,'sequence':2},uncertainty_ms=125,explanation='Mock rule observation')],timing_notes=[dict(event='e1',reason='order_uncertain')],sources=[dict(event_id='e1')],source_receipts={'e1':receipt},source_ingestion=dict(median_ms=1))
    raise AssertionError(route)


def mock_stream():
    finding=dict(type='finding',node='A',reason='revoked_device',actor='owner',explanation='Mock denial',containment='CONFIRMED_DENIAL_NO_BODY')
    report={k:dict(findings=[finding],status_events=[]) for k in ('recovery','approval')}
    return '\n'.join(json.dumps(x) for x in [dict(type='fixture_started',fixture='recovery'),finding,dict(finding,type='containment'),dict(type='complete',status='PASS',report=report)])+'\n'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--chromium'); parser.add_argument('--screenshots',type=Path);parser.add_argument('--mock',action='store_true')
    args=parser.parse_args()
    if args.screenshots: args.screenshots.mkdir(parents=True,exist_ok=True)
    with ExitStack() as stack:
        if args.mock:
            print('MOCK RESPONSE MODE: in-memory UI contracts only; no security runtime or cryptographic tests')
        else:
            proc=stack.enter_context(subprocess.Popen([sys.executable,'console.py'],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True));stack.callback(proc.kill)
            line=proc.stdout.readline();print(line.strip());assert 'Recovery Console:' in line,line
            url='http://127.0.0.1:8080/'
        with sync_playwright() as pw:
            browser=pw.chromium.launch(executable_path=args.chromium,args=['--no-sandbox','--disable-dev-shm-usage','--no-proxy-server']);page=browser.new_page(viewport={'width':1440,'height':950},reduced_motion='reduce')
            errors=[];requests=[];page.on('pageerror',lambda e:errors.append(str(e)));page.on('request',lambda r:requests.append(r.url) if '/run/' in r.url else None)
            if args.mock:
                # In-memory browser rendering; no network or local-server navigation.
                html=(ROOT/'ui/mock.html').read_text().replace('<link rel="stylesheet" href="/console.css">','').replace('<script src="/console.js" defer></script>','')
                page.set_content(html)
                page.add_style_tag(content=(ROOT/'ui/console.css').read_text())
                routes={k:mock_data(k) for k in ('pre','post','lab/revocation','lab/approval','lab/competing','lab/backup','lab/passport','archive','detection')}
                page.evaluate("""({routes, stream})=>{window.mockCalls=[];window.mockOverride=null;window.fetch=async (url,opts)=>{window.mockCalls.push({url,opts});const path=url.split('/run/')[1];const x=window.mockOverride;if(x)return new Response(x.body,{status:x.status,headers:{'Content-Type':x.contentType||'application/json'}});return path==='monitor'?new Response(stream,{headers:{'Content-Type':'application/x-ndjson'}}):new Response(JSON.stringify(routes[path]),{headers:{'Content-Type':'application/json'}})}}""",dict(routes=routes,stream=mock_stream()))
                page.add_script_tag(content=(ROOT/'ui/console.js').read_text())
            else:page.goto(url)
            expect(page.locator('#mode-pill')).to_contain_text('NOT TESTED');expect(page.locator('#run')).to_be_disabled()
            assert page.locator('nav a').count()==0
            expect(page.locator('#scenario-list button')).to_have_count(11)
            def choose(key):page.locator(f'[data-id="{key}"]').click();expect(page.locator('#mode-pill')).to_contain_text('NOT TESTED')
            for key in ('overview','pre','post','revocation','approval','competing','backup','passport','monitor','detection','quarantine'):
                choose(key); page.locator('#next').click();page.locator('#prev').click();assert not (page.evaluate("mockCalls.length") if args.mock else requests)
            print('PASS all 11 expected walkthroughs, no backend requests')
            def snap(name):
                if args.screenshots: page.screenshot(path=args.screenshots/(name+'.png'),full_page=True)
            choose('post');snap('expected-recovery')
            def run_case(key,route):
                choose(key)
                if key in ('pre','post','passport'):
                    page.locator('#challenge-wrap summary').click();page.locator('#challenge').fill('cb'*32);page.locator('#challenge-wrap summary').click()
                if key=='post':page.locator('#prediction').select_option('1')
                if args.mock:
                    page.locator('#run').click();expect(page.locator('#run')).to_be_enabled(timeout=30000);assert page.evaluate('mockCalls.at(-1).url')=='/run/'+route
                else:
                    with page.expect_response(lambda r:r.url.endswith('/run/'+route),timeout=30000) as res:page.locator('#run').click()
                    expect(page.locator('#run')).to_be_enabled(timeout=30000);assert res.value.status==200
                expect(page.locator('#mode-pill')).to_have_text('REPLAY COMPLETE' if key=='detection' else 'PASS')
                assert page.locator('#timeline .event').count()>0
                page.locator('#timeline .event').last.click();expect(page.locator('#raw-wrap')).to_be_visible()
                page.locator('#raw-wrap summary').click() if page.locator('#raw-wrap').get_attribute('open') is None else None
                assert page.locator('#raw').inner_text().strip()
                if key=='post':expect(page.locator('#run-status')).to_contain_text('Prediction differed; actual v2')
                if key=='pre':expect(page.locator('#metrics')).to_contain_text('v1')
                snap('observed-'+key)
                if key=='monitor':
                    if not args.mock:
                        records=[json.loads(line) for line in res.value.text().splitlines()]
                        assert records[-1]['type']=='complete' and records[-1]['status']=='PASS'
                        findings=[x for x in records if x['type']=='finding']
                        containment=[x for x in records if x['type']=='containment']
                        assert len(findings)==len(containment)>0
                        assert len({(x['fixture'],x['request_id']) for x in findings})==len(findings)
                        assert any('before worker termination' in x['stage'] for x in findings)
                        assert any('before valid rotation' in x['stage'] for x in findings)
                        assert next(i for i,x in enumerate(records) if x['type']=='administrative_response') < next(i for i,x in enumerate(records) if x['type']=='finding')
                    return None
                return mock_data(route) if args.mock else res.value.json()
            for key,route in [('pre','pre'),('post','post'),('revocation','lab/revocation'),('approval','lab/approval'),('competing','lab/competing'),('backup','lab/backup'),('passport','lab/passport'),('quarantine','archive'),('detection','detection'),('monitor','monitor')]:
                result=run_case(key,route)
                if key in ('pre','post') and not args.mock:
                    for n in ('A','B'):
                        x=result['nodes'][n];assert x['passport']['challenge']=='cb'*32;assert x['passport']['event']['reason']=='revoked_device'
                        assert x['additional_passports']['teammate-read']['event']['version']==result['active_version']
                        if key=='post':assert x['additional_passports']['retired-version']['event']['reason']=='wrong_version'
                if key in ('pre','post') and not args.mock:
                    assert result['audit_verified'] and len([x for x in result['evidence'] if x['reason']=='version_rotated'])==(key=='post')
                    if key=='post':assert all(x['status']==403 and x['reason']=='wrong_version' for x in result['cutoff'].values())
                if key=='detection' and not args.mock:
                    assert any(x['event']['detector_context']['classification']=='policy_violation' for x in result['findings'])
                    assert any(x['event']['detector_context']['classification']=='investigate' for x in result['findings'])
                    assert any('uncertain' in x['reason'] for x in result['timing_notes'])
                if key=='quarantine' and not args.mock:
                    assert result['historical']['producer']=='worker-B' and result['historical']['event']['reason']=='revoked_device'
                if key=='passport' and not args.mock:
                    for x in result['observations'].values():assert x['statement']['signature']==x['modified_statement']['signature'] and x['statement']['signed_bytes']!=x['modified_statement']['signed_bytes']
                print('PASS observed UI route',route)
            # Returning to a previous scenario is a replay, not a new run.
            choose('post');count=page.evaluate('mockCalls.length') if args.mock else len(requests)
            page.locator('#observed').click();expect(page.locator('#mode-pill')).to_have_text('PASS')
            page.locator('#expected').click();expect(page.locator('#mode-pill')).to_contain_text('NOT TESTED')
            assert (page.evaluate('mockCalls.length') if args.mock else len(requests))==count
            first=run_case('approval','lab/approval');second=run_case('approval','lab/approval')
            if not args.mock:
                assert {x['request_id'] for x in first['observations']['outcomes']}.isdisjoint(x['request_id'] for x in second['observations']['outcomes'])
            print('PASS retained replay and repeat execution')
            choose('passport');page.locator('#challenge-wrap summary').click();page.locator('#challenge').fill('invalid');count=page.evaluate('mockCalls.length') if args.mock else len(requests);page.locator('#run').click();expect(page.locator('#run-status')).to_contain_text('NOT TESTED');assert (page.evaluate('mockCalls.length') if args.mock else len(requests))==count
            for code,outcome in [(409,'FAIL'),(503,'UNAVAILABLE')]:
                choose('passport');body=json.dumps({'error':'Injected transport test','verification_failed':code==409})
                if args.mock:page.evaluate('(x)=>window.mockOverride=x',dict(status=code,body=body))
                else:page.route('**/run/lab/passport',lambda r,c=code,b=body:r.fulfill(status=c,content_type='application/json',body=b))
                page.locator('#run').click();expect(page.locator('#mode-pill')).to_have_text(outcome);assert page.locator('#run-wrap').is_hidden()
                if args.mock:page.evaluate('window.mockOverride=null')
                else:page.unroute('**/run/lab/passport')
            if args.mock:
                choose('pre');page.evaluate('(x)=>window.mockOverride=x',dict(status=200,body=json.dumps({'active_version':2})));page.locator('#run').click();expect(page.locator('#mode-pill')).to_have_text('UNAVAILABLE');page.evaluate('window.mockOverride=null')
                choose('monitor');page.evaluate('(x)=>window.mockOverride=x',dict(status=200,body=json.dumps({'type':'fixture_started','fixture':'recovery'})+'\n',contentType='application/x-ndjson'));page.locator('#run').click();expect(page.locator('#mode-pill')).to_have_text('UNAVAILABLE');page.evaluate('window.mockOverride=null')
            if not args.mock:
                status=page.evaluate("async()=> (await fetch('/run/lab/not-a-scenario',{method:'POST',headers:{'X-Recovery-Console':'run'}})).status")
                assert status==403
            choose('pre');page.set_viewport_size({'width':390,'height':844});snap('mobile-expected');assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            assert not errors,errors
            print('PASS invalid input, failure/unavailable presentation, mobile layout, no JS errors')
            browser.close()

if __name__=='__main__':main()
