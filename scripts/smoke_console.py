"""Exercise both baseline recovery cases in Chromium with Playwright."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
from playwright.sync_api import expect, sync_playwright


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chromium", help="optional path to a Chromium executable")
    parser.add_argument("--screenshots", type=Path, help="save observed scenario screenshots")
    args = parser.parse_args()
    if args.screenshots:
        args.screenshots.mkdir(parents=True, exist_ok=True)
    with subprocess.Popen([sys.executable, "console.py"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as server:
        try:
            print(server.stdout.readline().strip())
            with sync_playwright() as runner:
                browser = runner.chromium.launch(
                    executable_path=args.chromium,
                    args=["--no-sandbox", "--disable-dev-shm-usage", "--no-proxy-server"],
                )
                page = browser.new_page(viewport={"width": 1360, "height": 900})

                def capture(name):
                    if args.screenshots:
                        page.screenshot(path=args.screenshots / (name + ".png"))
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.goto("http://127.0.0.1:8080/")
                expect(page.locator("#check-revocation")).to_have_text("PENDING")
                capture("recovery-ready")
                for phase, outcome, prefix in (
                    ("pre", "v1", "Prediction verified."),
                    ("post", "v2", "Prediction differed."),
                ):
                    page.locator("#challenge").fill("cb" * 32)
                    page.locator("#phase").select_option(phase)
                    page.locator("#prediction").select_option("1")
                    with page.expect_response(lambda response: response.url.endswith("/run/" + phase), timeout=20000) as run:
                        page.get_by_role("button", name="Run recovery test").click()
                    assert run.value.status == 200
                    expect(page.locator("#version")).to_have_text(outcome)
                    expect(page.locator("#result")).to_contain_text(prefix)
                    for node in ("A", "B"):
                        expect(page.locator("#node" + node)).to_have_text("Revocation verified")
                    for event in page.locator(".event").all():
                        event.click()
                        if '"audit": "verified"' in page.locator("#evidence").inner_text():
                            break
                    else:
                        raise AssertionError("No verified audit evidence displayed")
                    if phase == "post":
                        for node in ("A", "B"):
                            expect(page.locator("#details" + node)).to_contain_text("v1 rejected with HTTP 403")
                    for check in ("revocation", "access", "audit"):
                        expect(page.locator("#check-" + check)).to_have_text("PASS")
                    page.locator("#check-revocation button").click()
                    observed = json.loads(page.locator("#evidence").inner_text())
                    for node in ("A", "B"):
                        assert observed[node]["passport"]["challenge"] == "cb" * 32
                        assert observed[node]["passport"]["event"]["reason"] == "revoked_device"
                        statements = observed[node]["additional_passports"]
                        teammate = statements["teammate-read"]["event"]
                        assert (teammate["allowed"], teammate["reason"], teammate["version"]) == (
                            True, "read", int(outcome[1:])
                        )
                        if phase == "post":
                            retired = statements["retired-version"]["event"]
                            assert (retired["allowed"], retired["reason"], retired["version"]) == (
                                False, "wrong_version", 1
                            )
                        else:
                            assert "retired-version" not in statements
                    page.evaluate("window.scrollTo(0, 0)")
                    capture("recovery-" + phase)
                    print(f"PASS {phase}: {outcome}, both nodes verified, prediction checked, audit evidence opened")
                with page.expect_response("**/run/detection") as run:
                    page.get_by_role("button", name="Replay detector evidence").click()
                assert run.value.status == 200
                expect(page.locator("#check-detector")).to_have_text("PASS")
                expect(page.locator("#detections")).to_contain_text("order uncertain")
                page.get_by_role("button", name="Investigate", exact=False).filter(has_text="access outside approval").click()
                expect(page.locator("#evidence")).to_contain_text("Approval boundary overlaps")
                page.get_by_role("button", name="Violation", exact=False).first.click()
                expect(page.locator("#evidence")).to_contain_text("policy_violation")
                expect(page.locator("#evidence")).to_contain_text("explanation")
                expect(page.locator("#evidence")).to_contain_text("CONFIRMED")
                page.locator("#evidence-panel").scroll_into_view_if_needed()
                capture("detection")
                print("PASS detection: confirmed source references, approvals, policy classification, and clock uncertainty")

                with page.expect_response("**/run/archive", timeout=20000) as run:
                    page.get_by_role("button", name="Run archive restore").click()
                assert run.value.status == 200
                expect(page.locator("#check-archive")).to_have_text("PASS")
                expect(page.locator("#archive-events")).to_contain_text("Stale read → HTTP 503")
                page.get_by_role("button", name="Archive Historical receipt").click()
                expect(page.locator("#evidence")).to_contain_text("worker-B")
                expect(page.locator("#evidence")).to_contain_text("revoked_device")
                page.locator("#evidence-panel").scroll_into_view_if_needed()
                capture("archive")
                print("PASS archive: quarantine, retained historical evidence, and verified current recovery")
                choice = page.locator("#lab-choice")
                lab_status = page.locator("#lab-status")
                lab_button = page.get_by_role("button", name="Run scenario", exact=True)

                def exercise_lab(name):
                    choice.select_option(name)
                    with page.expect_response("**/run/lab/" + name, timeout=20000) as request:
                        lab_button.click()
                    assert request.value.status == 200
                    expect(lab_status).to_contain_text("PASS")
                    return request.value.json()["observations"]

                lab_results = {name: exercise_lab(name) for name in
                               ("revocation", "approval", "competing", "pre", "post", "backup", "quarantine")}
                assert {item["denial_reason"] for item in lab_results["revocation"].values()} == {"revoked_device"}
                initial = lab_results["approval"]
                assert [item["reason"] for item in initial["outcomes"]] == [
                    "approval_expired", "version_rotated", "approval_missing"
                ]
                repeated = exercise_lab("approval")
                assert [item["reason"] for item in repeated["outcomes"]] == [
                    item["reason"] for item in initial["outcomes"]
                ]
                assert {item["request_id"] for item in repeated["outcomes"]}.isdisjoint(
                    item["request_id"] for item in initial["outcomes"]
                )
                assert sorted(item["status"] for item in lab_results["competing"]["outcomes"]) == [200, 403]
                assert [lab_results[phase]["active_version"] for phase in ("pre", "post")] == [1, 2]
                assert lab_results["backup"]["intact_accepted"] and not lab_results["backup"]["damaged_accepted"]
                assert {item["status"] for item in lab_results["quarantine"]["quarantine"].values()} == {503}
                page.locator("#scenario-lab").scroll_into_view_if_needed()
                capture("scenario-approval")

                choice.select_option("passport")
                page.locator("#lab-challenge").fill("invalid")
                with page.expect_response("**/run/lab/passport") as invalid:
                    lab_button.click()
                assert invalid.value.status == 400
                expect(lab_status).to_contain_text("NOT TESTED")
                challenge = "cad0" * 16
                page.locator("#lab-challenge").fill(challenge)
                passports = exercise_lab("passport")
                for node, result in passports.items():
                    assert result["node"] == node and result["challenge"] == challenge
                    assert result["original"] == "STATEMENT AUTHENTICATED"
                    assert result["modified"] == "REJECTED"
                    assert result["statement"]["signature"] == result["modified_statement"]["signature"]
                    assert result["statement"]["signed_bytes"] != result["modified_statement"]["signed_bytes"]
                page.get_by_text("Node A · STATEMENT AUTHENTICATED", exact=False).click()
                page.locator("#scenario-lab").scroll_into_view_if_needed()
                capture("scenario-passport")
                for code, expected in ((409, "FAIL"), (503, "UNAVAILABLE")):
                    def fixture_failure(route):
                        route.fulfill(status=code, json={"error": "Simulated fixture failure",
                                                        "verification_failed": code == 409})
                    page.route("**/run/lab/passport", fixture_failure)
                    lab_button.click()
                    expect(lab_status).to_contain_text(expected)
                    expect(page.locator("#lab-outcome details")).to_have_count(0)
                    page.unroute("**/run/lab/passport", fixture_failure)
                with page.expect_response("**/run/lab/not-a-scenario") as invalid_route:
                    page.evaluate("""fetch('/run/lab/not-a-scenario', {
                        method: 'POST', headers: {'X-Recovery-Console': 'run'}
                    })""")
                assert invalid_route.value.status == 403
                print("PASS all eight lab scenarios, repeat isolation, invalid input, and error presentation")
                assert not errors, errors
                browser.close()
        finally:
            if server.poll() is None:
                server.terminate()
            server.wait(timeout=5)


if __name__ == "__main__":
    main()
