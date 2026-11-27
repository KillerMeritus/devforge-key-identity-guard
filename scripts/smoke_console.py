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
                assert not errors, errors
                browser.close()
        finally:
            if server.poll() is None:
                server.terminate()
            server.wait(timeout=5)


if __name__ == "__main__":
    main()
