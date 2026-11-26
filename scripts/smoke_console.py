"""Exercise both baseline recovery cases in Chromium with Playwright."""
import argparse
import subprocess
import sys
from playwright.sync_api import expect, sync_playwright


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chromium", help="optional path to a Chromium executable")
    args = parser.parse_args()
    with subprocess.Popen([sys.executable, "console.py"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as server:
        try:
            print(server.stdout.readline().strip())
            with sync_playwright() as runner:
                browser = runner.chromium.launch(
                    executable_path=args.chromium,
                    args=["--no-sandbox", "--disable-dev-shm-usage", "--no-proxy-server"],
                )
                page = browser.new_page()
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.goto("http://127.0.0.1:8080/")
                for phase, outcome, prefix in (
                    ("pre", "v1", "Prediction verified."),
                    ("post", "v2", "Prediction differed."),
                ):
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
                    print(f"PASS {phase}: {outcome}, both nodes verified, prediction checked, audit evidence opened")
                assert not errors, errors
                browser.close()
        finally:
            if server.poll() is None:
                server.terminate()
            server.wait(timeout=5)


if __name__ == "__main__":
    main()
