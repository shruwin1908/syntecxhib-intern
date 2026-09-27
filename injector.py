"""
Injection + reflection-detection logic.

For each form / URL parameter, every payload is sent one at a time. The
response body is then checked for the *exact unescaped* payload string.
If it appears unescaped (not HTML-entity-encoded), that's a strong signal
the input isn't being sanitized before being echoed back.
"""

import requests

from payloads import build_payloads, generate_marker, render_payload

PAYLOADS = build_payloads()


def _is_reflected_unescaped(response_text, payload):
    """
    True if the raw payload string appears verbatim in the response.
    If the app HTML-escapes it (e.g. &lt;script&gt;), it won't match here,
    which is exactly the distinction we want (sanitized vs not).
    """
    return payload in response_text


def test_url_param(session, base_url, param_name, other_params, timeout=8):
    """
    Test a single query parameter on a GET endpoint against every payload.
    Returns a list of finding dicts (empty if nothing found).
    """
    findings = []
    for name, template in PAYLOADS:
        marker = generate_marker()
        payload = render_payload(template, marker)

        params = dict(other_params)
        params[param_name] = payload

        try:
            resp = session.get(base_url, params=params, timeout=timeout)
        except requests.RequestException:
            continue

        if _is_reflected_unescaped(resp.text, payload):
            findings.append({
                "type": "reflected_xss",
                "location": "url_param",
                "endpoint": resp.url,
                "parameter": param_name,
                "payload_name": name,
                "payload": payload,
                "evidence_marker": marker,
            })
    return findings


def test_form(session, form, timeout=8):
    """
    Test every text-like input of a form against every payload, one
    input at a time (others filled with a benign placeholder value).
    Returns a list of finding dicts.
    """
    findings = []
    action = form["action"]
    method = form["method"]
    inputs = form["inputs"]

    testable_types = {"text", "search", "url", "email", "tel", "textarea", "hidden"}

    for target_input in inputs:
        if target_input["type"] not in testable_types:
            continue

        for name, template in PAYLOADS:
            marker = generate_marker()
            payload = render_payload(template, marker)

            data = {}
            for inp in inputs:
                if inp["name"] == target_input["name"]:
                    data[inp["name"]] = payload
                else:
                    data[inp["name"]] = inp.get("value") or "test"

            try:
                if method == "post":
                    resp = session.post(action, data=data, timeout=timeout)
                else:
                    resp = session.get(action, params=data, timeout=timeout)
            except requests.RequestException:
                continue

            if _is_reflected_unescaped(resp.text, payload):
                findings.append({
                    "type": "reflected_xss",
                    "location": "form_field",
                    "endpoint": action,
                    "method": method,
                    "parameter": target_input["name"],
                    "payload_name": name,
                    "payload": payload,
                    "evidence_marker": marker,
                })
    return findings
