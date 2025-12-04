# report/html_report.py
from jinja2 import Template

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>WebScanPro Security Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            padding: 20px;
            background: #f5f6fa;
        }
        h1 {
            background: #2f3542;
            color: white;
            padding: 12px;
            border-radius: 6px;
        }
        h2 {
            color: #2f3542;
            border-left: 6px solid #57606f;
            padding-left: 10px;
        }
        .summary-box {
            background: white;
            border-radius: 6px;
            box-shadow: 0px 2px 6px rgba(0,0,0,0.1);
            padding: 15px;
            margin-bottom: 20px;
        }
        .vuln-box {
            background: white;
            padding: 15px;
            margin-bottom: 15px;
            border-left: 6px solid #ff6b6b;
            border-radius: 6px;
            box-shadow: 0px 2px 5px rgba(0,0,0,0.1);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            margin-top: 10px;
        }
        th, td {
            padding: 10px;
            border: 1px solid #dfe4ea;
        }
        th {
            background: #2f3542;
            color: white;
        }
        .sev-high { background: #ff6b6b; color: white; padding: 4px 8px; border-radius: 4px; }
        .sev-medium { background: #ffa502; color: white; padding: 4px 8px; border-radius: 4px; }
        .sev-low { background: #2ed573; color: white; padding: 4px 8px; border-radius: 4px; }
        pre {
            background: #f1f2f6;
            padding: 10px;
            border-radius: 6px;
            overflow-x: auto;
        }
    </style>
</head>
<body>

<h1>WebScanPro Security Report</h1>

<div class="summary-box">
    <h2>Target Information</h2>
    <p><strong>Target URL:</strong> {{ meta.base_url }}</p>
    <p><strong>Scan Started:</strong> {{ meta.start }}</p>
</div>

<div class="summary-box">
    <h2>Summary of Findings</h2>
    <table>
        <tr>
            <th>Vulnerability Category</th>
            <th>Findings</th>
        </tr>
        <tr><td>SQL Injection</td><td>{{ sqli|length }}</td></tr>
        <tr><td>Cross-Site Scripting (XSS)</td><td>{{ xss|length }}</td></tr>
        <tr><td>Authentication Issues</td><td>{{ auth|length }}</td></tr>
        <tr><td>Access Control / IDOR</td><td>{{ idor|length }}</td></tr>
    </table>
</div>

<h2>Detailed Findings</h2>

<!-- SQL Injection -->
{% if sqli %}
<h2>SQL Injection ({{ sqli|length }} findings)</h2>
{% for item in sqli %}
<div class="vuln-box">
    <h3>SQL Injection</h3>
    <p><strong>Endpoint:</strong> {{ item.endpoint }}</p>
    <p><strong>Severity:</strong> <span class="sev-high">HIGH</span></p>
    <p><strong>Payload Used:</strong> {{ item.payload }}</p>

    <p><strong>Suggested Mitigation:</strong></p>
    <ul>
        <li>Use prepared statements / parameterized queries.</li>
        <li>Validate and sanitize user inputs.</li>
        <li>Use ORM frameworks to avoid raw queries.</li>
    </ul>

    <p><strong>Evidence:</strong></p>
    <pre>{{ item.evidence | tojson(indent=2) }}</pre>
</div>
{% endfor %}
{% endif %}

<!-- XSS -->
{% if xss %}
<h2>Cross-Site Scripting ({{ xss|length }} findings)</h2>
{% for item in xss %}
<div class="vuln-box">
    <h3>Reflected XSS</h3>
    <p><strong>Endpoint:</strong> {{ item.endpoint }}</p>
    <p><strong>Severity:</strong> <span class="sev-high">HIGH</span></p>
    <p><strong>Payload Used:</strong> {{ item.payload }}</p>

    <p><strong>Suggested Mitigation:</strong></p>
    <ul>
        <li>Use HTML escaping for all dynamic content.</li>
        <li>Implement Content Security Policy (CSP).</li>
        <li>Validate and sanitize user inputs.</li>
    </ul>

    <p><strong>Evidence:</strong></p>
    <pre>{{ item.evidence | tojson(indent=2) }}</pre>
</div>
{% endfor %}
{% endif %}

<!-- Auth -->
{% if auth %}
<h2>Authentication Issues ({{ auth|length }} findings)</h2>
{% for item in auth %}
<div class="vuln-box" style="border-left-color:#ffa502;">
    <h3>Authentication Misconfiguration</h3>
    <p><strong>Endpoint:</strong> {{ item.endpoint if item.endpoint else "Login Page" }}</p>
    <p><strong>Severity:</strong> <span class="sev-medium">MEDIUM</span></p>

    {% if item.credential %}
    <p><strong>Weak Credential Found:</strong> {{ item.credential.username }} / {{ item.credential.password }}</p>
    {% endif %}

    <p><strong>Suggested Mitigation:</strong></p>
    <ul>
        <li>Enforce strong password policies.</li>
        <li>Implement account lockout after failed attempts.</li>
        <li>Use CAPTCHA for login brute-force prevention.</li>
    </ul>

    <p><strong>Details:</strong></p>
    <pre>{{ item | tojson(indent=2) }}</pre>
</div>
{% endfor %}
{% endif %}

<!-- IDOR -->
{% if idor %}
<h2>Access Control / IDOR ({{ idor|length }} findings)</h2>
{% for item in idor %}
<div class="vuln-box" style="border-left-color:#ffa502;">
    <h3>Insecure Direct Object Reference (IDOR)</h3>
    <p><strong>Endpoint:</strong> {{ item.endpoint }}</p>
    <p><strong>Severity:</strong> <span class="sev-medium">MEDIUM</span></p>

    <p><strong>Parameter Tested:</strong> {{ item.param }}</p>

    <p><strong>Suggested Mitigation:</strong></p>
    <ul>
        <li>Use server-side authorization checks.</li>
        <li>Never trust user-modified parameters.</li>
        <li>Use per-user object references (UUID, hashed IDs).</li>
    </ul>

    <p><strong>Evidence Snippet:</strong></p>
    <pre>{{ item.evidence_snippet }}</pre>
</div>
{% endfor %}
{% endif %}

</body>
</html>
"""

def generate_html_report(data, output_path):
    template = Template(HTML_TEMPLATE)
    html = template.render(
        meta=data["meta"],
        sqli=data["sqli"],
        xss=data["xss"],
        auth=data["auth"],
        idor=data["idor"]
    )
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
