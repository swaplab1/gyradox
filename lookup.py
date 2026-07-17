from flask import Flask, request, jsonify, render_template
import requests
from flask_cors import CORS
from openai import OpenAI

session = requests.Session()
session.trust_env = False 

app = Flask(__name__)
CORS(app)

# ------------------------------------------------
# API KEYS
# ------------------------------------------------
VT_API_KEY = ""
ABUSEIPDB_KEY = ""
WHOISXML_KEY = ""   # <── ADD THIS
client = OpenAI(api_key="")

BASE = "https://threatfox.abuse.ch/export/json"

THREATFOX_API = ""

@app.get("/")
def home():
    return render_template("index.html")


# ------------------------------------------------
# VirusTotal - IP Lookup
# ------------------------------------------------
@app.get("/vt/ip/<string:ip>")
def vt_ip(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    return jsonify(requests.get(url, headers=headers).json())


# ------------------------------------------------
# VirusTotal - URL Submit
# ------------------------------------------------
@app.post("/vt/url")
def vt_url():
    url_to_scan = request.json.get("url")
    scan_url = "https://www.virustotal.com/api/v3/urls"

    headers = {
        "x-apikey": VT_API_KEY,
        "content-type": "application/x-www-form-urlencoded"
    }

    encoded = f"url={url_to_scan}"
    resp = requests.post(scan_url, headers=headers, data=encoded)
    return jsonify(resp.json())


# ------------------------------------------------
# VirusTotal - Analysis
# ------------------------------------------------
@app.get("/vt/analysis/<string:scan_id>")
def vt_analysis(scan_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    headers = {"x-apikey": VT_API_KEY}
    return jsonify(requests.get(url, headers=headers).json())


# ------------------------------------------------
# VirusTotal - File Hash
# ------------------------------------------------
@app.get("/vt/hash/<string:file_hash>")
def vt_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    return jsonify(requests.get(url, headers=headers).json())


# ------------------------------------------------
# AbuseIPDB Lookup
# ------------------------------------------------
@app.get("/abuse/<string:ip>")
def abuse_ip(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": "90"}

    headers = {
        "Key": ABUSEIPDB_KEY,
        "Accept": "application/json"
    }

    r = requests.get(url, headers=headers, params=params)
    return jsonify(r.json())


# ------------------------------------------------
# WHOISXMLAPI DOMAIN LOOKUP (NEW)
# ------------------------------------------------
@app.get("/whoisxml/<string:domain>")
def whoisxml_lookup(domain):
    api_url = (
        f"https://www.whoisxmlapi.com/whoisserver/WhoisService"
        f"?apiKey={WHOISXML_KEY}&domainName={domain}&outputFormat=JSON"
    )

    try:
        r = requests.get(api_url, timeout=15)
        r.raise_for_status()
        return jsonify(r.json())

    except requests.exceptions.Timeout:
        return jsonify({"error": "WhoisXMLAPI timeout"}), 504

    except requests.exceptions.HTTPError as e:
        return jsonify({"error": f"HTTP error: {str(e)}"}), 500

    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500


# -----------------------------
# THREATFOX — Unified Query Function
# -----------------------------
def fetch_threatfox(url):
    try:
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            return {"error": f"ThreatFox returned {r.status_code}"}
        return {"data": r.json()}
    except Exception as e:
        return {"error": str(e)}

@app.get("/threatfox/malware")
def tf_malware():
    return jsonify(fetch_threatfox(f"{BASE}/sha256/recent/"))

@app.get("/threatfox/phishing")
def tf_phishing():
    return jsonify(fetch_threatfox(f"{BASE}/urls/recent/"))

@app.get("/threatfox/botnets")
def tf_botnets():
    return jsonify(fetch_threatfox(f"{BASE}/ip-port/recent/"))

@app.get("/threatfox/cve")
def tf_cve():
    return jsonify(fetch_threatfox(f"{BASE}/domains/recent/"))

@app.get("/threatfox/ransomware")
def tf_ransomware():
    return jsonify(fetch_threatfox(f"{BASE}/md5/recent/"))

# --------------------------------------
# ThreatFox - Search by Malware Name
# --------------------------------------

@app.get("/threatfox/search/<name>")
def threatfox_search(name):
    name = name.lower()
    url = "https://threatfox.abuse.ch/export/json/recent/"

    try:
        r = requests.get(url, timeout=10)

        print("DEBUG status:", r.status_code)
        print("DEBUG RAW:", r.text[:400])  # keep logging

        try:
            data = r.json()
        except:
            return jsonify({"error": "ThreatFox returned non-JSON response"})

        # --- REALITY: ThreatFox returns a dict of lists like { "1649294": [ {...} ] }
        if not isinstance(data, dict):
            return jsonify({"error": "Unexpected API format"})

        out = []

        # Example structure: { "1649294":[{...}], "1649295":[{...}] }
        for key, arr in data.items():
            if not isinstance(arr, list):
                continue

            for item in arr:
                if not isinstance(item, dict):
                    continue

                m = (item.get("malware") or "").lower()
                alias = (item.get("malware_alias") or "").lower()
                printable = (item.get("malware_printable") or "").lower()

                if name in m or name in alias or name in printable:
                    out.append(item)

        return jsonify({"data": out})

    except Exception as e:
        return jsonify({"error": str(e)})


# ------------------------------------------------
# Test Route
# ------------------------------------------------
@app.get("/test")
def test():
    return "Flask is working!"


# ------------------------------------------------
# Query Builder
# ------------------------------------------------
@app.route("/query")
def query():
    return render_template("query.html")

# ------------------------------------------------
# Ask AI
# ------------------------------------------------
@app.post("/askai")
def ask_ai():
    data = request.json
    ip = data.get("ip")
    url = data.get("url")
    file_hash = data.get("hash")

    user_input = ip or url or file_hash
    if not user_input:
        return jsonify({"answer": "No input received."})

    prompt = f"""
Threat Analysis Request:
Value: {user_input}

Provide:
1. Threat Summary
2. Risk Score (1–10)
3. Likely Threat Category
4. Recommended Actions
"""

    try:
        completion = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}]
        )
        return jsonify({"answer": completion.choices[0].message.content})

    except Exception as e:
        return jsonify({"answer": f"AI Error: {str(e)}"})


# ------------------------------------------------
# Run Server
# ------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
