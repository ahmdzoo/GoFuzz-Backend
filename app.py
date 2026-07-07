from flask import Flask, request, jsonify
from flask import Response
from flask_cors import CORS
import pandas as pd
import joblib
import xml.etree.ElementTree as ET
import requests
import xgboost
import subprocess
import os
import re
from urllib.parse import urlparse, parse_qs, unquote, quote
from requests.compat import urljoin

app = Flask(__name__)
CORS(app)

# ==============================
# DETEKSI ENVIRONMENT
# ==============================
IS_PRODUCTION = os.environ.get("RYAZE_ENV") == "production" or os.name != "nt"

# ==============================
# LOAD MODEL
# ==============================
model = joblib.load("model_vulnerability.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# ==============================
# LABEL NAMES (5 KELAS)
# ==============================
LABEL_NAMES = [
    'Command Injection',
    'Cross-Site Scripting (XSS)',
    'Normal',
    'Path Traversal',
    'SQL Injection'
]

# ==============================
# DETEKSI KERENTANAN
# ==============================
def detect_vulnerability(status, length, attack_type):
    try:
        status = int(status)
        length = int(length)
    except:
        return "⚪ Unknown"

    if status >= 500 and attack_type != "Normal":
        return "🔴 Vulnerable"
    if status >= 500 and attack_type == "Normal":
        return "🟡 Check Needed"
    if length > 1000:
        return "🟠 Suspicious"
    if attack_type == "Normal":
        return "🟢 Safe"
    if status == 200:
        return "🟡 Check Needed"
    return "🟢 Safe"

# ==============================
# PARSER FILE
# ==============================
def parse_file(file):
    payload_list = []
    status_list = []
    length_list = []

    filename = file.filename.lower()

    if filename.endswith(".xml"):
        tree = ET.parse(file)
        root = tree.getroot()
        for item in root.iter("item"):
            url = item.findtext("url")
            status = item.findtext("status")
            length = item.findtext("responselength")
            payload = url.split("=")[-1] if url else "unknown"
            payload_list.append(payload)
            status_list.append(status)
            length_list.append(length)
    else:
        file.seek(0)
        content = file.read().decode('utf-8')
        if not content.strip():
            return [], [], []
        
        first_line = content.split('\n')[0]
        if '|' in first_line:
            sep = '|'
        elif ';' in first_line:
            sep = ';'
        elif '\t' in first_line:
            sep = '\t'
        else:
            sep = ','
        
        import io
        df = pd.read_csv(io.StringIO(content), sep=sep, on_bad_lines='skip', engine='python')
        df.columns = [col.lower().strip() for col in df.columns]
        
        if "payload" in df.columns:
            payload_list = df["payload"].astype(str).tolist()
        elif len(df.columns) >= 2:
            payload_list = df.iloc[:, 1].astype(str).tolist()
        else:
            payload_list = df.iloc[:, 0].astype(str).tolist()
        
        if "status" in df.columns:
            status_list = df["status"].tolist()
        elif len(df.columns) >= 3:
            status_list = df.iloc[:, 2].tolist()
        else:
            status_list = [''] * len(payload_list)
        
        if "length" in df.columns:
            length_list = df["length"].tolist()
        elif len(df.columns) >= 5:
            length_list = df.iloc[:, 4].tolist()
        else:
            length_list = [''] * len(payload_list)
        
        payload_list = [str(p) for p in payload_list]
        status_list = [str(s) if s is not None else '' for s in status_list]
        length_list = [str(l) if l is not None else '' for l in length_list]

    return payload_list, status_list, length_list

# ==============================
# FUNGSI CRAWL DENGAN REQUESTS (CEPAT, TANPA BROWSER)
# ==============================
def crawl_with_requests(url):
    endpoints = []
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        r = requests.get(url, headers=headers, timeout=15)
        r.raise_for_status()

        hrefs = re.findall(r'href=["\'](.*?)["\']', r.text, re.IGNORECASE)

        for href in hrefs:
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            if not href.startswith(("http://", "https://")):
                href = urljoin(url, href)
            if "?" in href and "=" in href:
                endpoints.append(href)

        raw_urls = re.findall(r'(https?://[^\s"\'<>]+)', r.text)
        for u in raw_urls:
            if "?" in u and "=" in u and u not in endpoints:
                endpoints.append(u)

        seen = set()
        return [ep for ep in endpoints if not (ep in seen or seen.add(ep))]
    except Exception as e:
        print(f"❌ Requests crawl error: {e}")
        return []

# ==============================
# FUNGSI CRAWL DENGAN KATANA
# ==============================
def crawl_with_katana(url):
    katana_path = os.path.join(os.path.dirname(__file__), "katana.exe")
    if not os.path.exists(katana_path):
        return []
    
    try:
        cmd = [katana_path, "-u", url, "-d", "2", "-o", "endpoints.txt"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return []
        
        endpoints = []
        with open("endpoints.txt", "r") as f:
            for line in f:
                line = line.strip()
                if "?" in line and "=" in line:
                    endpoints.append(line)
        return endpoints
    except Exception as e:
        print(f"❌ Katana error: {e}")
        return []

# ==============================
# ENDPOINT /crawl
# ==============================
@app.route("/crawl", methods=["POST"])
def crawl():
    data = request.get_json()
    url = data.get("url")
    
    if not url:
        return jsonify({"error": "URL kosong"}), 400
    
    print(f"🔍 Crawling: {url}")
    print(f"📌 Environment: {'Production (Linux)' if IS_PRODUCTION else 'Local (Windows)'}")
    
    print("   🌐 Using Requests crawler...")
    endpoints = crawl_with_requests(url)
    
    if not endpoints and not IS_PRODUCTION:
        print("   ⚡ Fallback ke Katana...")
        endpoints = crawl_with_katana(url)
    
    if not endpoints:
        return jsonify({
            "endpoints": [],
            "params": [],
            "count": 0,
            "message": "⚠️ Tidak ada endpoint ditemukan."
        })
    
    params = []
    for ep in endpoints:
        match = re.search(r'\?(.+?)=', ep)
        if match:
            params.append(match.group(1))
    params = list(set(params))
    
    return jsonify({
        "endpoints": endpoints[:25],
        "params": params[:25],
        "count": len(endpoints),
        "total_params": len(params)
    })

# ==============================
# ENDPOINT /analyze
# ==============================
@app.route("/analyze", methods=["POST"])
def analyze():
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "File tidak ditemukan"}), 400

    payload_list, status_list, length_list = parse_file(file)

    X = vectorizer.transform(payload_list)
    pred = model.predict(X)
    pred_proba = model.predict_proba(X)

    results = []
    for idx, (p, pr, s, l) in enumerate(zip(payload_list, pred, status_list, length_list)):
        attack = LABEL_NAMES[pr]
        vuln = detect_vulnerability(s, l, attack)
        confidence = float(max(pred_proba[idx])) * 100

        results.append({
            "payload": str(p),
            "attack": str(attack),
            "vulnerability": str(vuln),
            "status": str(s),
            "length": int(l) if l else 0,
            "ml_prediction": int(pr),
            "confidence": float(round(confidence, 2))
        })

    return jsonify(results)

# ==============================
# ENDPOINT /scan
# ==============================
@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    url = data.get("url")
    param = data.get("param", "q")
    limit = data.get("limit", 50)

    if not url:
        return jsonify({"error": "URL kosong"}), 400

    try:
        with open("payload.txt", "r", encoding="utf-8") as f:
            all_payloads = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        all_payloads = [
            "' OR 1=1 --",
            "<script>alert(1)</script>",
            "../../etc/passwd",
            "; ls",
            "&& whoami",
            "normal_string"
        ]

    payloads = all_payloads[:limit] if limit and limit > 0 else all_payloads[:50]
    results = []

    for p in payloads:
        try:
            print(f"🔄 Scanning payload {payloads.index(p)+1}/{len(payloads)}...")
            full_url = f"{url}?{param}={quote(p)}"
            r = requests.get(full_url, timeout=5)
            
            status = r.status_code
            length = 0
            
            try:
                if r.text:
                    length = len(r.text)
            except:
                pass
            
            if length == 0 and r.content:
                try:
                    length = len(r.content.decode('utf-8', errors='ignore'))
                except:
                    length = len(r.content)
            
            if length == 0:
                content_length = r.headers.get('Content-Length')
                if content_length:
                    length = int(content_length)
            
            if length == 0 and r.raw:
                length = len(r.raw.read())
            
            print(f"   📊 Length: {length} | Status: {status}")

            X = vectorizer.transform([p])
            pred = model.predict(X)[0]
            attack = LABEL_NAMES[pred]
            pred_proba = model.predict_proba(X)
            confidence = float(max(pred_proba[0])) * 100
            vuln = detect_vulnerability(status, length, attack)

            results.append({
                "payload": p,
                "status": status,
                "attack": attack,
                "vulnerability": vuln,
                "length": length,
                "ml_prediction": int(pred),
                "confidence": float(round(confidence, 2))
            })

        except requests.exceptions.Timeout:
            results.append({
                "payload": p,
                "status": "timeout",
                "attack": "Unknown",
                "vulnerability": "🟠 Suspicious",
                "length": 0,
                "ml_prediction": -1,
                "confidence": 0
            })
        except Exception as e:
            print(f"❌ Error: {e}")
            results.append({
                "payload": p,
                "status": "error",
                "attack": "Unknown",
                "vulnerability": "Request Failed",
                "length": 0,
                "ml_prediction": -1,
                "confidence": 0
            })

    return jsonify(results)

# ==============================
# ENDPOINT /detect-params
# ==============================
@app.route("/detect-params", methods=["POST"])
def detect_params():
    url = request.get_json().get("url")
    if not url:
        return jsonify({"error": "URL kosong"}), 400

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    detected = list(params.keys()) if params else []

    if "login.aspx" in url.lower():
        if "ReturnUrl" in parsed.query:
            detected = ["ReturnUrl"]
        else:
            detected = ["ReturnUrl", "username", "password"]

    if not detected:
        recommendations = ["q", "id", "search", "sort", "page"]
        url_lower = url.lower()
        if "product" in url_lower:
            recommendations.extend(["category", "sort"])
        if "user" in url_lower or "profile" in url_lower:
            recommendations.extend(["username", "email"])
        if "search" in url_lower:
            recommendations.insert(0, "search")
        if "login" in url_lower or "auth" in url_lower:
            recommendations = ["ReturnUrl", "username", "password"]
        detected = list(dict.fromkeys(recommendations))[:5]

    return jsonify({"params": detected, "count": len(detected)})

# ==============================
# ROOT
# ==============================
@app.route("/")
def home():
    return "🔥 Backend jalan! Model sudah diupdate dengan 5 kelas"

# ==============================
# ENDPOINT /parse-burp
# ==============================
@app.route("/parse-burp", methods=["POST"])
def parse_burp():
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file"}), 400
    
    filename = file.filename.lower()
    results = []
    position = 0
    
    if filename.endswith(".xml"):
        tree = ET.parse(file)
        root = tree.getroot()
        for item in root.iter("item"):
            position += 1
            url = item.findtext("url", "")
            status = item.findtext("status", "")
            length = item.findtext("responselength", "")
            payload = ""
            if "?q=" in url:
                payload = unquote(url.split("?q=")[-1])
            results.append({"position": position, "payload": payload, "status": status, "length": length})
    else:
        content = file.read().decode('utf-8')
        lines = content.strip().split('\n')
        for line in lines:
            line = line.strip()
            if not line or line.startswith('Request') or line.startswith('position'):
                continue
            position += 1
            parts = line.split('\t')
            if len(parts) >= 5:
                payload = parts[1].strip()
                status = parts[2].strip()
                length = parts[4].strip()
                if ',' in payload:
                    payload = payload.split(',')[0]
                payload = payload.strip('"').strip("'")
                results.append({"position": position, "payload": payload, "status": status, "length": length})
    
    if not results:
        return jsonify({"error": "No data extracted"}), 400
    
    import csv
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['position', 'payload', 'status', 'length'])
    for r in results:
        writer.writerow([r['position'], r['payload'], r['status'], r['length']])
    
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=parsed_output.csv"}
    )

# ==============================
# RUN
# ==============================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(debug=False, host="0.0.0.0", port=port)
