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

app = Flask(__name__)
CORS(app)

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
# DETEKSI KERENTANAN (DIPERBAIKI)
# ==============================
def detect_vulnerability(status, length, attack_type):
    try:
        status = int(status)
        length = int(length)
    except:
        return "⚪ Unknown"

    # 🔴 PRIORITAS 1: Status 500 + BUKAN Normal → Vulnerable
    if status >= 500 and attack_type != "Normal":
        return "🔴 Vulnerable"
    
    # 🔴 PRIORITAS 2: Status 500 + Normal → Check Needed
    if status >= 500 and attack_type == "Normal":
        return "🟡 Check Needed"
    
    # 🔴 PRIORITAS 3: Length > 1000 → Suspicious
    if length > 1000:
        return "🟠 Suspicious"
    
    # 🔴 PRIORITAS 4: Normal → Safe
    if attack_type == "Normal":
        return "🟢 Safe"
    
    # 🔴 PRIORITAS 5: Status 200 → Check Needed
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

    # XML
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

    # CSV
    else:
        # Reset pointer ke awal file
        file.seek(0)
        
        # Baca file sebagai text
        content = file.read().decode('utf-8')
        
        if not content.strip():
            return [], [], []
        
        # Deteksi separator dari baris pertama
        first_line = content.split('\n')[0]
        
        if '|' in first_line:
            sep = '|'
        elif ';' in first_line:
            sep = ';'
        elif '\t' in first_line:
            sep = '\t'
        else:
            sep = ','
        
        # Baca CSV dengan separator yang terdeteksi
        import io
        df = pd.read_csv(io.StringIO(content), sep=sep, on_bad_lines='skip', engine='python')
        
        # Normalize column names
        df.columns = [col.lower().strip() for col in df.columns]
        
        # Extract payload
        if "payload" in df.columns:
            payload_list = df["payload"].astype(str).tolist()
        elif len(df.columns) >= 2:
            payload_list = df.iloc[:, 1].astype(str).tolist()
        else:
            payload_list = df.iloc[:, 0].astype(str).tolist()
        
        # Extract status
        if "status" in df.columns:
            status_list = df["status"].tolist()
        elif len(df.columns) >= 3:
            status_list = df.iloc[:, 2].tolist()
        else:
            status_list = [''] * len(payload_list)
        
        # Extract length
        if "length" in df.columns:
            length_list = df["length"].tolist()
        elif len(df.columns) >= 5:
            length_list = df.iloc[:, 4].tolist()
        else:
            length_list = [''] * len(payload_list)
        
        # Convert ke string
        payload_list = [str(p) for p in payload_list]
        status_list = [str(s) if s is not None else '' for s in status_list]
        length_list = [str(l) if l is not None else '' for l in length_list]

    return payload_list, status_list, length_list

@app.route("/crawl", methods=["POST"])
def crawl():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "URL kosong"}), 400

    # 🔴 PASTIKAN PATH KATANA BENAR
    katana_path = os.path.join(os.path.dirname(__file__), "katana.exe")
    
    if not os.path.exists(katana_path):
        return jsonify({"error": "katana.exe tidak ditemukan"}), 500

    try:
        cmd = [katana_path, "-u", url, "-d", "2", "-o", "endpoints.txt"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            return jsonify({"error": f"Katana error: {result.stderr}"}), 500

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Crawl timeout (30 detik)"}), 408
    except Exception as e:
        return jsonify({"error": f"Error: {str(e)}"}), 500

    # 🔴 BACA HASIL
    endpoints = []
    try:
        with open("endpoints.txt", "r") as f:
            for line in f:
                line = line.strip()
                if "?" in line and "=" in line:
                    endpoints.append(line)
    except:
        return jsonify({"error": "Gagal baca hasil crawl"}), 500

    # 🔴 EKSTRAK PARAMETER
    params = []
    for ep in endpoints:
        match = re.search(r'\?(.+?)=', ep)
        if match:
            params.append(match.group(1))
    params = list(set(params))

    # ==========================================================
    # 🔴🔴🔴 TARUH PESAN INI KALO ENDPOINT KOSONG!
    # ==========================================================
    if len(endpoints) == 0:
        return jsonify({
            "endpoints": [],
            "params": [],
            "count": 0,
            "message": "⚠️ Tidak ada endpoint ditemukan. Website ini mungkin SPA (Single Page Application) atau statis, tidak memiliki parameter URL yang bisa di-scan."
        })

    return jsonify({
        "endpoints": endpoints[:25],
        "params": params[:25],
        "count": len(endpoints),
        "total_params": len(params)  # 🔴 TAMBAHKAN INI!

    })

# ==============================
# ANALYZE FILE
# ==============================
@app.route("/analyze", methods=["POST"])
def analyze():
    file = request.files.get("file")

    if not file:
        return jsonify({"error": "File tidak ditemukan"}), 400

    payload_list, status_list, length_list = parse_file(file)

    # ML prediction
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
            "confidence": float(round(confidence, 2))  #
        })

    return jsonify(results)



# ==============================
# SCAN URL (FIXED - LENGTH)
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

    if limit and limit > 0:
        payloads = all_payloads[:limit]
    else:
        payloads = all_payloads[:50]

    results = []

    for p in payloads:
        try:
            print(f"🔄 Scanning payload {payloads.index(p)+1}/{len(payloads)}...")
            from urllib.parse import quote
            full_url = f"{url}?{param}={quote(p)}"
            
            r = requests.get(full_url, timeout=5)
            
            status = r.status_code
            
            # 🔴 FIX LENGTH - MULTI LAYER
            length = 0
            
            # Layer 1: Coba r.text (requests sudah decode)
            try:
                response_text = r.text
                if response_text:
                    length = len(response_text)
            except:
                pass
            
            # Layer 2: Jika masih 0, coba r.content
            if length == 0 and r.content:
                try:
                    length = len(r.content.decode('utf-8', errors='ignore'))
                except:
                    length = len(r.content)
            
            # Layer 3: Jika masih 0, coba header
            if length == 0:
                content_length = r.headers.get('Content-Length')
                if content_length:
                    length = int(content_length)
            
            # Layer 4: Jika masih 0, coba raw
            if length == 0 and r.raw:
                length = len(r.raw.read())
            
            print(f"   📊 Length: {length} | Status: {status}")

            # ML Prediction
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
    data = request.get_json()
    url = data.get("url")
    param = data.get("param", "q")
    limit = data.get("limit", 50)  # 🔴 BISA PILIH! 50, 100, 200, 490

    if not url:
        return jsonify({"error": "URL kosong"}), 400

    # Ambil payload dari payload.txt
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

    # 🔴 BATASI JUMLAH SESUAI PILIHAN USER
    if limit and limit > 0:
        payloads = all_payloads[:limit]
    else:
        payloads = all_payloads[:50]  # Default 50

    results = []

    for p in payloads:
        try:
            print(f"🔄 Scanning payload {payloads.index(p)+1}/{len(payloads)}...") # <--- TAMBAHKAN INI
            from urllib.parse import quote
            full_url = f"{url}?{param}={quote(p)}"
            r = requests.get(full_url, timeout=5)

            status = r.status_code
            length = len(r.text)

            # ML Prediction
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
            results.append({
                "payload": p,
                "status": "error",
                "attack": "Unknown",
                "vulnerability": "Request Failed",
                "length": 0,
                "ml_prediction": -1,
                "confidence": 0
            })

    return jsonify(results)  # 🔴 LANGSUNG TAMPIL DI DASHBOARD!

from urllib.parse import urlparse, parse_qs

@app.route("/detect-params", methods=["POST"])
def detect_params():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "URL kosong"}), 400

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    detected = list(params.keys()) if params else []

    # 🔴 FIX: Kasus khusus untuk login.aspx
    if "login.aspx" in url.lower():
        # Tambahkan parameter yang sebenarnya ada
        if "ReturnUrl" in parsed.query:
            detected = ["ReturnUrl"]  # Prioritaskan ReturnUrl
        else:
            # Rekomendasi untuk login page
            detected = ["ReturnUrl", "username", "password"]

    # Jika tidak ada parameter, beri rekomendasi berdasarkan URL
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

    return jsonify({
        "params": detected,
        "count": len(detected)
    })


# ==============================
# ROOT
# ==============================
@app.route("/")
def home():
    return "🔥 Backend jalan! Model sudah diupdate dengan 5 kelas (SQL Injection, XSS, Path Traversal, Command Injection, Normal)"

# ==============================
# ENDPOINT BARU: PARSE FILE BURP
# ==============================
@app.route("/parse-burp", methods=["POST"])
def parse_burp():
    """Terima file Burp (XML/CSV), return CSV siap upload"""
    
    file = request.files.get("file")
    
    if not file:
        return jsonify({"error": "No file"}), 400
    
    filename = file.filename.lower()
    results = []
    position = 0
    
    # ==================== HANDLE XML ====================
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
                from urllib.parse import unquote
                payload = unquote(url.split("?q=")[-1])
            
            results.append({
                "position": position,
                "payload": payload,
                "status": status,
                "length": length
            })
    
    # ==================== HANDLE CSV ====================
    else:
        content = file.read().decode('utf-8')
        lines = content.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith('Request') or line.startswith('position'):
                continue
            
            position += 1
            
            # Split by tab
            parts = line.split('\t')
            
            if len(parts) >= 5:
                payload = parts[1].strip()
                status = parts[2].strip()
                length = parts[4].strip()
                
                # Clean payload
                if ',' in payload:
                    payload = payload.split(',')[0]
                payload = payload.strip('"').strip("'")
                
                results.append({
                    "position": position,
                    "payload": payload,
                    "status": status,
                    "length": length
                })
    
    if not results:
        return jsonify({"error": "No data extracted"}), 400
    
    # Generate CSV output
    import csv
    import io
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['position', 'payload', 'status', 'length'])
    
    for r in results:
        writer.writerow([r['position'], r['payload'], r['status'], r['length']])
    
    # Return sebagai file download
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=parsed_output.csv"}
    )

# ==============================
# RUN
# ==============================
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)