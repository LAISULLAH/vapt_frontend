from flask import Flask, Response, request, jsonify
import subprocess
import time
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Allow cross-origin requests from React

# ---------------- Real-Time Command Stream ----------------
def run_command_stream(cmd, prefix=""):
    """
    Run a CLI command and yield output line by line in real-time for SSE.
    """
    try:
        process = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        for line in iter(process.stdout.readline, ''):
            if line:
                yield f"data: {prefix}{line.strip()}\n\n"
        process.stdout.close()
        process.wait()
    except Exception as e:
        yield f"data: [ERROR] Exception: {str(e)}\n\n"

# ---------------- Parsing Helpers ----------------
def parse_nmap_line(line):
    if "open" in line:
        return f"[NMAP] {line} --> Possible attack: service enumeration / brute force / exploit"
    elif "filtered" in line:
        return f"[NMAP] {line} --> Firewall / filtering detected"
    return f"[NMAP] {line}"

def parse_nikto_line(line):
    if "OSVDB" in line or "Server" in line:
        return f"[NIKTO] {line} --> Possible web vulnerabilities / misconfigurations"
    return f"[NIKTO] {line}"

def parse_nuclei_line(line):
    if line.strip():
        return f"[NUCLEI] {line} --> CVE / misconfiguration found"
    return None

# ---------------- SSE Scan Route ----------------
@app.route("/run_all_scans")
def run_all_scans():
    target = request.args.get("target")
    if not target:
        return "No target provided", 400

    def generate():
        yield f"data: [*] Starting full vulnerability scan on {target} at {time.ctime()}\n\n"

        # ----------- Nmap Scan -----------
        yield f"data: [*] Running Nmap scan...\n\n"
        for line in run_command_stream(f"nmap -sV {target}"):
            yield f"data: {parse_nmap_line(line)}\n\n"
            time.sleep(0.05)

        # ----------- Nikto Scan -----------
        yield f"data: [*] Running Nikto scan...\n\n"
        for line in run_command_stream(f"nikto -h {target}"):
            yield f"data: {parse_nikto_line(line)}\n\n"
            time.sleep(0.05)

        # ----------- Nuclei Scan -----------
        yield f"data: [*] Running Nuclei scan...\n\n"
        for line in run_command_stream(f"nuclei -u {target}"):
            parsed_line = parse_nuclei_line(line)
            if parsed_line:
                yield f"data: {parsed_line}\n\n"
            time.sleep(0.05)

        yield f"data: [*] Scan completed on {target} at {time.ctime()}\n\n"

    return Response(generate(), mimetype="text/event-stream")



@app.route("/chat", methods=["POST"])
def chat():
    data = request.json
    message = data.get("message", "")
    target = data.get("target", "Unknown")
    response = f"[AI] Received message about {target}: {message}\nHint: Check scan output for attack vectors"
    return jsonify({"response": response})

# ------------------ Run Flask ------------------

if __name__ == "__main__":
    # Run on port 5001 to avoid conflicts
    app.run(debug=True, port=5001)



# # backend_full.py
# from flask import Flask, request, jsonify
# from flask_cors import CORS
# import subprocess
# import time
# import shutil

# app = Flask(__name__)
# CORS(app)  # Allow frontend fetch

# # -----------------------
# # Helper functions
# # -----------------------
# def cmd_exists(cmd):
#     return shutil.which(cmd) is not None

# def run_cmd(cmd_list, timeout=60):
#     """Run a command and return output"""
#     try:
#         result = subprocess.run(cmd_list, capture_output=True, text=True, timeout=timeout)
#         return result.stdout.strip()
#     except subprocess.TimeoutExpired:
#         return "[ERROR] Command timed out"
#     except Exception as e:
#         return f"[ERROR] {str(e)}"

# # Store latest scan results per target
# scan_cache = {}

# # -----------------------
# # Run all 5 tools
# # -----------------------
# @app.route("/run_all_scans", methods=["POST"])
# def run_all_scans():
#     data = request.json
#     target = data.get("target")
#     if not target:
#         return jsonify({"result": "[ERROR] No target provided"}), 400

#     started = time.strftime("%Y-%m-%d %H:%M:%S")
#     scans = {"_meta": {"target": target, "started": started}}

#     # ---- TOOL 1: Nmap ----
#     if cmd_exists("nmap"):
#         scans["nmap"] = run_cmd(["nmap", "-sV", "-Pn", target], timeout=90)
#     else:
#         scans["nmap"] = "[NMAP] not installed"

#     # ---- TOOL 2: Nikto ----
#     if cmd_exists("nikto"):
#         scans["nikto"] = run_cmd(["nikto", "-h", f"https://{target}", "-ssl"], timeout=180)
#         if "ERROR" in scans["nikto"] and "not found" not in scans["nikto"]:
#             scans["nikto_fallback"] = run_cmd(["nikto", "-h", f"http://{target}"], timeout=180)
#     else:
#         scans["nikto"] = "[NIKTO] not installed"

#     # ---- TOOL 3: Nuclei ----
#     if cmd_exists("nuclei"):
#         scans["nuclei"] = run_cmd(["nuclei", "-u", f"https://{target}", "-silent"], timeout=180)
#     else:
#         scans["nuclei"] = "[NUCLEI] not installed"

#     # ---- TOOL 4: Custom Tool Placeholder ----
#     scans["custom_tool_1"] = f"[CUSTOM] Tool 4 executed on {target}"

#     # ---- TOOL 5: Custom Tool Placeholder ----
#     scans["custom_tool_2"] = f"[CUSTOM] Tool 5 executed on {target}"

#     scans["_meta"]["finished"] = time.strftime("%Y-%m-%d %H:%M:%S")

#     # Save to cache for chat usage
#     scan_cache[target] = scans

#     # Build combined text output for frontend
#     combined_lines = []
#     for k, v in scans.items():
#         if k.startswith("_"): continue
#         combined_lines.append(f"--- {k.upper()} ---")
#         combined_lines.append(v if isinstance(v, str) else str(v))
#         combined_lines.append("")
#     combined_text = "\n".join(combined_lines)

#     return jsonify({"result": combined_text, "scans": scans})

# # -----------------------
# # Chat endpoint (uses latest scan results)
# # -----------------------
# @app.route("/chat", methods=["POST"])
# def chat():
#     data = request.json
#     msg = data.get("message")
#     target = data.get("target")

#     if not msg or not target:
#         return jsonify({"response": "[ERROR] Missing message or target"}), 400

#     scans = scan_cache.get(target, {})

#     # Very simple AI response logic based on keywords
#     m = msg.lower()
#     if "port" in m:
#         nmap_output = scans.get("nmap", "")
#         response_text = f"[AI] Ports info for {target}:\n{nmap_output[:500]}..."  # truncate for safety
#     elif "vuln" in m or "vulnerability" in m:
#         nuclei_output = scans.get("nuclei", "")
#         response_text = f"[AI] Vulnerability scan for {target}:\n{nuclei_output[:500]}..."
#     elif "subdomain" in m:
#         subdomains = scans.get("custom_tool_1", "")
#         response_text = f"[AI] Subdomains found for {target}:\n{subdomains}"
#     elif "osint" in m:
#         osint_info = scans.get("custom_tool_2", "")
#         response_text = f"[AI] OSINT info for {target}:\n{osint_info}"
#     else:
#         response_text = f"[AI] Sorry, I only answer questions about Port Scan, Vulnerabilities, Subdomains, or OSINT for {target}."

#     return jsonify({"response": response_text})

# # -----------------------
# # Run server
# # -----------------------
# if __name__ == "__main__":
#     print("Starting Backend Full API on http://127.0.0.1:5000")
#     app.run(port=5000, debug=True)
