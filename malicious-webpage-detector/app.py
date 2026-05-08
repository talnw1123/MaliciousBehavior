"""
Malicious Webpage Behavior Detection System
Flask Application Entry Point
"""

import json
from flask import Flask, render_template, request, jsonify, send_file
from scraper import WebScraper
from detectors import IframeDetector, JSDetector, ScriptDetector, LinkDetector, SafeBrowsingDetector, RiskScorer
from database import ScanDatabase
from config import FLASK_HOST, FLASK_PORT, FLASK_DEBUG

app = Flask(__name__)
scraper = WebScraper()
db = ScanDatabase()


@app.route("/")
def index():
    """Render the main analysis page."""
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Analyze a URL for malicious behavior.

    Expects JSON body: {"url": "https://example.com"}
    Returns JSON with risk assessment results.
    """
    data = request.get_json()

    if not data or "url" not in data:
        return jsonify({"error": "URL is required"}), 400

    url = data["url"].strip()

    if not url:
        return jsonify({"error": "URL cannot be empty"}), 400

    # Fetch the webpage
    soup, raw_html, status_or_error = scraper.fetch_page(url)

    # Get base domain
    base_domain = scraper.get_base_domain(url)

    # Run all detectors
    all_findings = []

    # 5. Google Safe Browsing API Check (Run this first as it works without HTML)
    safe_browsing = SafeBrowsingDetector(url, soup)
    sb_findings = safe_browsing.detect()
    all_findings.extend(sb_findings)

    if soup is None:
        # If we couldn't fetch the page AND Safe Browsing didn't find anything, return the error
        if not sb_findings:
            return jsonify({
                "error": f"Failed to fetch page: {status_or_error}",
                "url": url,
            }), 400
        # Otherwise, we continue to return the Safe Browsing findings!
    else:
        # Only run HTML-based detectors if we successfully fetched the page
        # 1. Iframe detection
        iframe_detector = IframeDetector(soup, base_domain)
        all_findings.extend(iframe_detector.detect())

        # 2. JavaScript obfuscation detection
        js_detector = JSDetector(soup, raw_html)
        all_findings.extend(js_detector.detect())

        # 3. External script detection
        script_detector = ScriptDetector(soup, base_domain)
        all_findings.extend(script_detector.detect())

        # 4. Dangerous link detection
        link_detector = LinkDetector(soup, raw_html)
        all_findings.extend(link_detector.detect())

    # Calculate risk score
    risk_scorer = RiskScorer()
    risk_scorer.add_findings(all_findings)
    results = risk_scorer.get_results()

    # Add URL to results
    results["url"] = url
    results["status_code"] = status_or_error

    # Save to database
    db.save_scan(url, results["risk_level"], results["risk_score"], all_findings)

    return jsonify(results)


@app.route("/history", methods=["GET"])
def get_history():
    """Get scan history."""
    limit = request.args.get("limit", 50, type=int)
    history = db.get_history(limit)
    return jsonify(history)


@app.route("/history/<int:scan_id>", methods=["GET"])
def get_scan_detail(scan_id):
    """Get detailed scan result by ID."""
    detail = db.get_scan_detail(scan_id)
    if detail:
        # Re-generate recommendations since they are not stored in the DB
        if "recommendations" not in detail:
            risk_scorer = RiskScorer()
            risk_scorer.add_findings(detail.get("findings", []))
            risk_scorer.risk_level = detail.get("risk_level", "LOW")
            detail["recommendations"] = risk_scorer._generate_recommendations()
        return jsonify(detail)
    return jsonify({"error": "Scan not found"}), 404


@app.route("/history/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    """Delete a scan record."""
    db.delete_scan(scan_id)
    return jsonify({"message": "Scan deleted"})


@app.route("/history/clear", methods=["POST"])
def clear_history():
    """Clear all scan history."""
    db.clear_history()
    return jsonify({"message": "History cleared"})


@app.route("/export/<int:scan_id>", methods=["GET"])
def export_scan(scan_id):
    """Export scan result as JSON file."""
    detail = db.get_scan_detail(scan_id)
    if not detail:
        return jsonify({"error": "Scan not found"}), 404

    # Create export data
    export_data = {
        "scan_id": scan_id,
        "url": detail["url"],
        "risk_level": detail["risk_level"],
        "risk_score": detail["risk_score"],
        "scanned_at": detail["scanned_at"],
        "findings": detail["findings"],
    }

    # Save to temp file
    filename = f"scan_{scan_id}.json"
    with open(filename, "w") as f:
        json.dump(export_data, f, indent=2)

    return send_file(filename, as_attachment=True)


if __name__ == "__main__":
    print(f"Starting Malicious Webpage Behavior Detection System...")
    print(f"Server running at http://{FLASK_HOST}:{FLASK_PORT}")
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
