#!/usr/bin/env python3
import json
import gzip
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

ROOT = Path(__file__).parent
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0?"
CACHE = ROOT / "monthly-cache.json"


def monthly_counts():
    if CACHE.is_file():
        return json.loads(CACHE.read_text())
    # Use NVD's annual compressed feeds instead of making thousands of API requests.
    now = datetime.now(timezone.utc)
    first_year = 1999
    result = {f"{year}-{month:02d}": 0 for year in range(first_year, now.year + 1)
              for month in range(1, 13)}
    for year in range(2002, now.year + 1):
        url = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
        request = urllib.request.Request(url, headers={"User-Agent": "pwnclock/0.1"})
        with urllib.request.urlopen(request, timeout=120) as response:
            payload = json.loads(gzip.decompress(response.read()))
        for item in payload.get("vulnerabilities", []):
            date = item.get("cve", {}).get("published", "")[:7]
            if date in result:
                result[date] += 1
    # Drop the current month: it is still open, so its bar would look like a fall.
    current_month = now.strftime("%Y-%m")
    data = [{"month": month, "count": count} for month, count in result.items()
            if month < current_month]
    CACHE.write_text(json.dumps(data))
    return data


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/monthly":
            try:
                body = json.dumps({"source": "NVD", "data": monthly_counts()}).encode()
                self.send_response(200)
            except Exception as error:
                body = json.dumps({"error": str(error)}).encode()
                self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "public, max-age=3600")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        path = "/index.html" if self.path == "/" else self.path
        file = ROOT / path.lstrip("/")
        if file.is_file():
            body = file.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)


if __name__ == "__main__":
    print("pwnclock listening on http://0.0.0.0:9494")

    def warm_cache():
        try:
            monthly_counts()
            print("historical cache ready")
        except Exception as error:
            print("cache build failed:", error)

    if not CACHE.is_file():
        Thread(target=warm_cache, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 9494), Handler).serve_forever()
