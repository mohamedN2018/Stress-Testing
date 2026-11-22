"""Stand-in for the k6 binary (k6 is not installed on the build machine).

It accepts the same command line the adapter produces
(``run --quiet --out json=<file> <script.js>``), reads the generated script's
configuration, sends real HTTP requests and writes k6-style JSON "Point" lines.
It verifies the adapter's plumbing; it does not prove compatibility with a real
k6 release.
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.error
import urllib.request


def main(argv: list[str]) -> int:
    assert argv[0] == "run", argv
    out = next(a.split("=", 1)[1] for a in argv if a.startswith("json="))
    script = open(argv[-1], encoding="utf-8").read()
    cfg = json.loads(re.search(r"const cfg = (\{.*?\});\n", script, re.S).group(1))
    assert "maxRedirects: 0" in script and "rps: cfg.rps" in script
    total = sum(float(s["duration"].rstrip("s")) for s in cfg["stages"])
    interval = max(1.0 / cfg["rps"], cfg["interval"])
    deadline = time.monotonic() + total
    i = 0
    with open(out, "a", buffering=1, encoding="utf-8") as handle:
        def point(metric: str, value: float, tags: dict | None = None) -> None:
            handle.write(json.dumps({"type": "Point", "metric": metric,
                                     "data": {"time": "t", "value": value, "tags": tags or {}}}) + "\n")

        handle.write(json.dumps({"type": "Metric", "metric": "http_req_duration", "data": {}}) + "\n")
        while time.monotonic() < deadline:
            point("vus", cfg["stages"][0]["target"])
            url = cfg["baseUrl"] + cfg["paths"][i % len(cfg["paths"])]
            started = time.perf_counter()
            status, error = 0, ""
            try:
                with urllib.request.urlopen(urllib.request.Request(url, method=cfg["method"]), timeout=5) as r:
                    status = r.status
            except urllib.error.HTTPError as exc:
                status = exc.code
            except OSError as exc:
                error = type(exc).__name__
            tags = {"status": str(status)}
            if error:
                tags["error"] = error
            point("http_req_duration", (time.perf_counter() - started) * 1000, tags)
            i += 1
            time.sleep(interval)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
