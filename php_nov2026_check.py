#!/usr/bin/env python3
"""
php_nov2026_check.py - read-only check for the PHP security releases of 19 Nov 2026
(7 critical flaws incl. phpAfterShell CVE-2026-126714).  Vairav advisories
VTS-SA-2026-1120-PHP-NOV-RCE and VTS-SA-2026-1120-PHPAFTERSHELL.

Modes
  local   (default)  find PHP binaries on this host, compare version, check distro
                     changelog for the CVE IDs, show session/upload-progress settings.
  remote  --url URL  read the X-Powered-By header of a web server. Many servers hide it,
                     so the result is often UNKNOWN. A header is a hint, not proof.

Exit codes: 0 all fixed / none found, 1 at least one VULNERABLE, 2 only UNKNOWN/VERIFY, 3 usage error
Python 3.6+, standard library only. Makes no changes and sends no exploit traffic.
"""
import argparse, glob, gzip, json, os, re, shutil, ssl, subprocess, sys, urllib.request

ADVISORY = "VTS-SA-2026-1120"
FIXED = {(8, 2): (8, 2, 36), (8, 3): (8, 3, 37), (8, 4): (8, 4, 28), (8, 5): (8, 5, 13)}
CVES = ["CVE-2026-129496", "CVE-2026-129289", "CVE-2026-126714", "CVE-2026-129474",
        "CVE-2026-129481", "CVE-2026-129182", "CVE-2026-115560"]
BRANCH_NA = {  # CVEs that do not apply to a branch (per THN)
    (8, 2): {"CVE-2026-129481", "CVE-2026-129474", "CVE-2026-129182"},
    (8, 3): {"CVE-2026-129474", "CVE-2026-129182"},
    (8, 4): {"CVE-2026-129474", "CVE-2026-129182"},
}
USE_COLOR = sys.stdout.isatty()
def c(t, code): return "\033[%sm%s\033[0m" % (code, t) if USE_COLOR else t
ICON = {"VULNERABLE": c("[VULNERABLE]", "1;31"), "FIXED": c("[FIXED]", "1;32"),
        "VERIFY": c("[VERIFY]", "1;33"), "UNKNOWN": c("[UNKNOWN]", "1;33")}

def parse_ver(s):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", s or "")
    return tuple(int(x) for x in m.groups()) if m else None

def classify(ver, changelog_hit):
    """return (status, reason, applicable_cves)"""
    maj, mnr = ver[0], ver[1]
    if (maj, mnr) in FIXED:
        fx = FIXED[(maj, mnr)]
        na = BRANCH_NA.get((maj, mnr), set())
        cves = [x for x in CVES if x not in na]
        if ver >= fx:
            return "FIXED", "%s is at or above the fixed release %s" % (".".join(map(str, ver)), ".".join(map(str, fx))), []
        if changelog_hit:
            return "FIXED", "distribution changelog names the CVE IDs (backported fix); upstream %s is below %s" % (".".join(map(str, ver)), ".".join(map(str, fx))), []
        return "VULNERABLE", "version %s is below fixed %s" % (".".join(map(str, ver)), ".".join(map(str, fx))), cves
    if (maj, mnr) >= (8, 6):
        return "FIXED", "PHP 8.6 and later: fix included / not listed as affected", []
    if (maj, mnr) < (8, 2):
        if changelog_hit:
            return "FIXED", "distribution changelog names the CVE IDs", []
        return "VULNERABLE", "PHP %d.%d is end of life; no official fix. Migrate to 8.2+ fixed release" % (maj, mnr), [x for x in CVES]
    return "UNKNOWN", "unrecognised branch", []

def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, universal_newlines=True)
        return r.stdout or ""
    except Exception:
        return ""

def find_binaries():
    cands = set()
    for n in ("php", "php-fpm", "php-cgi", "php-fpm8", "lsphp"):
        p = shutil.which(n)
        if p: cands.add(os.path.realpath(p))
    pats = ["/usr/bin/php*", "/usr/sbin/php-fpm*", "/usr/local/bin/php*", "/usr/local/sbin/php-fpm*",
            "/opt/remi/php*/root/usr/bin/php", "/opt/remi/php*/root/usr/sbin/php-fpm",
            "/opt/plesk/php/*/bin/php", "/usr/local/lsws/lsphp*/bin/lsphp", "/Applications/XAMPP/xamppfiles/bin/php",
            "C:\\xampp\\php\\php.exe", "C:\\php\\php.exe", "C:\\wamp64\\bin\\php\\*\\php.exe",
            "C:\\Program Files\\PHP\\*\\php.exe", "C:\\inetpub\\php\\php.exe"]
    for p in pats:
        for f in glob.glob(p):
            if os.path.isfile(f) and re.match(r"^(php|php-fpm|php-cgi|lsphp)[0-9.\-]*(\.exe)?$", os.path.basename(f), re.I):
                cands.add(os.path.realpath(f))
    return sorted(cands)

def changelog_has_cve(path):
    """True if the owning distro package changelog names any of the CVE IDs."""
    if os.name == "nt": return False, None
    pkg = None
    if shutil.which("rpm"):
        o = run(["rpm", "-qf", path]).strip()
        if o and "not owned" not in o:
            pkg = o.splitlines()[0]
            cl = run(["rpm", "-q", "--changelog", pkg], 30)
            return any(x in cl for x in CVES), pkg
    if shutil.which("dpkg"):
        o = run(["dpkg", "-S", path])
        m = re.match(r"([^:,\s]+)", o)
        if m and "no path found" not in o:
            pkg = m.group(1)
            for f in ("/usr/share/doc/%s/changelog.Debian.gz" % pkg, "/usr/share/doc/%s/changelog.gz" % pkg):
                if os.path.exists(f):
                    try:
                        txt = gzip.open(f, "rt", errors="ignore").read()
                        return any(x in txt for x in CVES), pkg
                    except Exception:
                        pass
            return False, pkg
    return False, pkg

def ini_values(path):
    out = {}
    if os.path.basename(path).startswith(("php-fpm", "lsphp")) and "cgi" not in path:
        return out
    code = 'foreach(array("session.save_handler","session.upload_progress.enabled","session.serialize_handler") as $k) echo $k."=".ini_get($k)."\\n";'
    for ln in run([path, "-r", code]).splitlines():
        if "=" in ln and ln.startswith("session."):
            k, v = ln.split("=", 1); out[k] = v.strip()
    return out

def local_scan():
    res = []
    bins = find_binaries()
    for b in bins:
        o = run([b, "-v"])
        m = re.search(r"PHP\s+(\d+\.\d+\.\d+)", o)
        if not m: continue
        ver = parse_ver(m.group(1))
        hit, pkg = changelog_has_cve(b)
        st, why, cves = classify(ver, hit)
        ini = ini_values(b)
        notes = []
        if st != "FIXED":
            if ini.get("session.save_handler") == "files":
                notes.append("file-based sessions in use (phpAfterShell scope)")
            if ini.get("session.upload_progress.enabled") in ("1", "On", "on", "true"):
                notes.append("session.upload_progress.enabled is ON (trigger feature)")
        res.append({"target": b, "version": ".".join(map(str, ver)), "package": pkg, "status": st,
                    "reason": why, "applicable_cves": cves, "ini": ini, "notes": notes})
    return res, bins

def remote_scan(url, insecure):
    if "://" not in url: url = "https://" + url
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Vairav-php-check/1.0"})
        r = urllib.request.urlopen(req, timeout=10, context=ctx)
        hdr = r.headers
    except urllib.error.HTTPError as e:
        hdr = e.headers
    except Exception as e:
        return {"target": url, "status": "UNKNOWN", "reason": "request failed: %s" % e, "applicable_cves": [], "notes": []}
    xp = hdr.get("X-Powered-By", "")
    m = re.search(r"PHP/(\d+\.\d+\.\d+)", xp or "")
    if not m:
        return {"target": url, "status": "UNKNOWN", "reason": "no PHP version in headers (X-Powered-By hidden). Run local mode on the server",
                "applicable_cves": [], "notes": ["Server: %s" % hdr.get("Server", "n/a")]}
    ver = parse_ver(m.group(1))
    st, why, cves = classify(ver, False)
    notes = ["header only: a distribution may have backported the fix; confirm on the host"]
    if st == "VULNERABLE": st = "VERIFY"; why += " (header value; cannot see backports)"
    return {"target": url, "version": ".".join(map(str, ver)), "status": st, "reason": why, "applicable_cves": cves, "notes": notes}

def main():
    ap = argparse.ArgumentParser(description="Check PHP against the 19 Nov 2026 security releases (read-only).")
    ap.add_argument("--url", action="append", help="remote mode: URL or host to read X-Powered-By from (repeatable)")
    ap.add_argument("-f", "--file", help="remote mode: file with one URL/host per line")
    ap.add_argument("-k", "--insecure", action="store_true", help="skip TLS verification (remote mode)")
    ap.add_argument("--php", action="append", help="local mode: extra PHP binary path to test")
    ap.add_argument("--json", metavar="FILE", help="write JSON results")
    a = ap.parse_args()
    results = []
    urls = list(a.url or [])
    if a.file:
        urls += [l.strip() for l in open(a.file) if l.strip() and not l.startswith("#")]
    print("\nPHP 19-Nov-2026 check  |  Vairav %s  |  fixed: 8.5.13 / 8.4.28 / 8.3.37 / 8.2.36 / 8.6.0\n" % ADVISORY)
    if urls:
        for u in urls: results.append(remote_scan(u, a.insecure))
    else:
        results, bins = local_scan()
        if a.php:
            for b in a.php:
                o = run([b, "-v"]); m = re.search(r"PHP\s+(\d+\.\d+\.\d+)", o)
                if m:
                    ver = parse_ver(m.group(1)); st, why, cves = classify(ver, False)
                    results.append({"target": b, "version": m.group(1), "package": None, "status": st, "reason": why,
                                    "applicable_cves": cves, "ini": {}, "notes": []})
        if not results:
            print("No PHP binary found on this host. If PHP is in a container, run this inside it (docker exec ... ) or use --php /path/to/php.")
            sys.exit(0)
    for r in results:
        print("%s %s  (PHP %s)" % (ICON.get(r["status"], r["status"]), r["target"], r.get("version", "?")))
        print("    why: %s" % r["reason"])
        if r.get("package"): print("    package: %s" % r["package"])
        if r["applicable_cves"]: print("    applicable: %s" % ", ".join(r["applicable_cves"]))
        for n in r.get("notes", []): print("    note: %s" % n)
        print()
    vuln = sum(1 for r in results if r["status"] == "VULNERABLE")
    print("Summary: %d checked, %d vulnerable, %d fixed, %d unknown/verify" % (
        len(results), vuln, sum(1 for r in results if r["status"] == "FIXED"),
        sum(1 for r in results if r["status"] in ("UNKNOWN", "VERIFY"))))
    print("Reminder: patch, then RESTART php-fpm / Apache / LSAPI workers; confirm the version on the serving SAPI, not only the CLI.")
    if a.json:
        json.dump(results, open(a.json, "w"), indent=2)
    sys.exit(1 if vuln else (2 if any(r["status"] in ("UNKNOWN", "VERIFY") for r in results) else 0))

if __name__ == "__main__":
    main()
