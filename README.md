<div align="center">

# 🐘 PHP Nov-2026 Critical Flaws Checker

**Is this server's PHP patched against the 19 November 2026 security releases, including phpAfterShell?**

![python](https://img.shields.io/badge/python-3.6%2B-3776AB?logo=python&logoColor=white)
![deps](https://img.shields.io/badge/dependencies-none-brightgreen)
![mode](https://img.shields.io/badge/mode-read--only-blue)
![license](https://img.shields.io/badge/license-MIT-lightgrey)
![platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-informational)

Built by **Astra** ·

</div>

---

## 📚 Contents

[🎯 What it checks](#-what-it-checks) · [🚀 Quick start](#-quick-start) · [🧪 Modes](#-modes) · [🧮 Verdicts](#-verdicts) · [📦 Fixed releases](#-fixed-releases) · [🩹 How to fix](#-how-to-fix) · [🖨️ Example output](#️-example-output) · [🤖 CI use](#-ci-use) · [⚠️ Limits](#️-limits) · [🛡️ Safety](#️-safety)

## 🎯 What it checks

PHP shipped fixes for **seven critical flaws** on 19 Nov 2026. This tool tells you, per PHP binary, whether you are covered.

| CVE | Type | Notes |
|---|---|---|
| `CVE-2026-129496` | Use-after-free | Unauthenticated remote attacker can crash workers or run code |
| `CVE-2026-129289` | Inconsistent HTTP request interpretation | Needs persistent backend connections and a `php://input` path |
| `CVE-2026-126714` | **phpAfterShell**: session write race | Default file-based sessions; upload progress is the trigger |
| `CVE-2026-129474` | Use-after-free | **PHP 8.5 only** |
| `CVE-2026-129182` | Use-after-free | **PHP 8.5 only** |
| `CVE-2026-129481` | Use-after-free in session cleanup | Not PHP 8.2 |
| `CVE-2026-115560` | Input validation in session upload progress | Serializer switched at runtime |

For every PHP it finds the script:

- 🔢 compares the version with the **fixed release** of its branch
- 📜 reads the **distro package changelog** (rpm / dpkg) for the CVE IDs, because distros often backport fixes without changing the version number
- 🗝️ shows whether **file-based sessions** and **`session.upload_progress.enabled`** are on (the phpAfterShell conditions)
- 🧾 lists which CVEs apply to that branch

## 🚀 Quick start

```bash
git clone https://github.com/3tternp/php-nov2026-check.git
cd php-nov2026-check
python3 php_nov2026_check.py
```

No `pip install` needed. Run it **on the server** (or inside the container) for a reliable answer.

## 🧪 Modes

| Mode | Command | Reliability |
|---|---|---|
| 🖥️ **Local** (default) | `python3 php_nov2026_check.py` | ✅ High. Finds `php`, `php-fpm`, `php-cgi`, `lsphp`, Remi, Plesk, XAMPP, WAMP |
| 🎯 Specific binary | `python3 php_nov2026_check.py --php /opt/app/bin/php` | ✅ High. Use inside containers |
| 🌐 **Remote hint** | `python3 php_nov2026_check.py --url https://app.example.com -k` | ⚠️ Low. Reads `X-Powered-By`; most servers hide it |
| 📄 Remote list | `python3 php_nov2026_check.py -f urls.txt` | ⚠️ Low, same limits |
| 💾 Save results | add `--json out.json` | |

Docker example: `docker exec my-app python3 /tmp/php_nov2026_check.py` (copy the script in first), or `docker exec my-app php -v`.

## 🧮 Verdicts

| Verdict | Meaning |
|---|---|
| 🔴 **VULNERABLE** | Below the fixed release and no distro changelog naming the CVEs, or an end-of-life branch (8.1 and older) |
| 🟢 **FIXED** | At or above the fixed release, **or** the distro changelog names the CVE IDs |
| 🟡 **VERIFY / UNKNOWN** | Remote header shows an old version (backports invisible), or no version is exposed |

**Exit codes:** `0` all fixed or none found · `1` at least one vulnerable · `2` only verify/unknown · `3` usage error

## 📦 Fixed releases

| Branch | Fixed in |
|---|---|
| 8.5 | **8.5.13** |
| 8.4 | **8.4.28** |
| 8.3 | **8.3.37** |
| 8.2 | **8.2.36** |
| 8.6 | fix included |
| 8.1 and older | ❌ end of life, **no official fix**: migrate |

## 🩹 How to fix

1. ⬆️ Upgrade to a fixed release, or to a distro package whose changelog names the CVE IDs.
2. 🔁 **Restart** PHP-FPM, Apache (mod_php) or LSAPI workers, and rebuild and redeploy container images.
3. ✅ Confirm the version on the **serving SAPI**, not only the CLI (`php-fpm -v`, a protected `phpinfo()`).
4. 🔧 Fixed releases turn **session upload progress off by default**. Re-enable it only if the application needs it.
5. 🧱 Until patched, if the app does not use upload progress, set `session.upload_progress.enabled = 0` (and `php_admin_flag[session.upload_progress.enabled] = off` in the FPM pool). This is **interim only**.

## 🖨️ Example output

```text
PHP 19-Nov-2026 check  |  Vairav VTS-SA-2026-1120  |  fixed: 8.5.13 / 8.4.28 / 8.3.37 / 8.2.36 / 8.6.0

[VULNERABLE] /usr/bin/php8.3  (PHP 8.3.6)
    why: version 8.3.6 is below fixed 8.3.37
    package: php8.3-cli
    applicable: CVE-2026-129496, CVE-2026-129289, CVE-2026-126714, CVE-2026-129481, CVE-2026-115560
    note: file-based sessions in use (phpAfterShell scope)
    note: session.upload_progress.enabled is ON (trigger feature)

[FIXED] /opt/php84/bin/php  (PHP 8.4.28)
    why: 8.4.28 is at or above the fixed release 8.4.28

Summary: 2 checked, 1 vulnerable, 1 fixed, 0 unknown/verify
```

## 🤖 CI use

```yaml
- name: PHP patch gate
  run: python3 php_nov2026_check.py --json php-check.json   # fails the job on exit code 1
```

## ⚠️ Limits

- 🕵️ The ini values shown come from the **CLI** configuration, which can differ from FPM/Apache. Check the pool or vhost config too.
- 🧩 Per-branch CVE applicability follows the public reporting at release time; confirm details in the php-src advisories.
- 📜 A distro build can be fixed with an old version number. The changelog test covers `rpm` and `dpkg`; other packagers (Alpine, Nix, source builds) show as the upstream version.
- 🌍 Remote mode cannot see backports and often sees nothing.

## 🛡️ Safety

Read-only. It runs `php -v`, one `php -r` ini query, and package-manager queries. No exploit traffic, no file changes. Use only on systems you are authorised to assess.

## 📜 License

MIT, see [LICENSE](LICENSE). Provided as is; verify results before acting.
