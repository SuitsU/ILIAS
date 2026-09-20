# ILIAS 7 Security Findings (2026-09-20)

Validated MEDIUM/HIGH/CRITICAL issues from an injection/SSRF/RCE/secrets hunt.
Excluded already-known: WAC path traversal, WAC token not bound to path, SOAP saveQuestion IDOR.

## CRITICAL

### 1. Predictable password-assistance token enables account takeover
- **Location:** `include/inc.pwassist_session_handler.php`, `Services/Init/classes/class.ilPasswordAssistanceGUI.php`
- **Status:** Remediated in this branch (`random_bytes` token; removed session_start/destroy dance)

**Description:** `db_pwassist_create_id()` returned `ilSession::_duplicate(session_id())`, which is `md5(session_id())` (iterated only on collision). The requester’s session cookie is that `session_id()`, so the password-reset `key` was computable by the attacker who submitted the assistance form. The always-true branch (`|| true // wtf`) forced a new token on every request.

**Impact:** Unauthenticated account takeover of any local-auth user whose username and email the attacker knows (password assistance must be enabled).

**Attack path:**
1. Attacker opens `pwassist.php` and notes session cookie value `S`.
2. Attacker submits victim username + matching email.
3. Server stores `pwassist_id = md5(S)` bound to the victim.
4. Attacker opens `pwassist.php?key=<md5(S)>`, enters victim username and a new password.
5. Victim account password is replaced.

**Evidence:** `include/inc.pwassist_session_handler.php:67-71`, `Services/Authentication/classes/class.ilSession.php:306-329`, `Services/Init/classes/class.ilPasswordAssistanceGUI.php:293-311`, `451-496`

**Remediation:** Use `bin2hex(random_bytes(32))` (applied). Do not derive reset tokens from session IDs.

---

### 2. Webroot phpMyAdmin symlink
- **Location:** `/phpmyadmin` → `/var/www/html/phpmyadmin/` (tracked in git)
- **Severity:** CRITICAL (deployment)

**Description:** A git-tracked symlink exposes phpMyAdmin under the ILIAS document root whenever that target exists on the host.

**Impact:** Database administration UI reachable via the LMS vhost; often leads to full DB compromise if phpMyAdmin auth is weak/default or shared with other apps.

**Attack path:** Request `https://<ilias-host>/phpmyadmin/` on a host where `/var/www/html/phpmyadmin` is installed.

**Evidence:** tracked path `phpmyadmin` (symlink)

**Remediation:** Remove the symlink from the webroot and repository; never publish phpMyAdmin on the LMS vhost.

---

## HIGH

### 3. Zip slip via `ZipArchive::extractTo` (no path validation)
- **Locations:**
  - `Modules/CmiXapi/classes/class.ilCmiXapiContentUploadImporter.php:271-277`
  - `Modules/ScormAicc/classes/class.ilObjSAHSLearningModuleGUI.php:466-469`
  - `Modules/OrgUnit/classes/SimpleImport/class.ilOrgUnitSimpleImportGUI.php` (extractTo)

**Description:** Uploaded ZIPs are extracted with `ZipArchive::extractTo()` without rejecting entries containing `..` or absolute paths. Unlike modern Info-ZIP `unzip` (used by `ilUtil::unzip`, which strips `../`), PHP’s ZipArchive does not neutralize traversal names.

**Impact:** Authenticated users who can upload/import xAPI, SCORM export, or OrgUnit ZIP packages can write files outside the intended extract directory. Escaping into the document root enables webshell/RCE.

**Attack path:**
1. Obtain `create`/`write` on a CmiXapi or SAHS object (or OrgUnit import permission).
2. Upload a ZIP whose member path is `../../../../evil.php` (or similar relative to the extract dir under `data/`).
3. `extractTo` writes outside the module directory into web-executable space.
4. Request the planted PHP file.

**Evidence:** listed extractTo call sites; contrast `Services/Utilities/classes/class.ilUtil.php:1597-1684` (post-extract symlink scrub only, relies on external unzip).

**Remediation:** Reject any archive entry whose resolved path is not under the intended extract root (`realpath` prefix check). Prefer a shared safe-extract helper for all ZipArchive uses.

---

### 4. Open redirect on Shibboleth front-channel logout
- **Location:** `shib_logout.php`
- **Status:** Remediated in this branch (relative-only return URL)

**Description:** `ilUtil::redirect($_GET['return'])` accepted absolute URLs. `ilCtrl::redirectToURL` passes through any string containing `://` without same-origin checks.

**Impact:** Post-logout phishing / token theft via crafted IdP logout return links.

**Attack path:** `GET /shib_logout.php?action=logout&return=https://evil.example/phish`

**Evidence:** `shib_logout.php:25-35`, `Services/UICore/classes/class.ilCtrl.php:1280-1333`

**Remediation:** Allow only relative paths (applied). Prefer an allowlist of known post-logout landing pages.

---

### 5. Stud.IP referrer session fixation
- **Location:** `studip_referrer.php:23-31`
- **Status:** Remediated in this branch (rejects `sess_id` / `client_id` query params)

**Description:** When `ilias.ini.php` has `studip = 1`, the endpoint set the PHP session cookie and `ilClientId` from attacker-controlled `$_GET['sess_id']` / `$_GET['client_id']`.

**Impact:** Session fixation → account takeover after the victim authenticates into the attacker-chosen session.

**Attack path:**
1. Attacker creates session `S`, crafts `studip_referrer.php?sess_id=S&client_id=<client>&target=login`.
2. Victim follows the link (cookie set to `S`).
3. Victim logs in; attacker reuses cookie `S`.

**Evidence:** `studip_referrer.php:13-31`

**Remediation:** Never accept session IDs from the query string. Use a signed one-time Stud.IP handshake or server-side session bridge.

---

### 6. Authenticated SSRF via External Feed URL
- **Location:** `Services/Feeds/classes/class.ilExternalFeed.php:105-131,219-243`; `Services/Form/classes/class.ilFeedUrlInputGUI.php:89-102`

**Description:** Feed URL validation and discovery call MagpieRSS / `fopen($a_url)` on admin-supplied URLs with no blocklist for loopback, link-local, or cloud metadata addresses. `file://` and internal HTTP targets are reachable when `allow_url_fopen` permits.

**Impact:** SSRF to internal services / cloud metadata from any user allowed to create or configure External Feed objects.

**Attack path:** Create/edit External Feed with URL `http://169.254.169.254/` (or internal host); server fetches during `checkInput` / feed render.

**Evidence:** `ilExternalFeed::_checkUrl`, `_determineFeedUrl`; `ilFeedUrlInputGUI::checkInput`

**Remediation:** Validate scheme (`http`/`https` only), resolve DNS, deny private/link-local/metadata ranges, and fetch via a locked-down HTTP client (no redirects to internal IPs).

---

### 7. Debug endpoint `xdebug.php` in webroot
- **Location:** `xdebug.php` (tracked in git)

**Description:** Unauthenticated script calls `xdebug_info()` when Xdebug is loaded.

**Impact:** Configuration and environment disclosure useful for further attacks.

**Attack path:** `GET /xdebug.php`

**Evidence:** `xdebug.php:1-3`

**Remediation:** Remove from webroot/repository; never deploy debugger endpoints to production.

---

## MEDIUM

### 8. SCORM session-less store uses weak `mt_rand` hash
- **Location:** `Modules/ScormAicc/classes/SCORM/class.ilObjSCORMInitData.php:344-379`; `storeScorm.php` / `storeScorm2004.php` via `checkIfAllowed`

**Description:** Tracking auth token is `mt_rand(1000000000, 2147483647)` (~30 bits), valid ~24h, compared with loose `==`, and returned to the browser in init JSON.

**Impact:** Forgery of another user’s SCORM CMI/score updates if the hash is obtained (XSS, shared client, log leakage) or eventually guessed; bypasses normal PHP session binding by design.

**Remediation:** Use `random_bytes`/HMAC bound to user+package; compare with `hash_equals`; shorten TTL.

---

### 9. Open redirect via GlobalScreen ModeToggle Referer
- **Location:** `src/GlobalScreen/Client/ModeToggle.php:31-38`, entry `src/GlobalScreen/Client/toggle.php`
- **Status:** Remediated in this branch (Referer must start with `ILIAS_HTTP_PATH`)

**Description:** Unauthenticated toggle endpoint redirected to raw `$_SERVER['HTTP_REFERER']`.

**Impact:** Open redirect for phishing when an attacker can make a victim hit `toggle.php` with a crafted Referer.

**Remediation:** Validate Referer against ILIAS_HTTP_PATH or redirect to a fixed local URL.

---

### 10. CmiXapi proxy reflects `Origin` with credentials
- **Location:** `Modules/CmiXapi/xapiproxy.php:13-19` (and related XapiProxy headers)

**Description:** `Access-Control-Allow-Origin` echoes `HTTP_ORIGIN` together with `Allow-Credentials: true` without an allowlist.

**Impact:** Cross-origin credentialed access to the xAPI proxy from attacker origins if browser sends cookies/auth.

**Remediation:** Reflect only configured trusted origins (or omit credentials).

---

## Notes
- `setup/` remains in tree; ILIAS 7 web GUI is abandoned (static message only). CLI setup must stay off the public vhost per `docs/configuration/secure.md`.
- `unzip_test_file.zip` is a benign tracked test archive (removed with other webroot junk).
- System `unzip` used by `ilUtil::unzip` strips `../` on modern Info-ZIP; do not assume the same for ZipArchive.
