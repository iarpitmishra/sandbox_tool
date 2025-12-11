
# sandbox_tool – cURL Sandbox with eBPF + ENV Filter (SEC-001)

This project enforces **network**, **filesystem**, and **environment-variable** policies on the `curl` command using:

- eBPF LSM + cgroup hooks (`policy_kern.bpf.c` + `policy_loader.c`)
- A user-space `LD_PRELOAD` shim (`env_shim.c`) for SEC-001

It is designed to satisfy the E0256 “User Command Sandbox” assignment requirements.

---

## 1. Features / Policies

### NET-001 — Network Policy (kernel eBPF)

- Only allows `curl` to connect:
  - To **whitelisted domains** (e.g., `example.com`, `iisc.ac.in`)
  - On **ports 80 or 443** (HTTP/HTTPS)
- Any other domain or port (e.g., `google.com`, `iisc.ac.in:8443`, `example.com:60`) is **blocked**.

### FS-001 — Filesystem Policy (kernel eBPF)

- `curl` is only allowed to **write** under:

  ```text
  /tmp/curl_downloads/


* Writes to any other path (e.g., `/tmp/not_allowed`, `/etc/hosts`) are **blocked** with:

  ```text
  curl: (23) Failure writing output to destination
  ```

### SEC-001 — Environment Variable Policy (user-space shim)

* Implemented via `env_shim.c` compiled as `env_shim.so`, injected using `LD_PRELOAD`.

* Intercepts:

  * `getenv`
  * `secure_getenv`

* **Blocks** any access to environment variables whose **names contain**, case-insensitively:

  * `PASSWORD`
  * `KEY`
  * `SECRET`

* Logs behavior to `stderr`:

  * On violation:

    ```text
    SEC-001 VIOLATION: Blocked getenv('SECRET_PASSWORD')
    ```

  * On allowed reads:

    ```text
    SEC-001: Allowed getenv('USER') = [HIDDEN]
    ```

---

## 2. Build & Setup

### 2.1. Dependencies

On Ubuntu 22.04 (or similar) with kernel ≥ 6.8:

* `clang`, `llvm`
* `make`, `gcc`
* `libbpf-dev` or standalone libbpf (depending on how the repo is set up)
* `libjson-c-dev`
* `curl`

Install typical deps (if needed):

```bash
sudo apt update
sudo apt install -y clang llvm make gcc libbpf-dev libjson-c-dev curl
```

### 2.2. Clean old policies / pinned state

Before loading a new version, run:

```bash
cd ~/sandbox_tool

sudo pkill -f "./policy_loader" 2>/dev/null || true
sudo rm -rf /sys/fs/bpf/curl_sandbox 2>/dev/null || true
sudo mkdir -p /sys/fs/bpf/curl_sandbox/links
```

This:

* Kills any old `policy_loader` instances
* Removes old pinned maps/links under `/sys/fs/bpf/curl_sandbox`
* Re-creates the directory expected by the new loader

### 2.3. Build

```bash
make clean && make
```

This should:

* Build the BPF object files `policy_kern.bpf.o`, `policy_uprobes.bpf.o` (if present)
* Build the loader binary `policy_loader`

---

## 3. Running the Sandbox

### 3.1. Start the policy loader

In **Terminal 1**:

```bash
cd ~/sandbox_tool
sudo ./policy_loader policy.json --foreground
```

* Attaches the BPF programs (LSM + cgroup hooks)
* Keeps running in the foreground so you can see logs

### 3.2. Use `curl_sandbox.sh` (recommended wrapper)

In **Terminal 2**, use the provided script:

```bash
cd ~/sandbox_tool
sudo bash scripts/curl_sandbox.sh -I https://example.com
```

The script typically:

* Joins `curl` to the cgroup used by the sandbox
* Ensures the policies apply
* (Optionally) prepends `LD_PRELOAD=./env_shim.so` for SEC-001

---

## 4. SEC-001: env_shim Build & Usage

### 4.1. Build the shim

```bash
cd ~/sandbox_tool
gcc -shared -fPIC -o env_shim.so env_shim.c -ldl
```

> **Important:** Do **not** run `./env_shim.so` directly (it’s a shared library, not an executable).
> That’s why `./env_shim.so ./test_sec001_final` segfaults.

### 4.2. Test program for SEC-001

Create `test_sec001_final.c` (already in your repo) like:

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    printf("=== SEC-001 Final Test ===\n");

    // Test BLOCKED variables
    printf("1. SECRET_PASSWORD: %s\n", getenv("SECRET_PASSWORD"));
    printf("2. API_KEY: %s\n", getenv("API_KEY"));
    printf("3. MY_SECRET: %s\n", getenv("MY_SECRET"));

    // Test ALLOWED variables
    printf("4. NORMAL_VAR: %s\n", getenv("NORMAL_VAR"));
    printf("5. USER: %s\n", getenv("USER"));

    return 0;
}
```

Compile it:

```bash
gcc -o test_sec001_final test_sec001_final.c
```

Set environment variables:

```bash
export SECRET_PASSWORD=mysecret
export API_KEY=abc123
export MY_SECRET=test123
export NORMAL_VAR=ok
```

#### 4.2.1. Run **without** SEC-001

```bash
./test_sec001_final
```

Expected output:

```text
=== SEC-001 Final Test ===
1. SECRET_PASSWORD: mysecret
2. API_KEY: abc123
3. MY_SECRET: test123
4. NORMAL_VAR: ok
5. USER: atif
```

#### 4.2.2. Run **with** SEC-001 (LD_PRELOAD)

```bash
LD_PRELOAD=./env_shim.so ./test_sec001_final
```

Expected behavior:

* Shim prints logs like:

  ```text
  SEC-001: Environment filter loaded (PID: 43360)
  SEC-001 VIOLATION: Blocked getenv('SECRET_PASSWORD')
  SEC-001 VIOLATION: Blocked getenv('API_KEY')
  SEC-001 VIOLATION: Blocked getenv('MY_SECRET')
  SEC-001: Allowed getenv('NORMAL_VAR') = [HIDDEN]
  SEC-001: Allowed getenv('USER') = [HIDDEN]
  ```

* Program output becomes:

  ```text
  === SEC-001 Final Test ===
  1. SECRET_PASSWORD: (null)
  2. API_KEY: (null)
  3. MY_SECRET: (null)
  4. NORMAL_VAR: ok
  5. USER: atif
  ```

---

## 5. Demo Tests for curl

This section shows how the three policies behave for `curl`.

### 5.1. NET-001 tests (network policy)

With `policy_loader` running:

```bash
cd ~/sandbox_tool

# Allowed: example.com (80/443)
curl -I https://example.com

# Allowed: iisc.ac.in (443)
curl -I https://iisc.ac.in

# Blocked: non-whitelisted domain
curl -I https://google.com

# Blocked: non-whitelisted port on allowed domain
curl -I https://iisc.ac.in:8443

# Blocked: weird port on allowed domain
curl -I https://example.com:60
```

Typical observed behavior:

```text
curl -I https://example.com
USER: atif
accept-ranges: bytes
content-length: 513
content-type: text/html
...

curl -I https://iisc.ac.in
HTTP/1.1 200 OK
...

curl -I https://google.com
curl: (7) Couldn't connect to server

curl -I https://iisc.ac.in:8443
curl: (7) Couldn't connect to server

curl -I https://example.com:60
curl: (7) Couldn't connect to server
```

### 5.2. FS-001 tests (filesystem policy)

```bash
cd ~/sandbox_tool
sudo mkdir -p /tmp/curl_downloads
sudo mkdir -p /tmp/not_allowed
```

#### Allowed write:

```bash
sudo curl -sS https://example.com -o /tmp/curl_downloads/ok && echo "OK wrote"
```

Output:

```text
OK wrote
```

#### Blocked writes:

```bash
sudo curl -sS https://example.com -o /tmp/not_allowed || echo "blocked as expected"
sudo curl -sS https://example.com -o /etc/hosts      || echo "blocked as expected"
```

Expected:

```text
curl: (23) Failure writing output to destination
blocked as expected
```

### 5.3. SEC-001 tests with curl

#### 5.3.1. Without shim (baseline)

```bash
export SECRET_PASSWORD=mysecret
export API_KEY=abc123
export MY_SECRET=test123
export NORMAL_VAR=ok
export SSLKEYLOGFILE=/tmp/ssl_keys.log

curl -v https://example.com >/dev/null 2>&1 | grep SEC-001 || echo "No SEC-001 logs (as expected)"
```

Since the shim isn’t loaded, there are **no SEC-001 logs**.

#### 5.3.2. With shim using LD_PRELOAD

Run:

```bash
LD_PRELOAD=./env_shim.so curl -Is https://example.com 2>&1 | grep "SEC-001"
```

Sample logs:

```text
SEC-001: Environment filter loaded (PID: 43542)
SEC-001: Allowed getenv('P11_KIT_STRICT') = NULL
SEC-001: Allowed getenv('P11_KIT_DEBUG') = NULL
...
SEC-001 VIOLATION: Blocked getenv('SSLKEYLOGFILE')
SEC-001: Allowed getenv('CURL_HOME') = NULL
SEC-001: Allowed getenv('XDG_CONFIG_HOME') = NULL
SEC-001: Allowed getenv('HOME') = [HIDDEN]
SEC-001: Allowed getenv('CURL_CA_BUNDLE') = NULL
SEC-001: Allowed getenv('SSL_CERT_DIR') = [HIDDEN]
...
```

`curl` still succeeds (exit code 0), but any secret-like env var access is blocked and logged.

#### 5.3.3. Full sandbox wrapper test

Using the assignment’s wrapper script (which puts `curl` into the cgroup and uses the shim):

```bash
SECRET_PASSWORD=mysecret API_KEY=abc123 MY_SECRET=test123 \
sudo bash scripts/curl_sandbox.sh -I https://example.com 2>&1 | grep SEC-001
```

Expected logs (similar to):

```text
SEC-001: Environment filter loaded (PID: 43613)
SEC-001 VIOLATION: Blocked getenv('SSLKEYLOGFILE')
SEC-001: Allowed getenv('HOME') = [HIDDEN]
...
```

---

## 6. Summary

* **NET-001**: Enforced in kernel — only whitelisted domains and ports.
* **FS-001**: Enforced in kernel — only `/tmp/curl_downloads/` writable for `curl`.
* **SEC-001**: Enforced via `env_shim.so` + `LD_PRELOAD` — blocks env vars whose names contain `PASSWORD`, `KEY`, or `SECRET`.

To re-run everything from scratch:

1. Kill and unpin old policies
2. `make clean && make`
3. `sudo ./policy_loader policy.json --foreground`
4. In another terminal, run the curl + SEC-001 tests above.

This README should be enough for someone else to build, run, and verify your sandbox end-to-end.
