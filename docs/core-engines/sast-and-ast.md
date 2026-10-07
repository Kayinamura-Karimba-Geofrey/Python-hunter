# SAST & AST Security Engine Architecture

Python Hunter's Static Application Security Testing (SAST) engine operates directly on Python's **Abstract Syntax Tree (AST)**. It evaluates code structure, symbol bindings, and function invocations without executing code.

---

## 1. Engine Workflow & Architecture

```
┌────────────────────────┐
│   Python Source File   │
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│     AST Parser         │
│  (ast.parse in sandbox)│
└───────────┬────────────┘
            │
    ┌───────┴───────┬───────────────────┬───────────────────┐
    ▼               ▼                   ▼                   ▼
┌───────────────┐ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ Sink Detection│ │ Dynamic Code    │ │ Concurrency     │ │ Framework Rules │
│ (Subprocess,  │ │ & Serialization │ │ & TOCTOU Engine │ │ (FastAPI, Flask,│
│  OS, Popen)   │ │ (Pickle, YAML)  │ │ (Races, Deadlock│ │  Django, Auth)  │
└───────┬───────┘ └────────┬────────┘ └────────┬────────┘ └────────┬────────┘
        │                  │                   │                   │
        └──────────────────┴─────────┬─────────┴───────────────────┘
                                     │
                                     ▼
                      ┌─────────────────────────────┐
                      │ Normalized Security Findings│
                      └─────────────────────────────┘
```

---

## 2. Core SAST Analyzers

### 1. Command Injection & Subprocess Analyzer
Detects unsafe operating system process spawning:
* **`pyh_ast_005_subprocess_shell.py`**: Flags `subprocess.Popen`, `subprocess.run`, and `subprocess.call` when `shell=True` is supplied alongside dynamic variables.
* **`pyh_ast_010_os_popen.py`**: Detects legacy POSIX process execution using `os.popen()` or `os.system()` which invoke system shells implicitly.

### 2. Insecure Deserialization & Dynamic Execution
* **`pyh_dynamic_001_eval_exec.py`**: Identifies direct calls to `eval()`, `exec()`, or `compile()` with non-literal arguments.
* **`pyh_dynamic_002_unsafe_pickle.py`**: Flags deserialization of untrusted byte streams via `pickle.loads()` or `cPickle.loads()`, which can lead to Remote Code Execution (RCE) via `__reduce__` exploit payloads.
* **`pyh_dynamic_003_unsafe_yaml.py`**: Detects `yaml.load()` invocations missing `Loader=yaml.SafeLoader` or `yaml.CSafeLoader`.
* **`pyh_dynamic_004_reflection.py`**: Flags dynamic attribute resolution and object reflection (`getattr()`, `setattr()`) controlled by external input.
* **`pyh_dynamic_005_dynamic_import.py`**: Identifies dynamic module loading via `importlib.import_module()` or `__import__()`.

### 3. Concurrency & Race Condition Detection
* **`pyh_conc_001_potential_race.py`**: Detects shared mutable module-level state accessed across async co-routines or threaded workers without synchronization locks.
* **`pyh_conc_003_toctou.py`**: Flags **Time-of-Check to Time-of-Use (TOCTOU)** race conditions in file system interactions (e.g. checking `os.path.exists(path)` prior to `open(path, 'w')` instead of using atomic creation flags `os.O_CREAT | os.O_EXCL`).
* **`pyh_conc_004_deadlock.py`**: Identifies un-ordered nested lock acquisition patterns across threading locks and semaphores.

---

## 3. Web Framework Security Rules

Python Hunter includes specialized AST analyzers for modern web application frameworks:

### FastAPI Rules (`fastapi_rules.py`)
* **Insecure CORS Configuration**: Detects `CORSMiddleware` configured with `allow_origins=["*"]` combined with `allow_credentials=True`.
* **Exposed Interactive Documentation**: Warns when Swagger UI (`/docs`) and ReDoc (`/redoc`) endpoints are enabled in production environments.
* **Missing Response Models**: Identifies sensitive route handlers missing explicit `response_model` definitions that could leak internal database fields or password hashes.

### Django Rules (`django_rules.py`)
* **Debug Mode in Production**: Detects `DEBUG = True` settings in production configuration files.
* **Wildcard Allowed Hosts**: Flags `ALLOWED_HOSTS = ['*']` which enables HTTP Host header poisoning and cache poisoning attacks.
* **Raw SQL Execution**: Identifies un-parameterized queries executed via `Model.objects.raw()` or `django.db.connection.cursor().execute()`.

### Flask Rules (`flask_rules.py`)
* **Debug Mode**: Flags `app.run(debug=True)` which opens the interactive Werkzeug pin-protected debugger over the network.
* **Static File Path Traversal**: Identifies unsafe `send_file()` or `send_from_directory()` calls passing unvalidated user-controlled paths.

### Authentication & Cryptography Rules (`auth_rules.py`)
* **Weak JWT Algorithms**: Detects JWT verification functions that allow `"algorithm": "none"` or weak symmetric HMAC keys for token signing.
* **Timing Attack Vulnerabilities**: Flags standard string comparison operators (`==`, `!=`) used for cryptographic token or password hash verification instead of `hmac.compare_digest()`.
* **Insecure PRNG for Cryptographic Operations**: Warns when standard `random` module methods (`random.random()`, `random.choice()`) are used to generate security tokens instead of the `secrets` module.
