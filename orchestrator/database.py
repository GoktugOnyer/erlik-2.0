import aiosqlite
import os
from pathlib import Path

DB_DIR = Path(__file__).parent.parent / "data"
DB_PATH = DB_DIR / "pentest.db"


async def init_db():
    DB_DIR.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                target_url TEXT NOT NULL,
                scope_mode TEXT NOT NULL DEFAULT 'full',
                system_prompt TEXT NOT NULL DEFAULT '',
                enabled_tools TEXT NOT NULL DEFAULT 'nmap,ffuf,sqlmap,nuclei,nikto,gobuster,dirb,wfuzz,whatweb,wafw00f,hydra,curl,netcat,whois,xsstrike,dalfox,commix,crlfuzz,arjun,john,hashcat,jwt_tool,sslyze,testssl,playwright,zap-cli,pw-crawl,login-helper,diff-view,interactive-pw',
                model TEXT NOT NULL DEFAULT 'qwen2.5-coder:7b-instruct-q4_K_M',
                status TEXT NOT NULL DEFAULT 'created',
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS steps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL REFERENCES sessions(id),
                phase TEXT,
                step_number INTEGER,
                prompt_sent TEXT,
                model_response TEXT,
                tool_called TEXT,
                tool_input TEXT,
                tool_output TEXT,
                duration_ms INTEGER,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL REFERENCES sessions(id),
                vuln_type TEXT,
                severity TEXT,
                url TEXT,
                parameter TEXT,
                evidence TEXT,
                verified INTEGER DEFAULT 0,
                false_positive INTEGER DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL UNIQUE REFERENCES sessions(id),
                report_markdown TEXT NOT NULL,
                executive_summary TEXT,
                generated_by_model TEXT,
                generation_duration_ms INTEGER,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS recon_context (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL REFERENCES sessions(id),
                context_type TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT,
                source_tool TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS chains (
                id TEXT PRIMARY KEY,
                target_url TEXT NOT NULL,
                scope_mode TEXT NOT NULL DEFAULT 'full',
                system_prompt TEXT NOT NULL DEFAULT '',
                model TEXT NOT NULL DEFAULT 'qwen2.5-coder:7b-instruct-q4_K_M',
                enabled_tools TEXT NOT NULL DEFAULT '',
                current_phase TEXT NOT NULL DEFAULT 'recon',
                current_position INTEGER NOT NULL DEFAULT 0,
                total_sessions INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'created',
                auto_progress INTEGER NOT NULL DEFAULT 1,
                max_turns_per_session INTEGER NOT NULL DEFAULT 30,
                no_timeout INTEGER NOT NULL DEFAULT 0,
                toolset_preset TEXT DEFAULT NULL,
                disable_stagnation INTEGER DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS ground_truth (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_name TEXT NOT NULL,
                target_url TEXT NOT NULL,
                vuln_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                url_pattern TEXT,
                parameter TEXT,
                description TEXT,
                owasp_category TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS benchmark_runs (
                id TEXT PRIMARY KEY,
                target_url TEXT NOT NULL,
                target_name TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'pending',
                cold_session_id TEXT,
                warm_session_id TEXT,
                chain_id TEXT,
                max_turns INTEGER NOT NULL DEFAULT 30,
                no_timeout INTEGER NOT NULL DEFAULT 0,
                repeat_n INTEGER NOT NULL DEFAULT 1,
                current_iteration INTEGER NOT NULL DEFAULT 1,
                model TEXT NOT NULL DEFAULT 'qwen2.5-coder:7b-instruct-q4_K_M',
                system_prompt TEXT NOT NULL DEFAULT '',
                enabled_tools TEXT NOT NULL DEFAULT '',
                started_at TEXT,
                completed_at TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS benchmark_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                benchmark_id TEXT NOT NULL REFERENCES benchmark_runs(id),
                session_id TEXT NOT NULL REFERENCES sessions(id),
                session_type TEXT NOT NULL,
                total_findings INTEGER DEFAULT 0,
                true_positives INTEGER DEFAULT 0,
                false_positives INTEGER DEFAULT 0,
                missed_vulns INTEGER DEFAULT 0,
                precision_score REAL DEFAULT 0,
                recall_score REAL DEFAULT 0,
                f1_score REAL DEFAULT 0,
                severity_score REAL DEFAULT 0,
                findings_per_minute REAL DEFAULT 0,
                findings_per_turn REAL DEFAULT 0,
                tool_coverage REAL DEFAULT 0,
                unique_tools_used INTEGER DEFAULT 0,
                total_tools_available INTEGER DEFAULT 0,
                time_to_first_finding_ms INTEGER,
                time_to_first_high_ms INTEGER,
                total_duration_ms INTEGER,
                total_steps INTEGER DEFAULT 0,
                phases_covered TEXT DEFAULT '',
                vuln_types_found TEXT DEFAULT '',
                severity_distribution TEXT DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            -- v2: test-case driven runs (replaces freeform sessions as default)
            CREATE TABLE IF NOT EXISTS v2_runs (
                id TEXT PRIMARY KEY,
                test_case_id TEXT NOT NULL,
                target_json TEXT NOT NULL,
                provider TEXT,
                model TEXT,
                duration_ms INTEGER,
                stopped_early INTEGER DEFAULT 0,
                chain_root_run_id TEXT,
                steps_json TEXT,
                chain_next_json TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS v2_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES v2_runs(id),
                test_case_id TEXT NOT NULL,
                step TEXT,
                vuln_type TEXT,
                severity TEXT,
                url TEXT,
                parameter TEXT,
                evidence TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_steps_session ON steps(session_id);
            CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
            CREATE INDEX IF NOT EXISTS idx_reports_session ON reports(session_id);
            CREATE INDEX IF NOT EXISTS idx_recon_session ON recon_context(session_id);
            CREATE INDEX IF NOT EXISTS idx_chains_status ON chains(status);
            CREATE INDEX IF NOT EXISTS idx_ground_truth_target ON ground_truth(target_name);
            CREATE INDEX IF NOT EXISTS idx_benchmark_results_bid ON benchmark_results(benchmark_id);
            CREATE INDEX IF NOT EXISTS idx_benchmark_runs_status ON benchmark_runs(status);
            CREATE INDEX IF NOT EXISTS idx_v2_findings_run ON v2_findings(run_id);
            CREATE INDEX IF NOT EXISTS idx_v2_runs_chain_root ON v2_runs(chain_root_run_id);
            CREATE INDEX IF NOT EXISTS idx_v2_runs_test_case ON v2_runs(test_case_id);
        """)

        # Add new columns to sessions (safe migration for existing DBs)
        migrations = [
            ("session_type", "TEXT DEFAULT 'cold'"),
            ("parent_session_id", "TEXT DEFAULT NULL"),
            ("vuln_category", "TEXT DEFAULT NULL"),
            ("total_duration_ms", "INTEGER DEFAULT NULL"),
            ("total_steps", "INTEGER DEFAULT 0"),
            ("total_findings", "INTEGER DEFAULT 0"),
            ("no_timeout", "INTEGER DEFAULT 0"),
            ("tool_timeout", "INTEGER DEFAULT NULL"),
            ("max_turns", "INTEGER DEFAULT 30"),
            ("chain_id", "TEXT DEFAULT NULL"),
            ("chain_position", "INTEGER DEFAULT NULL"),
            ("chain_phase", "TEXT DEFAULT NULL"),
            ("toolset_preset", "TEXT DEFAULT NULL"),  # RQ3-b action-space ablation
            ("disable_stagnation", "INTEGER DEFAULT 0"),  # benchmark opt-out
            ("run_config", "TEXT DEFAULT NULL"),  # per-session automation flow (JSON)
        ]
        for col_name, col_def in migrations:
            try:
                await db.execute(f"ALTER TABLE sessions ADD COLUMN {col_name} {col_def}")
            except Exception:
                pass  # column already exists

        # Migrations for chains table
        chain_migrations = [
            ("toolset_preset", "TEXT DEFAULT NULL"),
            ("disable_stagnation", "INTEGER DEFAULT 0"),
            ("run_config", "TEXT DEFAULT NULL"),  # per-session automation flow (JSON)
        ]
        for col_name, col_def in chain_migrations:
            try:
                await db.execute(f"ALTER TABLE chains ADD COLUMN {col_name} {col_def}")
            except Exception:
                pass  # column already exists

        # Migrations for benchmark_runs table
        bench_migrations = [
            ("repeat_n", "INTEGER NOT NULL DEFAULT 1"),
            ("current_iteration", "INTEGER NOT NULL DEFAULT 1"),
            ("toolset_preset", "TEXT DEFAULT NULL"),  # which toolset tier this run used
            ("disable_stagnation", "INTEGER DEFAULT 0"),
        ]
        for col_name, col_def in bench_migrations:
            try:
                await db.execute(f"ALTER TABLE benchmark_runs ADD COLUMN {col_name} {col_def}")
            except Exception:
                pass  # column already exists

        # Migrations for benchmark_results table
        bench_result_migrations = [
            ("toolset_preset", "TEXT DEFAULT NULL"),
        ]
        for col_name, col_def in bench_result_migrations:
            try:
                await db.execute(f"ALTER TABLE benchmark_results ADD COLUMN {col_name} {col_def}")
            except Exception:
                pass  # column already exists

        # CVE enrichment columns (populated by orchestrator/enrichment/nvd.py
        # when ERLIK_ENRICH_CVE is set). Additive + nullable — no-op when unused.
        cve_columns = [
            ("cve_id", "TEXT DEFAULT NULL"),
            ("cvss_score", "REAL DEFAULT NULL"),
            ("cvss_vector", "TEXT DEFAULT NULL"),
            ("cwe", "TEXT DEFAULT NULL"),
        ]
        for table in ("findings", "v2_findings"):
            for col_name, col_def in cve_columns:
                try:
                    await db.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_def}")
                except Exception:
                    pass  # column already exists

        # Structured finding columns (Phase 2). Populated at report time by the
        # calibration pass in main.py:_generate_report. Additive + nullable — the
        # report renders identically when these stay NULL.
        structured_columns = [
            ("calibrated_severity", "TEXT DEFAULT NULL"),
            ("owasp_category", "TEXT DEFAULT NULL"),
            ("mitre", "TEXT DEFAULT NULL"),
            ("impact", "TEXT DEFAULT NULL"),
            ("remediation", "TEXT DEFAULT NULL"),
            ("confidence", "TEXT DEFAULT NULL"),
            ("ref_links", "TEXT DEFAULT NULL"),
        ]
        for table in ("findings", "v2_findings"):
            for col_name, col_def in structured_columns:
                try:
                    await db.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_def}")
                except Exception:
                    pass  # column already exists

        # Per-target memory: key recon_context by normalized target so knowledge
        # accumulates across unrelated runs against the same target (additive).
        try:
            await db.execute("ALTER TABLE recon_context ADD COLUMN target_key TEXT DEFAULT NULL")
        except Exception:
            pass
        try:
            await db.execute("CREATE INDEX IF NOT EXISTS idx_recon_context_target ON recon_context(target_key)")
        except Exception:
            pass

        # Stateful exploit-primitive store (captured tokens/cookies/creds per session).
        await db.execute("""
            CREATE TABLE IF NOT EXISTS session_primitives (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                value TEXT NOT NULL,
                hint TEXT,
                source_tool TEXT,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_session_primitives_sid ON session_primitives(session_id);")

        # Operator triage columns (accept/reject + severity override) — additive.
        triage_columns = [
            ("triage_status", "TEXT DEFAULT NULL"),      # accepted | rejected | NULL
            ("severity_override", "TEXT DEFAULT NULL"),
            ("triage_note", "TEXT DEFAULT NULL"),
        ]
        for table in ("findings", "v2_findings"):
            for col_name, col_def in triage_columns:
                try:
                    await db.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_def}")
                except Exception:
                    pass  # column already exists

        await db.commit()


async def get_db():
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    # WAL + a busy timeout so concurrent per-step writes from parallel sessions
    # WAIT for the writer lock instead of failing immediately with
    # "database is locked". Pure reliability win, no behavior change.
    # (FK enforcement is intentionally NOT enabled here — it would require
    # auditing every insert order first; tracked as a separate change.)
    try:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA busy_timeout=5000")
    except Exception:
        pass  # never let PRAGMA setup block opening the DB
    return db
