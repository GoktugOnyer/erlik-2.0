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
                enabled_tools TEXT NOT NULL DEFAULT 'nmap,ffuf,sqlmap,nuclei,nikto,gobuster,dirb,wfuzz,whatweb,wafw00f,hydra,curl,netcat,whois,xsstrike,dalfox,commix,crlfuzz,arjun,john,hashcat,jwt_tool,sslyze,testssl,playwright,zap-cli',
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
                max_turns_per_session INTEGER NOT NULL DEFAULT 15,
                no_timeout INTEGER NOT NULL DEFAULT 0,
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
                max_turns INTEGER NOT NULL DEFAULT 15,
                no_timeout INTEGER NOT NULL DEFAULT 0,
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

            CREATE INDEX IF NOT EXISTS idx_steps_session ON steps(session_id);
            CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
            CREATE INDEX IF NOT EXISTS idx_reports_session ON reports(session_id);
            CREATE INDEX IF NOT EXISTS idx_recon_session ON recon_context(session_id);
            CREATE INDEX IF NOT EXISTS idx_chains_status ON chains(status);
            CREATE INDEX IF NOT EXISTS idx_ground_truth_target ON ground_truth(target_name);
            CREATE INDEX IF NOT EXISTS idx_benchmark_results_bid ON benchmark_results(benchmark_id);
            CREATE INDEX IF NOT EXISTS idx_benchmark_runs_status ON benchmark_runs(status);
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
            ("max_turns", "INTEGER DEFAULT 15"),
            ("chain_id", "TEXT DEFAULT NULL"),
            ("chain_position", "INTEGER DEFAULT NULL"),
            ("chain_phase", "TEXT DEFAULT NULL"),
        ]
        for col_name, col_def in migrations:
            try:
                await db.execute(f"ALTER TABLE sessions ADD COLUMN {col_name} {col_def}")
            except Exception:
                pass  # column already exists

        await db.commit()


async def get_db():
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    return db
