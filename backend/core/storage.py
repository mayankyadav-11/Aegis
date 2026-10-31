"""
AEGIS 2.0 — Dual-Mode Storage Architecture

Implements:
1. SessionStorage: In-memory, ephemeral storage with TTL for regular anonymous users.
2. PersistentStorage: Multi-tenant SQLite database for authenticated enterprise users.
3. Strict organization-level isolation and server-side mode resolution.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from core.auth import AuthContext, hash_password, verify_password
from schemas import AnalysisResponse


# ---------------------------------------------------------------------------
# 1. Ephemeral Session Storage (for Regular Users)
# ---------------------------------------------------------------------------

class SessionStorage:
    """
    In-memory session-scoped storage.
    Automatically purges investigations when sessions expire due to inactivity.
    Never persists to disk.
    """

    def __init__(self, inactivity_timeout_seconds: int = 3600):
        self._lock = threading.Lock()
        self._sessions: dict[str, dict[str, Any]] = {}
        self.inactivity_timeout = inactivity_timeout_seconds

    def _cleanup_unlocked(self):
        """Remove sessions that have exceeded inactivity timeout."""
        now = time.time()
        expired = [
            sid for sid, sdata in self._sessions.items()
            if now - sdata["last_active"] > self.inactivity_timeout
        ]
        for sid in expired:
            del self._sessions[sid]

    def touch_session(self, session_id: str):
        """Register or update activity timestamp for a session."""
        with self._lock:
            self._cleanup_unlocked()
            if session_id not in self._sessions:
                self._sessions[session_id] = {
                    "created_at": time.time(),
                    "last_active": time.time(),
                    "cases": {},
                }
            else:
                self._sessions[session_id]["last_active"] = time.time()

    def save_case(self, session_id: str, case: AnalysisResponse):
        """Store a case inside the caller's active session."""
        with self._lock:
            self._cleanup_unlocked()
            if session_id not in self._sessions:
                self._sessions[session_id] = {
                    "created_at": time.time(),
                    "last_active": time.time(),
                    "cases": {},
                }
            else:
                self._sessions[session_id]["last_active"] = time.time()

            # Store serializable dict
            case_dict = case.model_dump()
            self._sessions[session_id]["cases"][case.case_id] = case_dict

    def get_case(self, session_id: str, case_id: str) -> Optional[dict]:
        """Retrieve a case from the session, updating activity."""
        with self._lock:
            self._cleanup_unlocked()
            sdata = self._sessions.get(session_id)
            if not sdata:
                return None
            sdata["last_active"] = time.time()
            return sdata["cases"].get(case_id)

    def list_cases(self, session_id: str) -> list[dict]:
        """List all active cases in the caller's session."""
        with self._lock:
            self._cleanup_unlocked()
            sdata = self._sessions.get(session_id)
            if not sdata:
                return []
            sdata["last_active"] = time.time()
            # Return cases sorted newest first
            cases = list(sdata["cases"].values())
            cases.sort(key=lambda c: c.get("created_at", ""), reverse=True)
            return cases

    def delete_session(self, session_id: str) -> bool:
        """Purge all session investigations immediately upon user logout/reset."""
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return True
            return False


# ---------------------------------------------------------------------------
# 2. Persistent Multi-Tenant Storage (for Enterprise Users)
# ---------------------------------------------------------------------------

class PersistentStorage:
    """
    SQLite persistent storage for authenticated enterprise organizations.
    Enforces organization isolation: users cannot see cases belonging to other orgs.
    """

    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            db_path = Path(__file__).resolve().parent.parent / "data" / "aegis.db"
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Create tables and seed initial enterprise accounts if empty."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Organizations
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS organizations (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)

            # Users
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    hashed_password TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    role TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (org_id) REFERENCES organizations(id)
                )
            """)

            # Enterprise Cases
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS enterprise_cases (
                    case_id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    input_type TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    evidence_hash TEXT,
                    payload_json TEXT NOT NULL,
                    FOREIGN KEY (org_id) REFERENCES organizations(id),
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)

            # Indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cases_org ON enterprise_cases(org_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cases_created ON enterprise_cases(created_at)")

            conn.commit()

        # Seed initial demo enterprise accounts
        self._seed_default_accounts()

    def _seed_default_accounts(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM organizations")
            if cursor.fetchone()["count"] == 0:
                now = datetime.now(timezone.utc).isoformat()

                # Org 1: Acme Corp
                cursor.execute(
                    "INSERT INTO organizations (id, name, created_at) VALUES (?, ?, ?)",
                    ("org_acme", "Acme Corporation", now),
                )
                h1, s1 = hash_password("Password123!")
                cursor.execute(
                    """INSERT INTO users (id, org_id, email, hashed_password, salt, role, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    ("usr_acme_lead", "org_acme", "secops@acme.com", h1, s1, "security_lead", now),
                )

                # Org 2: CyberShield Ltd (Multi-tenant test)
                cursor.execute(
                    "INSERT INTO organizations (id, name, created_at) VALUES (?, ?, ?)",
                    ("org_cybershield", "CyberShield Ltd", now),
                )
                h2, s2 = hash_password("Password123!")
                cursor.execute(
                    """INSERT INTO users (id, org_id, email, hashed_password, salt, role, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    ("usr_shield_analyst", "org_cybershield", "analyst@cybershield.com", h2, s2, "threat_analyst", now),
                )
                conn.commit()

    def authenticate_user(self, email: str, password: str) -> Optional[dict]:
        """Authenticate user by email and password. Returns user profile if valid."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """SELECT u.id, u.org_id, u.email, u.hashed_password, u.salt, u.role, o.name as org_name
                   FROM users u
                   JOIN organizations o ON u.org_id = o.id
                   WHERE LOWER(u.email) = LOWER(?)""",
                (email.strip(),),
            )
            row = cursor.fetchone()
            if not row:
                return None
            if not verify_password(password, row["salt"], row["hashed_password"]):
                return None

            return {
                "id": row["id"],
                "org_id": row["org_id"],
                "org_name": row["org_name"],
                "email": row["email"],
                "role": row["role"],
            }

    def get_user_by_id(self, user_id: str) -> Optional[dict]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """SELECT u.id, u.org_id, u.email, u.role, o.name as org_name
                   FROM users u
                   JOIN organizations o ON u.org_id = o.id
                   WHERE u.id = ?""",
                (user_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "id": row["id"],
                "org_id": row["org_id"],
                "org_name": row["org_name"],
                "email": row["email"],
                "role": row["role"],
            }

    def save_case(self, context: AuthContext, case: AnalysisResponse) -> str:
        """Persist investigation strictly attached to the authenticated org and user."""
        if not context.is_enterprise or not context.org_id or not context.user_id:
            raise PermissionError("Attempted to save persistent case without enterprise authentication.")

        payload_json = case.model_dump_json()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """INSERT OR REPLACE INTO enterprise_cases
                   (case_id, org_id, user_id, input_type, created_at, risk_score, risk_level, verdict, confidence, evidence_hash, payload_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    case.case_id,
                    context.org_id,
                    context.user_id,
                    case.input_type.value if hasattr(case.input_type, "value") else str(case.input_type),
                    case.created_at,
                    case.risk_score,
                    case.risk_level.value if hasattr(case.risk_level, "value") else str(case.risk_level),
                    case.verdict.value if hasattr(case.verdict, "value") else str(case.verdict),
                    case.confidence.value if hasattr(case.confidence, "value") else str(case.confidence),
                    case.evidence_hash,
                    payload_json,
                ),
            )
            conn.commit()
        return case.case_id

    def get_case(self, context: AuthContext, case_id: str) -> Optional[dict]:
        """
        Retrieve case strictly enforcing organization isolation.
        Cannot read cases belonging to another organization.
        """
        if not context.is_enterprise or not context.org_id:
            return None

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """SELECT payload_json FROM enterprise_cases
                   WHERE case_id = ? AND org_id = ?""",
                (case_id, context.org_id),
            )
            row = cursor.fetchone()
            if not row:
                return None
            return json.loads(row["payload_json"])

    def list_cases(
        self,
        context: AuthContext,
        query: Optional[str] = None,
        input_type: Optional[str] = None,
        verdict: Optional[str] = None,
        risk_level: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict:
        """List and filter cases for the authenticated organization."""
        if not context.is_enterprise or not context.org_id:
            return {"total": 0, "cases": [], "limit": limit, "offset": offset}

        clauses = ["org_id = ?"]
        params: list[Any] = [context.org_id]

        if input_type:
            clauses.append("input_type = ?")
            params.append(input_type.lower())
        if verdict:
            clauses.append("verdict = ?")
            params.append(verdict.lower())
        if risk_level:
            clauses.append("risk_level = ?")
            params.append(risk_level.lower())
        if query:
            clauses.append("(case_id LIKE ? OR payload_json LIKE ?)")
            search_param = f"%{query}%"
            params.extend([search_param, search_param])

        where_sql = " AND ".join(clauses)

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Count total
            cursor.execute(f"SELECT COUNT(*) as count FROM enterprise_cases WHERE {where_sql}", params)
            total = cursor.fetchone()["count"]

            # Fetch page
            page_sql = f"""
                SELECT payload_json FROM enterprise_cases
                WHERE {where_sql}
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
            """
            cursor.execute(page_sql, params + [limit, offset])
            rows = cursor.fetchall()
            cases = [json.loads(r["payload_json"]) for r in rows]

            return {
                "total": total,
                "cases": cases,
                "limit": limit,
                "offset": offset,
            }


# ---------------------------------------------------------------------------
# Global Storage Singletons
# ---------------------------------------------------------------------------

session_storage = SessionStorage()
persistent_storage = PersistentStorage()

