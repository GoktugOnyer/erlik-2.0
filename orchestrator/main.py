import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from orchestrator.database import init_db, get_db
from orchestrator.models import SessionCreate, SessionResponse
from orchestrator import llm_client


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(title="Pentest Agent", lifespan=lifespan)
templates = Jinja2Templates(directory="dashboard/templates")


# --- WebSocket Manager ---

class ConnectionManager:
    def __init__(self):
        self.active: dict[str, list[WebSocket]] = {}

    async def connect(self, session_id: str, ws: WebSocket):
        await ws.accept()
        self.active.setdefault(session_id, []).append(ws)

    def disconnect(self, session_id: str, ws: WebSocket):
        if session_id in self.active:
            self.active[session_id] = [
                c for c in self.active[session_id] if c is not ws
            ]

    async def broadcast(self, session_id: str, message: dict):
        import json
        for ws in self.active.get(session_id, []):
            try:
                await ws.send_text(json.dumps(message))
            except Exception:
                pass


manager = ConnectionManager()


# --- Routes ---

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/sessions", response_model=SessionResponse)
async def create_session(data: SessionCreate):
    session_id = uuid.uuid4().hex[:12]
    db = await get_db()
    try:
        await db.execute(
            "INSERT INTO sessions (id, target_url, scope_mode) VALUES (?, ?, ?)",
            (session_id, data.target_url, data.scope_mode.value),
        )
        await db.commit()
        row = await db.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
        session = await row.fetchone()
        return SessionResponse(
            id=session["id"],
            target_url=session["target_url"],
            scope_mode=session["scope_mode"],
            status=session["status"],
            created_at=session["created_at"],
        )
    finally:
        await db.close()


@app.get("/api/sessions/{session_id}", response_model=SessionResponse)
async def get_session(session_id: str):
    db = await get_db()
    try:
        row = await db.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
        session = await row.fetchone()
        if not session:
            from fastapi import HTTPException
            raise HTTPException(404, "Session not found")
        return SessionResponse(
            id=session["id"],
            target_url=session["target_url"],
            scope_mode=session["scope_mode"],
            status=session["status"],
            created_at=session["created_at"],
        )
    finally:
        await db.close()


@app.post("/api/sessions/{session_id}/start")
async def start_session(session_id: str):
    db = await get_db()
    try:
        await db.execute(
            "UPDATE sessions SET status = 'running', updated_at = datetime('now') WHERE id = ?",
            (session_id,),
        )
        await db.commit()
        await manager.broadcast(session_id, {
            "type": "status",
            "status": "running",
            "message": "Session started. Agent loop is a TODO placeholder.",
        })
        return {"status": "running", "message": "Agent loop not yet implemented."}
    finally:
        await db.close()


@app.get("/api/sessions/{session_id}/steps")
async def list_steps(session_id: str):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM steps WHERE session_id = ? ORDER BY step_number", (session_id,)
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


@app.get("/api/sessions/{session_id}/findings")
async def list_findings(session_id: str):
    db = await get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM findings WHERE session_id = ? ORDER BY id", (session_id,)
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


@app.get("/api/health")
async def health():
    return await llm_client.health_check()


@app.websocket("/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    await manager.connect(session_id, websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Echo for now
            await websocket.send_text(f"echo: {data}")
    except WebSocketDisconnect:
        manager.disconnect(session_id, websocket)
