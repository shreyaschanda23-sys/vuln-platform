from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from collections import defaultdict

router = APIRouter()


class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[int, list[WebSocket]] = defaultdict(list)

    async def connect(self, scan_id: int, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[scan_id].append(websocket)

    def disconnect(self, scan_id: int, websocket: WebSocket):
        if websocket in self.active_connections[scan_id]:
            self.active_connections[scan_id].remove(websocket)

    async def broadcast(self, scan_id: int, message: dict):
        dead = []
        for ws in self.active_connections[scan_id]:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(scan_id, ws)


manager = ConnectionManager()


@router.websocket("/ws/scans/{scan_id}")
async def scan_progress_socket(websocket: WebSocket, scan_id: int):
    await manager.connect(scan_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(scan_id, websocket)