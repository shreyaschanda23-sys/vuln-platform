# api/routes/websocket.py
import json
import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from collections import defaultdict
import redis.asyncio as aioredis

from app.config import settings

router = APIRouter()

_REDIS_CHANNEL_PREFIX = "scan_progress:"


class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[int, list[WebSocket]] = defaultdict(list)

    async def connect(self, scan_id: int, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[scan_id].append(websocket)

    def disconnect(self, scan_id: int, websocket: WebSocket):
        if websocket in self.active_connections[scan_id]:
            self.active_connections[scan_id].remove(websocket)

    async def broadcast_local(self, scan_id: int, message: dict):
        """Send to WebSocket clients connected to THIS process only."""
        dead = []
        for ws in self.active_connections[scan_id]:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(scan_id, ws)


manager = ConnectionManager()


async def _redis_listener():
    """
    Runs once inside the FastAPI process. Subscribes to a Redis pubsub
    pattern covering all scan progress channels, and re-broadcasts any
    message published by Celery workers to this process's local WebSocket
    connections. This is the bridge between the Celery worker process
    (which has no WebSocket connections of its own) and FastAPI (which
    does).
    """
    redis_client = aioredis.from_url(settings.redis_url)
    pubsub = redis_client.pubsub()
    await pubsub.psubscribe(f"{_REDIS_CHANNEL_PREFIX}*")

    async for message in pubsub.listen():
        if message["type"] != "pmessage":
            continue
        try:
            channel = message["channel"].decode() if isinstance(message["channel"], bytes) else message["channel"]
            scan_id = int(channel.replace(_REDIS_CHANNEL_PREFIX, ""))
            data = json.loads(message["data"])
            await manager.broadcast_local(scan_id, data)
        except Exception:
            continue


@router.on_event("startup")
async def _start_redis_listener():
    asyncio.create_task(_redis_listener())


@router.websocket("/ws/scans/{scan_id}")
async def scan_progress_socket(websocket: WebSocket, scan_id: int):
    await manager.connect(scan_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(scan_id, websocket)