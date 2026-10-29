"""
WebSocket Endpoints (/api/ws)
Provides real-time bidirectional connection endpoint for SOC Command Center.
"""

import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from backend.app.core.websocket import soc_ws_manager

logger = logging.getLogger("SentinelAI.WSEndpoint")

router = APIRouter(prefix="/ws", tags=["WebSocket Telemetry Stream"])


@router.websocket("/soc")
async def soc_websocket_endpoint(websocket: WebSocket):
    """
    WebSocket Endpoint for SOC Command Center.
    Maintains active telemetry stream connection and broadcasts live security threat events.
    """
    await soc_ws_manager.connect(websocket)
    try:
        # Keep connection alive listening for ping/heartbeat or disconnects
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        soc_ws_manager.disconnect(websocket)
    except Exception as err:
        logger.warning(f"WebSocket connection error: {err}")
        soc_ws_manager.disconnect(websocket)
