from fastapi import WebSocket, WebSocketDisconnect
from typing import List, Dict, Any
import json
import asyncio
from datetime import datetime

class ConnectionManager:
    """Manages WebSocket connections for real-time threat updates"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.connection_metadata: Dict[WebSocket, Dict[str, Any]] = {}
    
    async def connect(self, websocket: WebSocket, client_id: str = None):
        """Accept and register a new WebSocket connection"""
        await websocket.accept()
        self.active_connections.append(websocket)
        self.connection_metadata[websocket] = {
            "client_id": client_id or f"client_{len(self.active_connections)}",
            "connected_at": datetime.now().isoformat(),
            "message_count": 0
        }
        print(f"[WebSocket] Client connected: {self.connection_metadata[websocket]['client_id']}")
        
        # Send welcome message
        await self.send_personal_message({
            "type": "connection",
            "status": "connected",
            "message": "Real-time threat intelligence stream active",
            "timestamp": datetime.now().isoformat()
        }, websocket)
    
    def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection"""
        if websocket in self.active_connections:
            client_id = self.connection_metadata.get(websocket, {}).get("client_id", "unknown")
            self.active_connections.remove(websocket)
            if websocket in self.connection_metadata:
                del self.connection_metadata[websocket]
            print(f"[WebSocket] Client disconnected: {client_id}")
    
    async def send_personal_message(self, message: Dict[str, Any], websocket: WebSocket):
        """Send a message to a specific client"""
        try:
            await websocket.send_json(message)
            if websocket in self.connection_metadata:
                self.connection_metadata[websocket]["message_count"] += 1
        except Exception as e:
            print(f"[WebSocket] Error sending personal message: {e}")
    
    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast a message to all connected clients"""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
                if connection in self.connection_metadata:
                    self.connection_metadata[connection]["message_count"] += 1
            except WebSocketDisconnect:
                disconnected.append(connection)
            except Exception as e:
                print(f"[WebSocket] Error broadcasting to client: {e}")
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for connection in disconnected:
            self.disconnect(connection)
    
    async def broadcast_threat_update(self, threat_data: Dict[str, Any]):
        """Broadcast a threat update to all clients"""
        message = {
            "type": "threat_update",
            "data": threat_data,
            "timestamp": datetime.now().isoformat()
        }
        await self.broadcast(message)
    
    async def broadcast_remediation(self, remediation_data: Dict[str, Any]):
        """Broadcast a remediation event to all clients"""
        message = {
            "type": "remediation",
            "data": remediation_data,
            "timestamp": datetime.now().isoformat()
        }
        await self.broadcast(message)
    
    async def broadcast_alert(self, alert_type: str, alert_message: str, severity: str = "INFO"):
        """Broadcast an alert notification"""
        message = {
            "type": "alert",
            "alert_type": alert_type,
            "message": alert_message,
            "severity": severity,
            "timestamp": datetime.now().isoformat()
        }
        await self.broadcast(message)
    
    async def broadcast_log_source_update(self, source_name: str, stats: Dict[str, Any]):
        """Broadcast log source statistics update"""
        message = {
            "type": "log_source_update",
            "data": {
                "source": source_name,
                "stats": stats
            },
            "timestamp": datetime.now().isoformat()
        }
        await self.broadcast(message)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        return {
            "active_connections": len(self.active_connections),
            "total_messages": sum(
                meta.get("message_count", 0) 
                for meta in self.connection_metadata.values()
            ),
            "clients": [
                {
                    "client_id": meta.get("client_id"),
                    "connected_at": meta.get("connected_at"),
                    "message_count": meta.get("message_count", 0)
                }
                for meta in self.connection_metadata.values()
            ]
        }

# Global connection manager instance
manager = ConnectionManager()
