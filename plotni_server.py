"""
PlotNi VPN Server v2.0 - Render Edition
Handles HTTP health checks + WebSocket tunnel on same port.

Deploy this on Render.com!
"""

import asyncio
import hashlib
import json
import os

try:
    from aiohttp import web
    import aiohttp
    HTTP_OK = True
except ImportError:
    HTTP_OK = False
    print("[!] Run: pip install aiohttp")
    exit(1)

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False
    print("[!] WARNING: Running in PLAINTEXT mode!")

# ─── CONFIG ────────────────────────────────────────────────────────────────────
HOST       = "0.0.0.0"
PORT       = int(os.environ.get("PORT", 9999))
SECRET_KEY = os.environ.get("PLOTNI_KEY", "plotni-secret-key-change-this")
# ───────────────────────────────────────────────────────────────────────────────

def derive_key(secret):
    return hashlib.sha256(secret.encode()).digest()

def encrypt(data, key):
    if not CRYPTO_OK: return data
    iv = os.urandom(16)
    c = AES.new(key, AES.MODE_CBC, iv)
    return iv + c.encrypt(pad(data, AES.block_size))

def decrypt(data, key):
    if not CRYPTO_OK: return data
    iv = data[:16]
    c = AES.new(key, AES.MODE_CBC, iv)
    return unpad(c.decrypt(data[16:]), AES.block_size)


async def relay_to_client(reader, ws, key):
    """Forward target → client."""
    try:
        while True:
            data = await reader.read(4096)
            if not data: break
            await ws.send_bytes(encrypt(data, key))
    except: pass


async def ws_handler(request):
    """Handle WebSocket VPN connections."""
    key = derive_key(SECRET_KEY)

    ws = web.WebSocketResponse(max_msg_size=10*1024*1024)
    await ws.prepare(request)

    peer = request.remote
    print(f"[+] Client connected: {peer}")
    writer = None

    try:
        # ── Receive destination ───────────────────────────────────────────────
        msg = await ws.receive()
        if msg.type != aiohttp.WSMsgType.BINARY:
            return ws

        info   = json.loads(decrypt(msg.data, key).decode())
        host   = info["host"]
        port   = int(info["port"])
        print(f"[→] Routing → {host}:{port}")

        # ── Connect to target ─────────────────────────────────────────────────
        reader, writer = await asyncio.open_connection(host, port)
        await ws.send_bytes(encrypt(b"OK", key))
        print(f"[✓] Tunnel open → {host}:{port}")

        # ── Relay ─────────────────────────────────────────────────────────────
        relay = asyncio.create_task(relay_to_client(reader, ws, key))

        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.BINARY:
                data = decrypt(msg.data, key)
                writer.write(data)
                await writer.drain()
            elif msg.type in (aiohttp.WSMsgType.ERROR, aiohttp.WSMsgType.CLOSE):
                break

        relay.cancel()

    except Exception as e:
        print(f"[-] Error ({peer}): {e}")
        try:
            await ws.send_bytes(encrypt(json.dumps({"error": str(e)}).encode(), key))
        except: pass
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except: pass
        print(f"[-] Disconnected: {peer}")

    return ws


async def health_handler(request):
    """Handle Render health checks (GET/HEAD requests)."""
    return web.Response(text="PlotNi VPN Server OK", status=200)


async def main():
    key  = derive_key(SECRET_KEY)
    mode = "AES-256-CBC" if CRYPTO_OK else "PLAINTEXT ⚠️"

    app = web.Application()
    app.router.add_get("/",    health_handler)   # health check
    app.router.add_get("/ws",  ws_handler)       # WebSocket endpoint
    app.router.add_head("/",   health_handler)   # Render HEAD health check

    print("=" * 50)
    print("  PlotNi VPN Server v2.0 — Render Edition")
    print("=" * 50)
    print(f"  Port     : {PORT}")
    print(f"  Mode     : {mode}")
    print(f"  Key hash : {hashlib.md5(key).hexdigest()[:8]}...")
    print("=" * 50)
    print(f"  WS endpoint: wss://your-app.onrender.com/ws")
    print("  Server running...\n")

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, HOST, PORT)
    await site.start()
    await asyncio.Future()  # run forever


if __name__ == "__main__":
    asyncio.run(main())
