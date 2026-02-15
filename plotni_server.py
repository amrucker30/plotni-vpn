"""
██████╗ ██╗      ██████╗ ████████╗███╗   ██╗██╗
██╔══██╗██║     ██╔═══██╗╚══██╔══╝████╗  ██║██║
██████╔╝██║     ██║   ██║   ██║   ██╔██╗ ██║██║
██╔═══╝ ██║     ██║   ██║   ██║   ██║╚██╗██║██║
██║     ███████╗╚██████╔╝   ██║   ██║ ╚████║██║
╚═╝     ╚══════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═══╝╚═╝
         PlotNi VPN — Server v1.0
         WebSocket + AES-256 Encrypted Tunnel

Usage:
    pip install websockets pycryptodome
    python plotni_server.py

Then expose with Cloudflare:
    cloudflared tunnel --url ws://localhost:9999
"""

import asyncio
import hashlib
import json
import os
import socket

try:
    import websockets
except ImportError:
    print("[!] Run: pip install websockets")
    exit(1)

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False
    print("[!] Run: pip install pycryptodome")
    print("[!] Running in PLAINTEXT mode — not secure!\n")

# ─── CONFIG ────────────────────────────────────────────────────────────────────
HOST       = "0.0.0.0"
PORT       = int(os.environ.get("PORT", 9999))  # Railway sets this automatically
SECRET_KEY = os.environ.get("PLOTNI_KEY", "plotni-secret-key-change-this")
# ───────────────────────────────────────────────────────────────────────────────

def derive_key(secret: str) -> bytes:
    return hashlib.sha256(secret.encode()).digest()

def encrypt(data: bytes, key: bytes) -> bytes:
    if not CRYPTO_OK:
        return data
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(data, AES.block_size))

def decrypt(data: bytes, key: bytes) -> bytes:
    if not CRYPTO_OK:
        return data
    iv = data[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data[16:]), AES.block_size)


async def relay_to_client(reader: asyncio.StreamReader, ws, key: bytes):
    """Forward data from target → encrypt → send to client via WebSocket."""
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            encrypted = encrypt(data, key)
            await ws.send(encrypted)
    except Exception:
        pass


async def handle_client(ws):
    """Handle a single PlotNi VPN client connection over WebSocket."""
    key = derive_key(SECRET_KEY)
    peer = ws.remote_address
    print(f"[+] Client connected: {peer[0]}:{peer[1]}")

    reader = None
    writer = None

    try:
        # ── Step 1: Receive encrypted destination ─────────────────────────────
        enc_request = await ws.recv()
        request     = decrypt(enc_request, key).decode()
        info        = json.loads(request)
        target_host = info["host"]
        target_port = int(info["port"])
        print(f"[→] Routing → {target_host}:{target_port}")

        # ── Step 2: Connect to target ─────────────────────────────────────────
        reader, writer = await asyncio.open_connection(target_host, target_port)

        # ── Step 3: Send OK to client ─────────────────────────────────────────
        await ws.send(encrypt(b"OK", key))
        print(f"[✓] Tunnel open → {target_host}:{target_port}")

        # ── Step 4: Relay in both directions ──────────────────────────────────
        relay_task = asyncio.create_task(relay_to_client(reader, ws, key))

        async for message in ws:
            if isinstance(message, bytes):
                data = decrypt(message, key)
                writer.write(data)
                await writer.drain()

        relay_task.cancel()

    except Exception as e:
        print(f"[-] Error ({peer}): {e}")
        try:
            err = encrypt(json.dumps({"error": str(e)}).encode(), key)
            await ws.send(err)
        except Exception:
            pass
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        print(f"[-] Client disconnected: {peer[0]}:{peer[1]}")


async def main():
    key = derive_key(SECRET_KEY)
    mode = "AES-256-CBC" if CRYPTO_OK else "PLAINTEXT ⚠️"

    print("=" * 55)
    print("  ██████╗ ██╗      ██████╗ ████████╗███╗  ██╗██╗")
    print("  ██╔══██╗██║     ██╔═══██╗╚══██╔══╝████╗ ██║██║")
    print("  ██████╔╝██║     ██║   ██║   ██║   ██╔██╗██║██║")
    print("  ██╔═══╝ ██║     ██║   ██║   ██║   ██║╚████║██║")
    print("  ██║     ███████╗╚██████╔╝   ██║   ██║ ╚███║██║")
    print("  ╚═╝     ╚══════╝ ╚═════╝    ╚═╝   ╚═╝  ╚══╝╚═╝")
    print("=" * 55)
    print(f"  Mode     : {mode}")
    print(f"  Listening: ws://{HOST}:{PORT}")
    print(f"  Key hash : {hashlib.md5(key).hexdigest()[:8]}...")
    print("=" * 55)
    print("\n  Next step — expose with Cloudflare:")
    print(f"  $ cloudflared tunnel --url ws://localhost:{PORT}\n")

    async with websockets.serve(handle_client, HOST, PORT):
        print(f"  PlotNi VPN Server running... (Ctrl+C to stop)\n")
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    asyncio.run(main())
