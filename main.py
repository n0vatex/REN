import asyncio
import json
import os
import hashlib
import secrets
import time
import base64
import stat
import subprocess
from datetime import datetime, timedelta
from urllib.parse import quote

from fastapi import FastAPI, Request, HTTPException, WebSocket, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging
import psutil

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("N0vatex-Xray-Gateway")

app = FastAPI(title="N0vatex panel", docs_url=None, redoc_url=None)

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "xray_port": 8005,  # پورت داخلی جدید برای جلوگیری از تداخل
    "secret": os.environ.get("SECRET_KEY", "n0vatex-xray-secret-key-2026"),
    "xray_path": "/tmp/xray", # انتقال به دایرکتوری لایه موقت لینوکس برای دور زدن محدودیت ریلی
    "xray_config": "/tmp/xray_config.json"
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()

CUSTOM_ADDRESSES: list = ["www.speedtest.net", "www.cloudflare.com"]
CUSTOM_ADDRESSES_LOCK = asyncio.Lock()

SESSION_COOKIE = "n0vatex_session"
SESSION_TTL = 60 * 60 * 24 * 7

stats = {"start_time": time.time(), "total_traffic_bytes": 0}
xray_process = None

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {"password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "admin"))}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

async def create_session() -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token

async def is_valid_session(token: str | None) -> bool:
    if not token:
        return False
    async with SESSIONS_LOCK:
        exp = SESSIONS.get(token)
        if exp is None or exp < time.time():
            SESSIONS.pop(token, None)
            return False
        return True

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

def get_domain() -> str:
    return os.environ.get("RENDER_EXTERNAL_URL", os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost")).replace("https://", "").replace("http://", "")

def download_xray():
    if os.path.exists(CONFIG["xray_path"]):
        logger.info("Xray binary already exists in /tmp.")
        return

    logger.info("Downloading Xray-core for Linux X86_64...")
    url = "https://github.com/XTLS/Xray-core/releases/download/v24.11.30/Xray-linux-64.zip"
    
    import zipfile
    try:
        with httpx.Client() as client:
            r = client.get(url, follow_redirects=True)
            r.raise_for_status()
            with open("/tmp/xray.zip", "wb") as f:
                f.write(r.content)
        
        with zipfile.ZipFile("/tmp/xray.zip", "r") as zip_ref:
            zip_ref.extract("xray", path="/tmp")
            
        os.remove("/tmp/xray.zip")
        # دادن دسترسی اجرایی همه‌جانبه لینوکسی در دایرکتوری آزاد /tmp
        os.chmod(CONFIG["xray_path"], stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
        logger.info("Xray-core successfully written and permitted in /tmp.")
    except Exception as e:
        logger.error(f"Failed to download Xray-core: {e}")

async def generate_xray_config():
    inbounds = []
    async with LINKS_LOCK:
        for uid, user in LINKS.items():
            if not user["active"]:
                continue
                
            # VLESS اینباند استاندارد لایه لوکال هوم
            inbounds.append({
                "port": CONFIG["xray_port"],
                "listen": "127.0.0.1",
                "protocol": "vless",
                "settings": {"clients": [{"id": user["uuid"], "level": 0}], "decryption": "none"},
                "streamSettings": {"network": "ws", "wsSettings": {"path": f"/n0vatex-vless/{uid}"}},
                "tag": f"vless-{uid}"
            })
            
            # VMess
            inbounds.append({
                "port": CONFIG["xray_port"],
                "listen": "127.0.0.1",
                "protocol": "vmess",
                "settings": {"clients": [{"id": user["uuid"], "level": 0}]},
                "streamSettings": {"network": "ws", "wsSettings": {"path": f"/n0vatex-vmess/{uid}"}},
                "tag": f"vmess-{uid}"
            })
            
            # Trojan
            inbounds.append({
                "port": CONFIG["xray_port"],
                "listen": "127.0.0.1",
                "protocol": "trojan",
                "settings": {"clients": [{"password": user["uuid"], "level": 0}]},
                "streamSettings": {"network": "ws", "wsSettings": {"path": f"/n0vatex-trojan/{uid}"}},
                "tag": f"trojan-{uid}"
            })

    if not inbounds:
        inbounds.append({
            "port": CONFIG["xray_port"],
            "listen": "127.0.0.1",
            "protocol": "vless",
            "settings": {"clients": [{"id": "00000000-0000-0000-0000-000000000000", "level": 0}], "decryption": "none"},
            "streamSettings": {"network": "ws", "wsSettings": {"path": "/n0vatex-default"}},
            "tag": "default-inbound"
        })

    xray_json = {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": [{"protocol": "freedom", "settings": {}}]
    }
    with open(CONFIG["xray_config"], "w") as f:
        json.dump(xray_json, f, indent=2)

async def restart_xray():
    global xray_process
    await generate_xray_config()
    if xray_process:
        try:
            xray_process.terminate()
            await xray_process.wait()
        except:
            pass
    try:
        xray_process = await asyncio.create_subprocess_exec(
            CONFIG["xray_path"], "-c", CONFIG["xray_config"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        logger.info(f"Xray-core bypass sequence initiated on internal port {CONFIG['xray_port']}")
    except Exception as e:
        logger.error(f"Xray execute failed: {e}")

# --- تونل زدن بایت به بایت بدون دستکاری هدر برای پایداری ۱۰۰ درصدی وب‌ساکت ---
async def forward_websocket(client_ws: WebSocket):
    await client_ws.accept()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", CONFIG["xray_port"])
    except Exception as e:
        logger.error(f"Bridge gateway broken: {e}")
        await client_ws.close()
        return

    async def client_to_xray():
        try:
            while True:
                msg = await client_ws.receive()
                if msg["type"] == "websocket.disconnect":
                    break
                data = msg.get("bytes") or (msg.get("text") or "").encode()
                if data:
                    stats["total_traffic_bytes"] += len(data)
                    writer.write(data)
                    await writer.drain()
        except:
            pass

    async def xray_to_client():
        try:
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                stats["total_traffic_bytes"] += len(data)
                await client_ws.send_bytes(data)
        except:
            pass

    task_up = asyncio.create_task(client_to_xray())
    task_down = asyncio.create_task(xray_to_client())
    await asyncio.wait({task_up, task_down}, return_when=asyncio.FIRST_COMPLETED)
    try:
        writer.close()
        await writer.wait_closed()
    except:
        pass

@app.websocket("/n0vatex-vless/{uid}")
async def ws_vless(websocket: WebSocket, uid: str):
    await forward_websocket(websocket)

@app.websocket("/n0vatex-vmess/{uid}")
async def ws_vmess(websocket: WebSocket, uid: str):
    await forward_websocket(websocket)

@app.websocket("/n0vatex-trojan/{uid}")
async def ws_trojan(websocket: WebSocket, uid: str):
    await forward_websocket(websocket)

# --- پایش مانیتورینگ حجم مصرفی ---
async def xray_traffic_monitor():
    while True:
        await asyncio.sleep(5)
        async with LINKS_LOCK:
            need_restart = False
            for uid, user in LINKS.items():
                if user["active"]:
                    if user["expiry"] and datetime.now() >= datetime.fromisoformat(user["expiry"]):
                        user["active"] = False
                        need_restart = True
                    if user["limit_bytes"] > 0 and user["used_bytes"] >= user["limit_bytes"]:
                        user["active"] = False
                        need_restart = True
            if need_restart:
                asyncio.create_task(restart_xray())

def make_vless(uid, uuid, label, addr, dom):
    p = f"/n0vatex-vless/{uid}"
    return f"vless://{uuid}@{addr}:443?encryption=none&security=tls&type=ws&host={dom}&path={quote(p)}&sni={dom}&fp=chrome#N0vatex_VLESS_{label}"

def make_vmess(uid, uuid, label, addr, dom):
    p = f"/n0vatex-vmess/{uid}"
    j = {"v": "2", "ps": f"N0vatex_VMess_{label}", "add": addr, "port": "443", "id": uuid, "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": dom, "path": p, "tls": "tls", "sni": dom, "fp": "chrome"}
    return f"vmess://{base64.b64encode(json.dumps(j).encode()).decode()}"

def make_trojan(uid, uuid, label, addr, dom):
    p = f"/n0vatex-trojan/{uid}"
    return f"trojan://{uuid}@{addr}:443?security=tls&type=ws&host={dom}&path={quote(p)}&sni={dom}&fp=chrome#N0vatex_Trojan_{label}"

@app.on_event("startup")
async def startup():
    download_xray()
    async with LINKS_LOCK:
        if not LINKS:
            LINKS["admin_default"] = {
                "label": "N0vatex_Admin", "uuid": "7a35c5c1-84a2-4a0b-8b9a-4f9e160e32b4",
                "limit_bytes": 0, "used_bytes": 0, "created_at": datetime.now().isoformat(), "active": True, "expiry": ""
            }
    await restart_xray()
    asyncio.create_task(xray_traffic_monitor())

@app.get("/")
async def root(): return RedirectResponse(url="/login")

@app.get("/login", response_class=HTMLResponse)
async def login_page(): return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    if not await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/login")
    return HTMLResponse(content=DASHBOARD_HTML)

@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    if hash_password(str(body.get("password") or "")) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid password")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    return {
        "active_connections": len(psutil.net_connections()),
        "total_traffic_mb": round(stats["total_traffic_bytes"] / (1024 * 1024), 2),
        "links_count": len(LINKS),
        "uptime": str(timedelta(seconds=int(time.time() - stats["start_time"]))),
        "cpu_percent": psutil.cpu_percent(),
        "memory_percent": psutil.virtual_memory().percent,
    }

@app.post("/api/links")
async def create_link(request: Request, _=Depends(require_auth)):
    body = await request.json()
    label = (body.get("label") or "User").strip()
    limit_gb = float(body.get("limit_gb") or 0)
    expiry_days = float(body.get("expiry_days") or 0)
    uid = secrets.token_hex(4)
    u_uuid = str(secrets.token_hex(8)) + "-" + str(secrets.token_hex(4)) + "-4" + str(secrets.token_hex(3)) + "-8" + str(secrets.token_hex(3)) + "-" + str(secrets.token_hex(12))
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": label, "uuid": u_uuid, "limit_bytes": int(limit_gb * 1024 * 1024 * 1024),
            "used_bytes": 0, "created_at": datetime.now().isoformat(), "active": True,
            "expiry": (datetime.now() + timedelta(days=expiry_days)).isoformat() if expiry_days > 0 else ""
        }
    await restart_xray()
    return {"ok": True}

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    dom = get_domain()
    res = []
    async with LINKS_LOCK:
        for uid, u in LINKS.items():
            res.append({
                "uid": uid, "label": u["label"], "limit_bytes": u["limit_bytes"], "used_bytes": u["used_bytes"], "active": u["active"],
                "vless": make_vless(uid, u["uuid"], u["label"], dom, dom),
                "vmess": make_vmess(uid, u["uuid"], u["label"], dom, dom),
                "trojan": make_trojan(uid, u["uuid"], u["label"], dom, dom),
                "sub": f"https://{dom}/sub/{uid}"
            })
    return {"links": res}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        if uid in LINKS: LINKS.pop(uid)
    await restart_xray()
    return {"ok": True}

@app.get("/sub/{uid}")
async def subscription_endpoint(uid: str):
    async with LINKS_LOCK:
        u = LINKS.get(uid)
    if not u or not u["active"]:
        raise HTTPException(status_code=404, detail="Inactive or not found")
    dom = get_domain()
    configs = [
        make_vless(uid, u["uuid"], u["label"], dom, dom),
        make_vmess(uid, u["uuid"], u["label"], dom, dom),
        make_trojan(uid, u["uuid"], u["label"], dom, dom)
    ]
    async with CUSTOM_ADDRESSES_LOCK:
        for idx, addr in enumerate(CUSTOM_ADDRESSES):
            configs.append(make_vless(uid, u["uuid"], f"{u['label']}_IP_{idx+1}", addr, dom))
            configs.append(make_vmess(uid, u["uuid"], f"{u['label']}_IP_{idx+1}", addr, dom))
            configs.append(make_trojan(uid, u["uuid"], f"{u['label']}_IP_{idx+1}", addr, dom))
    return Response(content=base64.b64encode("\n".join(configs).encode()).decode(), media_type="text/plain")

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="fa" dir="rtl"><head><meta charset="UTF-8"><title>ورود</title><style>body{background:#0b0b0e;color:#fff;font-family:Tahoma;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;}.card{background:#13131a;padding:40px;border-radius:16px;border:1px solid #242432;width:300px;text-align:center;}input{width:100%;padding:10px;margin:15px 0;background:#1c1c24;border:1px solid #2e2e3f;color:#fff;border-radius:8px;}button{width:100%;padding:10px;background:#dc2626;border:none;color:#fff;border-radius:8px;cursor:pointer;font-weight:bold;}</style></head>
<body><div class="card"><h2>N0vatex panel</h2><input type="password" id="pass" placeholder="رمز عبور"><button onclick="login()">ورود</button></div>
<script>async function login(){const r=await fetch('/api/login',{method:'POST',body:JSON.stringify({password:document.getElementById('pass').value})});if(r.ok)location.href='/dashboard';else alert('Error');}</script></body></html>"""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="fa" dir="rtl"><head><meta charset="UTF-8"><title>داشبرد</title><style>body{background:#09090d;color:#e2e8f0;font-family:Tahoma;margin:0;padding:20px;}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;margin-bottom:20px;}.card{background:#121218;padding:20px;border-radius:12px;border:1px solid #1e1e2f;}table{width:100%;border-collapse:collapse;margin-top:20px;background:#121218;}th,td{padding:12px;text-align:right;border-bottom:1px solid #1e1e2f;}th{background:#1a1a26;}button{background:#2563eb;color:#fff;border:none;padding:5px 10px;border-radius:4px;cursor:pointer;margin-left:4px;}</style></head>
<body><h1>N0vatex panel 🚀</h1><div class="grid"><div class="card"><h3>ترافیک کل:</h3><p id="t-traffic">--</p></div><div class="card"><h3>تعداد کانفیگ:</h3><p id="t-count">--</p></div><div class="card"><h3>Uptime:</h3><p id="t-uptime">--</p></div><div class="card"><h3>CPU:</h3><p id="t-cpu">--</p></div></div>
<div class="card"><h2>ساخت کاربر جدید</h2><input type="text" id="label" placeholder="نام"><input type="number" id="limit" placeholder="حجم GB"><input type="number" id="days" placeholder="روز"><button onclick="createUser()" style="background:#dc2626;">+ ایجاد</button></div>
<table><thead><tr><th>نام کاربر</th><th>حجم مصرفی</th><th>کانفیگ‌ها</th><th>عملیات</th></tr></thead><tbody id="users-table"></tbody></table>
<script>
async function getStats(){const r=await fetch('/stats');const d=await r.json();document.getElementById('t-traffic').textContent=d.total_traffic_mb+" MB";document.getElementById('t-count').textContent=d.links_count;document.getElementById('t-uptime').textContent=d.uptime;document.getElementById('t-cpu').textContent=d.cpu_percent+"%";}
async function loadUsers(){const r=await fetch('/api/links');const d=await r.json();document.getElementById('users-table').innerHTML=d.links.map(u=>`<tr><td><b>${u.label}</b></td><td>${(u.used_bytes/(1024*1024)).toFixed(1)} MB</td><td><button onclick="navigator.clipboard.writeText('${u.vless}');alert('کپی شد')">VLESS</button><button onclick="navigator.clipboard.writeText('${u.vmess}');alert('کپی شد')" style="background:#10b981;">VMess</button><button onclick="navigator.clipboard.writeText('${u.trojan}');alert('کپی شد')" style="background:#7c3aed;">Trojan</button><button onclick="navigator.clipboard.writeText('${u.sub}');alert('کپی شد')" style="background:#f59e0b;">Subscription</button></td><td><button onclick="deleteUser('${u.uid}')" style="background:#ef4444;">حذف</button></td></tr>`).join('');}
async function createUser
