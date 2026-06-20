import asyncio
import json
import os
import hashlib
import secrets
import time
import re
import base64
import stat
import subprocess
from datetime import datetime, timedelta
from urllib.parse import quote
from collections import deque, defaultdict

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
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
    "secret": os.environ.get("SECRET_KEY", "n0vatex-xray-secret-key-2026"),
    "xray_path": "./xray",
    "xray_config": "./xray_config.json"
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# دیتابیس‌های موقت در حافظه
LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()

CUSTOM_ADDRESSES: list = ["www.speedtest.net", "www.cloudflare.com"]
CUSTOM_ADDRESSES_LOCK = asyncio.Lock()

CUSTOM_DOMAIN: str = ""
CUSTOM_DOMAIN_LOCK = asyncio.Lock()

SESSION_COOKIE = "n0vatex_session"
SESSION_TTL = 60 * 60 * 24 * 7

stats = {"start_time": time.time(), "total_errors": 0}
error_logs: deque = deque(maxlen=50)
xray_process = None

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {"password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "admin"))}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

# --- توابع امنیتی و نشست‌ها ---
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

async def destroy_session(token: str | None):
    if token:
        async with SESSIONS_LOCK:
            SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token

def get_domain() -> str:
    return os.environ.get("RENDER_EXTERNAL_URL", os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost")).replace("https://", "").replace("http://", "")

# --- بخش دانلود و مدیریت هسته XRAY ---
def download_xray():
    if os.path.exists(CONFIG["xray_path"]):
        logger.info("Xray binary already exists.")
        return

    logger.info("Downloading Xray-core for Linux X86_64...")
    # دانلود مستقیم نسخه پایدار از سورس معتبر گیت‌هاب اکس‌ری
    url = "https://github.com/XTLS/Xray-core/releases/download/v24.11.30/Xray-linux-64.zip"
    
    import zipfile
    try:
        with httpx.Client() as client:
            r = client.get(url, follow_redirects=True)
            r.raise_for_status()
            with open("xray.zip", "wb") as f:
                f.write(r.content)
        
        with zipfile.ZipFile("xray.zip", "r") as zip_ref:
            zip_ref.extract("xray", path=".")
            
        os.remove("xray.zip")
        # دادن دسترسی اجرایی به باینری اکس‌ری
        st = os.stat(CONFIG["xray_path"])
        os.chmod(CONFIG["xray_path"], st.st_mode | stat.S_IEXEC)
        logger.info("Xray-core downloaded and prepared successfully.")
    except Exception as e:
        logger.error(f"Failed to download Xray-core: {e}")

async def generate_xray_config():
    """تولید کانفیگ داینامیک JSON برای هسته Xray شامل پروتکل‌های VLESS، VMess و Trojan"""
    domain = CUSTOM_DOMAIN if CUSTOM_DOMAIN else get_domain()
    
    # ساختاربندی پایه اینباندها (Inbounds)
    inbounds = []
    
    async with LINKS_LOCK:
        for uid, user in LINKS.items():
            if not user["active"]:
                continue
                
            # ۱. اینباند برای VLESS over WebSocket
            inbounds.append({
                "port": CONFIG["port"],
                "listen": "0.0.0.0",
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": user["uuid"], "level": 0}],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "ws",
                    "wsSettings": {
                        "path": f"/n0vatex-vless/{uid}"
                    }
                },
                "tag": f"vless-{uid}"
            })
            
            # ۲. اینباند برای VMess over WebSocket
            inbounds.append({
                "port": CONFIG["port"],
                "listen": "0.0.0.0",
                "protocol": "vmess",
                "settings": {
                    "clients": [{"id": user["uuid"], "level": 0, "alterId": 0}]
                },
                "streamSettings": {
                    "network": "ws",
                    "wsSettings": {
                        "path": f"/n0vatex-vmess/{uid}"
                    }
                },
                "tag": f"vmess-{uid}"
            })
            
            # ۳. اینباند برای Trojan over WebSocket
            inbounds.append({
                "port": CONFIG["port"],
                "listen": "0.0.0.0",
                "protocol": "trojan",
                "settings": {
                    "clients": [{"password": user["uuid"], "level": 0}]
                },
                "streamSettings": {
                    "network": "ws",
                    "wsSettings": {
                        "path": f"/n0vatex-trojan/{uid}"
                    }
                },
                "tag": f"trojan-{uid}"
            })

    # اگر کاربر فعالی نبود، یک اینباند دیفالت ست می‌کنیم تا اکس‌ری ارور ندهد
    if not inbounds:
        inbounds.append({
            "port": CONFIG["port"],
            "listen": "0.0.0.0",
            "protocol": "vless",
            "settings": {"clients": [{"id": "00000000-0000-0000-0000-000000000000", "level": 0}], "decryption": "none"},
            "streamSettings": {"network": "ws", "wsSettings": {"path": "/n0vatex-default"}},
            "tag": "default-inbound"
        })

    xray_json = {
        "log": {"loglevel": "warning"},
        "inbounds": inbounds,
        "outbounds": [
            {"protocol": "freedom", "settings": {}, "tag": "direct"},
            {"protocol": "blackhole", "settings": {}, "tag": "blocked"}
        ]
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
            
    logger.info("Starting Xray-core core engine...")
    try:
        xray_process = await asyncio.create_subprocess_exec(
            CONFIG["xray_path"], "-c", CONFIG["xray_config"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        logger.info(f"Xray-core is running successfully (PID: {xray_process.pid})")
    except Exception as e:
        logger.error(f"Failed to start Xray: {e}")

# --- سیستم مانیتورینگ حجم مصرفی فرضی (جایگزین لاگ‌گیر استاندارد) ---
async def xray_traffic_monitor():
    """شبیه‌ساز و پایشگر ترافیک؛ متصل به دیتابیس کاربران پنل"""
    while True:
        await asyncio.sleep(5)
        # در این بخش به دلیل عدم استفاده از ماژول پیچیده gRPC اکس‌ری، سیستم به طور خودکار
        # محدودیت‌های حجمی و انقضا را پایش کرده و کاربران متجاوز را غیرفعال می‌کند.
        async with LINKS_LOCK:
            need_restart = False
            for uid, user in LINKS.items():
                if user["active"]:
                    # چک کردن انقضای زمانی کانفیگ
                    if user["expiry"] and datetime.now() >= datetime.fromisoformat(user["expiry"]):
                        user["active"] = False
                        need_restart = True
                        logger.info(f"Inbound '{uid}' expired and was deactivated.")
                    # چک کردن سقف حجم مصرفی
                    if user["limit_bytes"] > 0 and user["used_bytes"] >= user["limit_bytes"]:
                        user["active"] = False
                        need_restart = True
                        logger.info(f"Inbound '{uid}' reached quota limit and was deactivated.")
            if need_restart:
                asyncio.create_task(restart_xray())

# --- ساخت متون و لینک‌های پروتکل‌ها ---
def make_vless(uid, uuid, label, addr, dom):
    p = f"/n0vatex-vless/{uid}"
    return f"vless://{uuid}@{addr}:443?encryption=none&security=tls&type=ws&host={dom}&path={quote(p)}&sni={dom}&fp=chrome#N0vatex_VLESS_{label}"

def make_vmess(uid, uuid, label, addr, dom):
    p = f"/n0vatex-vmess/{uid}"
    j = {"v": "2", "ps": f"N0vatex_VMess_{label}", "add": addr, "port": "443", "id": uuid, "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": dom, "path": p, "tls": "tls", "sni": dom, "fp": "chrome"}
    b = base64.b64encode(json.dumps(j).encode()).decode()
    return f"vmess://{b}"

def make_trojan(uid, uuid, label, addr, dom):
    p = f"/n0vatex-trojan/{uid}"
    return f"trojan://{uuid}@{addr}:443?security=tls&type=ws&host={dom}&path={quote(p)}&sni={dom}&fp=chrome#N0vatex_Trojan_{label}"

# --- شروع به کار برنامه ---
@app.on_event("startup")
async def startup():
    download_xray()
    # ساخت یک اینباند ادمین/پیش‌فرض در اولین اجرا
    async with LINKS_LOCK:
        if not LINKS:
            LINKS["admin_default"] = {
                "label": "N0vatex Admin",
                "uuid": "7a35c5c1-84a2-4a0b-8b9a-4f9e160e32b4",
                "limit_bytes": 0,
                "used_bytes": 0,
                "max_connections": 0,
                "created_at": datetime.now().isoformat(),
                "active": True,
                "expiry": ""
            }
    await restart_xray()
    asyncio.create_task(xray_traffic_monitor())

@app.get("/")
async def root():
    return RedirectResponse(url="/login")

# --- HTML TEMPLATES ---
@app.get("/login", response_class=HTMLResponse)
async def login_page():
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        return RedirectResponse(url="/login")
    return HTMLResponse(content=DASHBOARD_HTML)

# --- API ENDPOINTS ---
@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    password = str(body.get("password") or "")
    if hash_password(password) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid password")
    token = await create_session()
    resp = JSONResponse({"ok": True})
    resp.set_cookie(key=SESSION_COOKIE, value=token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.get("/stats")
async def get_stats(_=Depends(require_auth)):
    async with LINKS_LOCK:
        total_traffic = sum(u["used_bytes"] for u in LINKS.values())
        links_count = len(LINKS)
    return {
        "active_connections": len(psutil.net_connections()),
        "total_traffic_mb": round(total_traffic / (1024 * 1024), 2),
        "links_count": links_count,
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
    
    limit_bytes = int(limit_gb * 1024 * 1024 * 1024)
    expiry = (datetime.now() + timedelta(days=expiry_days)).isoformat() if expiry_days > 0 else ""
    
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": label, "uuid": u_uuid, "limit_bytes": limit_bytes,
            "used_bytes": 0, "created_at": datetime.now().isoformat(),
            "active": True, "expiry": expiry
        }
        
    await restart_xray()
    return {"ok": True}

@app.get("/api/links")
async def list_links(_=Depends(require_auth)):
    dom = CUSTOM_DOMAIN if CUSTOM_DOMAIN else get_domain()
    res = []
    async with LINKS_LOCK:
        for uid, u in LINKS.items():
            # ساخت انواع پروتکل‌ها به صورت داینامیک
            vless_l = make_vless(uid, u["uuid"], u["label"], dom, dom)
            vmess_l = make_vmess(uid, u["uuid"], u["label"], dom, dom)
            trojan_l = make_trojan(uid, u["uuid"], u["label"], dom, dom)
            
            res.append({
                "uid": uid, "label": u["label"], "limit_bytes": u["limit_bytes"],
                "used_bytes": u["used_bytes"], "active": u["active"], "expiry": u["expiry"],
                "vless": vless_l, "vmess": vmess_l, "trojan": trojan_l,
                "sub": f"https://{dom}/sub/{uid}"
            })
    return {"links": res}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        if uid in LINKS:
            LINKS.pop(uid)
    await restart_xray()
    return {"ok": True}

# --- سابسکریپشن هوشمند (تولید هر ۳ پروتکل هم‌زمان) ---
@app.get("/sub/{uid}")
async def subscription_endpoint(uid: str):
    async with LINKS_LOCK:
        u = LINKS.get(uid)
    if not u or not u["active"]:
        raise HTTPException(status_code=404, detail="Inbound link not found or inactive")
        
    dom = CUSTOM_DOMAIN if CUSTOM_DOMAIN else get_domain()
    async with CUSTOM_ADDRESSES_LOCK:
        addrs = list(CUSTOM_ADDRESSES)
        
    configs = []
    # قرار دادن دامنه اصلی سرور
    configs.append(make_vless(uid, u["uuid"], f"{u['label']}_SRV", dom, dom))
    configs.append(make_vmess(uid, u["uuid"], f"{u['label']}_SRV", dom, dom))
    configs.append(make_trojan(uid, u["uuid"], f"{u['label']}_SRV", dom, dom))
    
    # قرار دادن آی‌پی‌های تمیز کلودفلر
    for idx, addr in enumerate(addrs):
        configs.append(make_vless(uid, u["uuid"], f"{u['label']}_IP_{idx+1}", addr, dom))
        configs.append(make_vmess(uid, u["uuid"], f"{u['label']}_IP_{idx+1}", addr, dom))
        configs.append(make_trojan(uid, u["uuid"], f"{u['label']}_IP_{idx+1}", addr, dom))
        
    content = "\n".join(configs)
    b64_content = base64.b64encode(content.encode()).decode()
    return Response(content=b64_content, media_type="text/plain")

# --- رابط کاربری فرانت‌اند ---
LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>ورود به N0vatex panel</title>
    <style>
        body { background: #0b0b0e; color: #fff; font-family: Tahoma; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-card { background: #13131a; padding: 40px; border-radius: 16px; border: 1px solid #242432; width: 300px; text-align: center; }
        input { width: 100%; padding: 10px; margin: 15px 0; background: #1c1c24; border: 1px solid #2e2e3f; color: #fff; border-radius: 8px; box-sizing: border-box;}
        button { width: 100%; padding: 10px; background: #dc2626; border: none; color: white; border-radius: 8px; cursor: pointer; font-weight: bold; }
        button:hover { background: #b91c1c; }
    </style>
</head>
<body>
    <div class="login-card">
        <h2>N0vatex panel</h2>
        <p style="color: #666; font-size:12px;">مدیریت کانکشن‌های بر پایه هسته Xray</p>
        <input type="password" id="pass" placeholder="رمز عبور مدیریت">
        <button onclick="login()">ورود به پنل</button>
    </div>
    <script>
        async function login(){
            const r = await fetch('/api/login', {method:'POST', body: JSON.stringify({password: document.getElementById('pass').value})});
            if(r.ok) location.href='/dashboard';
            else alert('رمز عبور اشتباه است.');
        }
    </script>
</body>
</html>"""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <title>داشبرد هوشمند N0vatex</title>
    <style>
        body { background: #09090d; color: #e2e8f0; font-family: Tahoma; margin: 0; padding: 20px; }
        .grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 20px; }
        .card { background: #121218; padding: 20px; border-radius: 12px; border: 1px solid #1e1e2f; }
        .btn { background: #dc2626; color: #fff; padding: 8px 15px; border: none; border-radius: 6px; cursor: pointer; font-weight: bold;}
        table { width: 100%; border-collapse: collapse; margin-top: 20px; background: #121218; border-radius: 10px; overflow: hidden;}
        th, td { padding: 12px; text-align: right; border-bottom: 1px solid #1e1e2f; }
        th { background: #1a1a26; }
        .links-area button { margin-left: 5px; background: #2563eb; color: white; border: none; padding: 4px 8px; border-radius: 4px; cursor: pointer; font-size: 11px;}
    </style>
</head>
<body>
    <h1>داشبرد مدیریتی N0vatex panel 🚀</h1>
    <div class="grid">
        <div class="card"><h3>حجم مصرفی کل:</h3><p id="t-traffic">--</p></div>
        <div class="card"><h3>تعداد کانفیگ‌ها:</h3><p id="t-count">--</p></div>
        <div class="card"><h3>مدت زمان فعالیت سرور:</h3><p id="t-uptime">--</p></div>
        <div class="card"><h3>میزان مصرف پردازنده:</h3><p id="t-cpu">--</p></div>
    </div>

    <div class="card">
        <h2>ساخت کاربر جدید (VLESS, VMess, Trojan هم‌زمان)</h2>
        <input type="text" id="label" placeholder="نام کاربر (مثلاً: Ali)" style="padding: 8px; background: #1a1a24; border: 1px solid #2e2e3f; color: white; border-radius: 6px;">
        <input type="number" id="limit" placeholder="محدودیت حجم (GB) - 0 برای نامحدود" style="padding: 8px; background: #1a1a24; border: 1px solid #2e2e3f; color: white; border-radius: 6px;">
        <input type="number" id="days" placeholder="مدت اعتبار (روز)" style="padding: 8px; background: #1a1a24; border: 1px solid #2e2e3f; color: white; border-radius: 6px;">
        <button class="btn" onclick="createUser()">+ ایجاد کانفیگ</button>
    </div>

    <table>
        <thead>
            <tr>
                <th>نام کاربر</th>
                <th>حجم مصرفی</th>
                <th>دریافت کانفیگ‌های اختصاصی اکس‌ری</th>
                <th>عملیات</th>
            </tr>
        </thead>
        <tbody id="users-table"></tbody>
    </table>

    <script>
        async function getStats(){
            const r = await fetch('/stats'); const d = await r.json();
            document.getElementById('t-traffic').textContent = d.total_traffic_mb + " MB";
            document.getElementById('t-count').textContent = d.links_count;
            document.getElementById('t-uptime').textContent = d.uptime;
            document.getElementById('t-cpu').textContent = d.cpu_percent + "%";
        }
        async function loadUsers(){
            const r = await fetch('/api/links'); const d = await r.json();
            document.getElementById('users-table').innerHTML = d.links.map(u => `
                <tr>
                    <td><b>${u.label}</b></td>
                    <td>${(u.used_bytes/(1024*1024)).toFixed(1)} MB / ${u.limit_bytes===0 ? 'نامحدود' : (u.limit_bytes/(1024*1024*1024))+' GB'}</td>
                    <td class="links-area">
                        <button onclick="navigator.clipboard.writeText('${u.vless}');alert('VLESS کپی شد')">VLESS</button>
                        <button onclick="navigator.clipboard.writeText('${u.vmess}');alert('VMess کپی شد')" style="background:#10b981;">VMess</button>
                        <button onclick="navigator.clipboard.writeText('${u.trojan}');alert('Trojan کپی شد')" style="background:#7c3aed;">Trojan</button>
                        <button onclick="navigator.clipboard.writeText('${u.sub}');alert('لینک ساب کپی شد')" style="background:#f59e0b;">لینک ساب (Subscription)</button>
                    </td>
                    <td><button onclick="deleteUser('${u.uid}')" style="background:#ef4444; border:none; padding:5px 10px; color:white; border-radius:4px; cursor:pointer;">حذف</button></td>
                </tr>
            `).join('');
        }
        async function createUser(){
            await fetch('/api/links', {method:'POST', body: JSON.stringify({
                label: document.getElementById('label').value,
                limit_gb: document.getElementById('limit').value,
                expiry_days: document.getElementById('days').value
            })});
            loadUsers(); getStats();
        }
        async function deleteUser(uid){
            if(confirm('آیا مایل به حذف هستید؟')) {
                await fetch('/api/links/'+uid, {method:'DELETE'});
                loadUsers(); getStats();
            }
        }
        setInterval(getStats, 4000);
        getStats(); loadUsers();
    </script>
</body>
</html>"""

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=CONFIG["port"], reload=False)
