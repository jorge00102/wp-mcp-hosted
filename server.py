import os, json, time, threading, queue, re, io
from typing import Dict, Any, Optional
from fastapi import FastAPI, Request, Header, HTTPException
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from sse_starlette.sse import EventSourceResponse
import requests

# =====================
# Configuración por ENV
# =====================
WP_BASE_URL = (os.environ.get("WP_BASE_URL", "").strip()).rstrip("/")
WP_USER     = (os.environ.get("WP_USER", "").strip())
WP_APP_PASS = (os.environ.get("WP_APP_PASSWORD", "").strip())
MCP_TOKEN   = (os.environ.get("MCP_TOKEN", "").strip())  # si vacío -> sin auth

# =====================
# App FastAPI + CORS
# =====================
app = FastAPI(title="WP Hosted MCP (HTTP/SSE)", redirect_slashes=False)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # si quieres, restringe a https://chat.openai.com y https://chatgpt.com
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS", "HEAD"],
    allow_headers=["*"],
)

# ---------------------
# Seguridad opcional
# ---------------------
def _norm_auth_header(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    return re.sub(r"\s+", " ", value).strip()

def assert_auth(auth: Optional[str]):
    if not MCP_TOKEN:
        return
    if not auth:
        raise HTTPException(status_code=401, detail="Unauthorized: missing Authorization header")
    auth = _norm_auth_header(auth)
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized: expected Bearer token")
    token = auth.split(" ", 1)[1]
    if token != MCP_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized: invalid token")

# ---------------------
# Cliente REST de WordPress
# ---------------------
def _ensure_wp_env():
    if not WP_BASE_URL or not WP_USER or not WP_APP_PASS:
        raise HTTPException(status_code=500, detail="WordPress env vars missing: WP_BASE_URL, WP_USER, WP_APP_PASSWORD")

def wp_request(method: str, path: str, json_body: Dict[str, Any] | None = None,
               files=None, params: Dict[str, Any] | None = None):
    _ensure_wp_env()
    if not path.startswith("/"):
        path = "/" + path
    url = f"{WP_BASE_URL}/wp-json/wp/v2{path}"
    if files is not None:
        resp = requests.request(method, url, auth=(WP_USER, WP_APP_PASS),
                                files=files, params=params, timeout=45)
    else:
        resp = requests.request(method, url, auth=(WP_USER, WP_APP_PASS),
                                json=json_body, params=params, timeout=45)
    if not resp.ok:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)
    ct = (resp.headers.get("Content-Type") or "")
    if ct.startswith("application/json"):
        return resp.json()
    return resp.text

# ---------------------
# TOOLS
# ---------------------
def tool_search(params: Dict[str, Any]):
    _ensure_wp_env()
    query = (params.get("query") or "").strip()
    top_k = int(params.get("top_k", 5))
    if not query:
        raise HTTPException(status_code=400, detail="Falta 'query'")
    url = f"{WP_BASE_URL}/wp-json/wp/v2/search"
    r = requests.get(url, params={"search": query, "per_page": max(1, min(top_k, 20))},
                     timeout=30, auth=(WP_USER, WP_APP_PASS))
    if not r.ok:
        raise HTTPException(status_code=r.status_code, detail=r.text)
    items = r.json()
    return {"results": [{"id": it.get("id"), "title": it.get("title") or "", "url": it.get("url"),
                          "type": it.get("type"), "subtype": it.get("subtype")} for it in items]}

def tool_fetch(params: Dict[str, Any]):
    url = (params.get("url") or "").strip()
    if not url or not re.match(r"^https?://", url, re.I):
        raise HTTPException(status_code=400, detail="URL inválida")
    r = requests.get(url, timeout=45)
    if not r.ok:
        raise HTTPException(status_code=r.status_code, detail=f"Fetch falló: {r.status_code}")
    ct = r.headers.get("Content-Type", "")
    try:
        text = r.text if "text/" in ct or "json" in ct else None
    except Exception:
        text = None
    return {"status": r.status_code, "content_type": ct, "text": text, "bytes_len": len(r.content)}

def tool_wp_create_page(params: Dict[str, Any]):
    title   = params.get("title") or "Nueva página"
    content = params.get("content") or ""
    status  = params.get("status", "publish")
    data = wp_request("POST", "/pages", {"title": title, "content": content, "status": status})
    return {"id": data.get("id"), "link": data.get("link"), "status": data.get("status")}

def tool_wp_update_page(params: Dict[str, Any]):
    page_id = params.get("id")
    if not page_id: raise HTTPException(status_code=400, detail="Falta 'id'")
    updates = {k: params[k] for k in ("title", "content", "status", "slug") if k in params}
    data = wp_request("POST", f"/pages/{page_id}", updates)
    return {"id": data.get("id"), "link": data.get("link"), "status": data.get("status")}

def tool_wp_delete_page(params: Dict[str, Any]):
    page_id = params.get("id")
    if not page_id: raise HTTPException(status_code=400, detail="Falta 'id'")
    force = bool(params.get("force", False))
    return wp_request("DELETE", f"/pages/{page_id}", params={"force": str(force).lower()})

def tool_wp_get_page(params: Dict[str, Any]):
    page_id = params.get("id")
    if not page_id: raise HTTPException(status_code=400, detail="Falta 'id'")
    return wp_request("GET", f"/pages/{page_id}")

def tool_wp_list_pages(params: Dict[str, Any]):
    p = {"page": int(params.get("page", 1)), "per_page": int(params.get("per_page", 10))}
    if params.get("search"): p["search"] = params["search"]
    return wp_request("GET", "/pages", params=p)

def tool_wp_create_post(params: Dict[str, Any]):
    title   = params.get("title") or "Nuevo post"
    content = params.get("content") or ""
    status  = params.get("status", "draft")
    payload = {"title": title, "content": content, "status": status}
    if params.get("categories"): payload["categories"] = params["categories"]
    if params.get("tags"): payload["tags"] = params["tags"]
    data = wp_request("POST", "/posts", payload)
    return {"id": data.get("id"), "link": data.get("link"), "status": data.get("status")}

def tool_wp_update_post(params: Dict[str, Any]):
    post_id = params.get("id")
    if not post_id: raise HTTPException(status_code=400, detail="Falta 'id'")
    updates = {k: params[k] for k in ("title","content","status","slug","categories","tags","featured_media") if k in params}
    data = wp_request("POST", f"/posts/{post_id}", updates)
    return {"id": data.get("id"), "link": data.get("link"), "status": data.get("status")}

def tool_wp_delete_post(params: Dict[str, Any]):
    post_id = params.get("id")
    if not post_id: raise HTTPException(status_code=400, detail="Falta 'id'")
    force = bool(params.get("force", False))
    return wp_request("DELETE", f"/posts/{post_id}", params={"force": str(force).lower()})

def tool_wp_get_post(params: Dict[str, Any]):
    post_id = params.get("id")
    if not post_id: raise HTTPException(status_code=400, detail="Falta 'id'")
    return wp_request("GET", f"/posts/{post_id}")

def tool_wp_list_posts(params: Dict[str, Any]):
    p = {"page": int(params.get("page", 1)), "per_page": int(params.get("per_page", 10))}
    if params.get("search"): p["search"] = params["search"]
    if params.get("categories"): p["categories"] = params["categories"]
    if params.get("tags"): p["tags"] = params["tags"]
    return wp_request("GET", "/posts", params=p)

def _download_bytes(url: str) -> bytes:
    r = requests.get(url, timeout=45)
    if not r.ok: raise HTTPException(status_code=400, detail=f"No se pudo descargar: {r.status_code}")
    return r.content

def tool_wp_upload_media(params: Dict[str, Any]):
    src = params.get("source_url"); filename = params.get("filename", "upload.bin")
    if not src: raise HTTPException(status_code=400, detail="Falta 'source_url'")
    content = _download_bytes(src)
    files = {'file': (filename, io.BytesIO(content), 'application/octet-stream')}
    data = wp_request("POST", "/media", files=files)
    return {"id": data.get("id"), "source_url": data.get("source_url")}

def tool_wp_set_featured_image(params: Dict[str, Any]):
    post_id = params.get("post_id"); media_id = params.get("media_id")
    if not post_id or not media_id: raise HTTPException(status_code=400, detail="Falta 'post_id' o 'media_id'")
    data = wp_request("POST", f"/posts/{post_id}", {"featured_media": media_id})
    return {"id": data.get("id"), "featured_media": data.get("featured_media")}

def tool_wp_create_category(params: Dict[str, Any]):
    name = params.get("name"); slug = params.get("slug"); parent = params.get("parent")
    if not name: raise HTTPException(status_code=400, detail="Falta 'name'")
    payload = {"name": name}; 
    if slug: payload["slug"]=slug
    if parent: payload["parent"]=parent
    return wp_request("POST", "/categories", payload)

def tool_wp_list_categories(params: Dict[str, Any]):
    p = {}; 
    if params.get("search"): p["search"]=params["search"]
    return wp_request("GET", "/categories", params=p)

def tool_wp_create_tag(params: Dict[str, Any]):
    name=params.get("name"); slug=params.get("slug")
    if not name: raise HTTPException(status_code=400, detail="Falta 'name'")
    payload={"name":name}; 
    if slug: payload["slug"]=slug
    return wp_request("POST", "/tags", payload)

def tool_wp_list_tags(params: Dict[str, Any]):
    p = {}; 
    if params.get("search"): p["search"]=params["search"]
    return wp_request("GET", "/tags", params=p)

def tool_wp_me(params: Dict[str, Any]):
    _ensure_wp_env()
    data = wp_request("GET", "/users/me")
    return {"id": data.get("id"), "name": data.get("name"), "url": data.get("url"), "roles": data.get("roles")}

# ---------------------
# Catálogo de TOOLS
# ---------------------
TOOLS: Dict[str, Dict[str, Any]] = {
    # Genéricas
    "search": {"description": "Buscar contenido por texto. Devuelve resultados con título y URL.",
               "schema": {"type": "object","properties": {"query":{"type":"string"},"top_k":{"type":"integer","minimum":1,"maximum":20}},
                          "required":["query"],"additionalProperties":False}, "handler": tool_search},
    "fetch": {"description": "Descargar una URL (GET).",
              "schema": {"type":"object","properties":{"url":{"type":"string"}},"required":["url"],"additionalProperties":False},
              "handler": tool_fetch},

    # Páginas
    "wp_create_page": {"description": "Crear página.","schema":{"type":"object","properties":{
        "title":{"type":"string"},"content":{"type":"string"},"status":{"type":"string","enum":["publish","draft","private"]}},
        "required":["title","content"],"additionalProperties":False}, "handler": tool_wp_create_page},
    "wp_update_page": {"description": "Actualizar página por ID.","schema":{"type":"object","properties":{
        "id":{"type":"integer"},"title":{"type":"string"},"content":{"type":"string"},
        "status":{"type":"string","enum":["publish","draft","private"]},"slug":{"type":"string"}},
        "required":["id"],"additionalProperties":False}, "handler": tool_wp_update_page},
    "wp_delete_page": {"description": "Eliminar página por ID.","schema":{"type":"object","properties":{
        "id":{"type":"integer"},"force":{"type":"boolean"}},"required":["id"],"additionalProperties":False},
        "handler": tool_wp_delete_page},
    "wp_get_page": {"description": "Obtener página por ID.","schema":{"type":"object","properties":{
        "id":{"type":"integer"}},"required":["id"],"additionalProperties":False}, "handler": tool_wp_get_page},
    "wp_list_pages": {"description": "Listar páginas.","schema":{"type":"object","properties":{
        "page":{"type":"integer"},"per_page":{"type":"integer"},"search":{"type":"string"}},
        "additionalProperties":False}, "handler": tool_wp_list_pages},

    # Posts
    "wp_create_post": {"description":"Crear post.","schema":{"type":"object","properties":{
        "title":{"type":"string"},"content":{"type":"string"},"status":{"type":"string","enum":["publish","draft","private"]},
        "categories":{"type":"array","items":{"type":"integer"}},"tags":{"type":"array","items":{"type":"integer"}}},
        "required":["title","content"],"additionalProperties":False}, "handler": tool_wp_create_post},
    "wp_update_post": {"description":"Actualizar post por ID.","schema":{"type":"object","properties":{
        "id":{"type":"integer"},"title":{"type":"string"},"content":{"type":"string"},"status":{"type":"string","enum":["publish","draft","private"]},
        "slug":{"type":"string"},"categories":{"type":"array","items":{"type":"integer"}},
        "tags":{"type":"array","items":{"type":"integer"}},"featured_media":{"type":"integer"}},
        "required":["id"],"additionalProperties":False}, "handler": tool_wp_update_post},
    "wp_delete_post": {"description":"Eliminar post por ID.","schema":{"type":"object","properties":{
        "id":{"type":"integer"},"force":{"type":"boolean"}},"required":["id"],"additionalProperties":False}, "handler": tool_wp_delete_post},
    "wp_get_post": {"description":"Obtener post por ID.","schema":{"type":"object","properties":{
        "id":{"type":"integer"}},"required":["id"],"additionalProperties":False}, "handler": tool_wp_get_post},
    "wp_list_posts": {"description":"Listar posts.","schema":{"type":"object","properties":{
        "page":{"type":"integer"},"per_page":{"type":"integer"},"search":{"type":"string"},
        "categories":{"type":"array","items":{"type":"integer"}},"tags":{"type":"array","items":{"type":"integer"}}},
        "additionalProperties":False}, "handler": tool_wp_list_posts},

    # Media
    "wp_upload_media": {"description":"Subir a Medios desde URL.","schema":{"type":"object","properties":{
        "source_url":{"type":"string"},"filename":{"type":"string"}},"required":["source_url"],"additionalProperties":False},
        "handler": tool_wp_upload_media},
    "wp_set_featured_image": {"description":"Asignar imagen destacada.","schema":{"type":"object","properties":{
        "post_id":{"type":"integer"},"media_id":{"type":"integer"}},"required":["post_id","media_id"],"additionalProperties":False},
        "handler": tool_wp_set_featured_image},

    # Taxonomías
    "wp_create_category": {"description":"Crear categoría.","schema":{"type":"object","properties":{
        "name":{"type":"string"},"slug":{"type":"string"},"parent":{"type":"integer"}},
        "required":["name"],"additionalProperties":False}, "handler": tool_wp_create_category},
    "wp_list_categories": {"description":"Listar categorías.","schema":{"type":"object","properties":{
        "search":{"type":"string"}},"additionalProperties":False}, "handler": tool_wp_list_categories},
    "wp_create_tag": {"description":"Crear tag.","schema":{"type":"object","properties":{
        "name":{"type":"string"},"slug":{"type":"string"}},"required":["name"],"additionalProperties":False},
        "handler": tool_wp_create_tag},
    "wp_list_tags": {"description":"Listar tags.","schema":{"type":"object","properties":{
        "search":{"type":"string"}},"additionalProperties":False}, "handler": tool_wp_list_tags},

    # Usuario
    "wp_me": {"description":"Usuario autenticado.","schema":{"type":"object","properties":{},"additionalProperties":False},
              "handler": tool_wp_me},
}

# ---------------------
# Endpoints de cortesía
# ---------------------
@app.get("/")
@app.post("/")
def root():
    return {"ok": True, "service": "wp-mcp", "endpoints": ["/mcp", "/mcp/call", "/healthz"]}

@app.get("/favicon.ico", status_code=204)
@app.get("/favicon.png", status_code=204)
@app.get("/favicon.svg", status_code=204)
def favicon():
    return PlainTextResponse("")

# Salud
@app.get("/healthz", response_class=PlainTextResponse)
@app.get("/healthz/", response_class=PlainTextResponse)
def healthz():
    return "ok"

# ---------------------
# /mcp schema (debug)
# ---------------------
@app.get("/mcp/schema")
@app.get("/mcp/schema/")
def mcp_schema(authorization: str | None = Header(default=None)):
    assert_auth(authorization)
    return {
        "type": "mcp",
        "transport": "sse",
        "tools": {name: {"description": t["description"], "schema": t["schema"]} for name, t in TOOLS.items()}
    }

# ---------------------
# HEAD/OPTIONS por si el validador los usa
# ---------------------
@app.options("/mcp")
@app.options("/mcp/")
def mcp_options():
    return PlainTextResponse("", status_code=204)

@app.head("/mcp")
@app.head("/mcp/")
def mcp_head():
    return PlainTextResponse("", status_code=204)

# ---------------------
# POST /mcp: SIEMPRE devuelve catálogo (ignora body)
# ---------------------
@app.post("/mcp")
@app.post("/mcp/")
async def mcp_probe(authorization: str | None = Header(default=None), request: Request = None):
    assert_auth(authorization)
    # leer body de forma tolerante (sin exigir JSON)
    try:
        await request.body()
    except Exception:
        pass
    return {
        "type": "mcp",
        "transport": "sse",
        "tools": [
            {"name": name, "description": t["description"], "schema": t["schema"],
             "input_schema": t["schema"], "inputSchema": t["schema"]}
            for name, t in TOOLS.items()
        ]
    }

# ---------------------
# GET /mcp – SSE (primer evento: tools con type/transport)
# ---------------------
@app.get("/mcp")
@app.get("/mcp/")
async def mcp_sse(request: Request, authorization: str | None = Header(default=None)):
    assert_auth(authorization)
    q: "queue.Queue[tuple[str,str]]" = queue.Queue()

    def producer():
        initial = {
            "type": "mcp",
            "transport": "sse",
            "tools": [
                {"name": name, "description": t["description"], "schema": t["schema"],
                 "input_schema": t["schema"], "inputSchema": t["schema"]}
                for name, t in TOOLS.items()
            ]
        }
        q.put(("tools", json.dumps(initial)))
        while True:
            time.sleep(15)
            q.put(("ping", json.dumps({"ts": time.time()})))

    threading.Thread(target=producer, daemon=True).start()

    async def event_generator():
        while True:
            if await request.is_disconnected():
                break
            try:
                ev, data = q.get(timeout=30)
                yield {"event": ev, "data": data}
            except queue.Empty:
                yield {"event": "ping", "data": json.dumps({"ts": time.time()})}

    return EventSourceResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
    )

# ---------------------
# Invocación de tools
# ---------------------
@app.post("/mcp/call")
@app.post("/mcp/call/")
async def mcp_call(req: Request, authorization: str | None = Header(default=None)):
    assert_auth(authorization)
    # aceptar body nulo o inválido y tratar de responder con error claro
    try:
        body = await req.json()
    except Exception:
        body = {}
    name   = body.get("name")
    params = body.get("arguments") or {}
    if not name:
        raise HTTPException(status_code=400, detail="Falta 'name'")
    tool = TOOLS.get(name)
    if not tool:
        raise HTTPException(status_code=404, detail=f"Tool '{name}' no existe")
    try:
        return {"ok": True, "result": tool["handler"](params)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Tool '{name}' error: {e}")


# (fin)
