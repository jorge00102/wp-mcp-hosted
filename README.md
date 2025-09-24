# WP Hosted MCP (HTTP/SSE) — listo para Agent mode


## Variables de entorno
- `WP_BASE_URL` = https://tu-wordpress.com
- `WP_USER` = usuario_admin
- `WP_APP_PASSWORD` = xxxx xxxx xxxx xxxx (Application Password)
- `MCP_TOKEN` = token-largo-seguro


## Endpoints
- `GET /healthz` y `/healthz/` → ok
- `GET /mcp` y `/mcp/` → SSE (anuncia tools y keepalive)
- `GET /mcp/schema` → inspección de tools/schemas
- `POST /mcp/call` y `/mcp/call/` → invocar tool: { name, arguments }


## Conexión en ChatGPT → Agent mode
1. Add tool → Hosted MCP (o Custom HTTP MCP)
2. Server URL: `https://TU-SERVICIO.onrender.com/mcp` *(sin slash final)*
3. Headers: `Authorization: Bearer <MCP_TOKEN>`


## Pruebas rápidas
```bash
curl -s https://TU-SERVICIO.onrender.com/healthz
curl -N -H "Authorization: Bearer $MCP_TOKEN" https://TU-SERVICIO.onrender.com/mcp
curl -X POST https://TU-SERVICIO.onrender.com/mcp/call \
-H "Authorization: Bearer $MCP_TOKEN" -H "Content-Type: application/json" \
-d '{"name":"wp_me","arguments":{}}'
