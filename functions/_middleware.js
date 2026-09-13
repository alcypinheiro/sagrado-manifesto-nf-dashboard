// Cloudflare Pages Function — gate de acesso por PIN fixo compartilhado.
//
// Roda automaticamente na frente de TODA rota do projeto Pages (não precisa de
// domínio/Worker separado). Precisa de duas variáveis de ambiente configuradas
// no painel do Cloudflare (Pages project → Settings → Environment variables),
// marcadas como "Secret" e definidas tanto em Production quanto em Preview:
//
//   ACCESS_PIN     -> o código de acesso que as pessoas vão digitar
//   COOKIE_SECRET  -> uma string aleatória qualquer, só para assinar o cookie
//                     (evita que alguém forje o cookie sem saber o PIN)
//
// Depois de digitar o PIN correto uma vez, o navegador recebe um cookie
// assinado válido por 30 dias — não precisa digitar de novo até expirar ou
// limpar os cookies do site.

const COOKIE_NAME = "manifesto_access";
const COOKIE_MAX_AGE_SECONDS = 60 * 60 * 24 * 30; // 30 dias

async function sign(value, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function validCookie(cookieHeader, secret) {
  if (!cookieHeader) return false;
  const match = cookieHeader.match(new RegExp(`${COOKIE_NAME}=([^;]+)`));
  if (!match) return false;
  const [ts, sig] = decodeURIComponent(match[1]).split(".");
  if (!ts || !sig) return false;
  const age = Math.floor(Date.now() / 1000) - Number(ts);
  if (!Number.isFinite(age) || age < 0 || age > COOKIE_MAX_AGE_SECONDS) return false;
  const expected = await sign(ts, secret);
  return expected === sig;
}

function loginPage(error) {
  return `<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Acesso — Manifesto de Notas Fiscais</title>
<style>
  :root{color-scheme:light dark;--bg:#0b1220;--card:#121b30;--border:#22304d;--text:#eaf0fb;--muted:#93a2c2;--accent:#0998be;}
  *{box-sizing:border-box;}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
    background:var(--bg);color:var(--text);font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;padding:16px;}
  form{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:32px 28px;width:100%;max-width:340px;}
  h1{font-size:16px;margin:0 0 4px;}
  p{font-size:13px;color:var(--muted);margin:0 0 20px;}
  input{width:100%;padding:11px 12px;border-radius:8px;border:1px solid var(--border);
    background:#0b1220;color:var(--text);font-size:15px;letter-spacing:1px;}
  input:focus{outline:2px solid var(--accent);outline-offset:1px;}
  button{width:100%;margin-top:14px;padding:11px;border:0;border-radius:8px;
    background:var(--accent);color:#fff;font-size:14px;font-weight:600;cursor:pointer;}
  button:hover{filter:brightness(1.08);}
  .err{color:#ea4f3c;font-size:12.5px;margin:10px 0 0;}
</style></head>
<body>
  <form method="POST">
    <h1>Manifesto de Notas Fiscais — Rede Sagrado</h1>
    <p>Digite o código de acesso para ver o painel.</p>
    <input type="password" name="pin" placeholder="Código de acesso" autofocus required>
    ${error ? '<p class="err">Código incorreto. Tente novamente.</p>' : ""}
    <button type="submit">Entrar</button>
  </form>
</body></html>`;
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const secret = env.COOKIE_SECRET;
  const pin = env.ACCESS_PIN;

  if (!secret || !pin) {
    return new Response(
      "Configuração incompleta: defina ACCESS_PIN e COOKIE_SECRET nas variáveis de ambiente do projeto Pages.",
      { status: 500 }
    );
  }

  const cookieHeader = request.headers.get("Cookie");
  if (await validCookie(cookieHeader, secret)) {
    return next();
  }

  if (request.method === "POST") {
    const form = await request.formData();
    if (form.get("pin") === pin) {
      const ts = Math.floor(Date.now() / 1000).toString();
      const sig = await sign(ts, secret);
      const cookieValue = encodeURIComponent(`${ts}.${sig}`);
      const headers = new Headers({ Location: request.url });
      headers.append(
        "Set-Cookie",
        `${COOKIE_NAME}=${cookieValue}; Max-Age=${COOKIE_MAX_AGE_SECONDS}; Path=/; HttpOnly; Secure; SameSite=Lax`
      );
      return new Response(null, { status: 303, headers });
    }
    return new Response(loginPage(true), {
      status: 401,
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }

  return new Response(loginPage(false), {
    status: 401,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}
