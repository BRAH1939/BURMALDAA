const ALLOWED_ORIGINS = new Set([
  "https://brah1939.github.io",
  "https://burmaldaa.kozukhargg.workers.dev"
]);
const MAX_BYTES = 8 * 1024 * 1024;
const ALLOWED_TYPES = new Set(["image/jpeg", "image/png", "image/webp", "image/gif"]);
const VOTE_CATEGORIES = new Set(["burmalda-king", "panther-burmaldy"]);


function corsHeaders(origin) {
  const headers = {
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin"
  };
  if (ALLOWED_ORIGINS.has(origin)) headers["Access-Control-Allow-Origin"] = origin;
  return headers;
}
function json(data, status, origin) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...corsHeaders(origin) }
  });
}
function detectImage(bytes) {
  const b = bytes;
  if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "image/jpeg";
  if (b.length >= 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return "image/png";
  if (b.length >= 12 && String.fromCharCode(...b.slice(0, 4)) === "RIFF" && String.fromCharCode(...b.slice(8, 12)) === "WEBP") return "image/webp";
  if (b.length >= 6) {
    const sig = String.fromCharCode(...b.slice(0, 6));
    if (sig === "GIF87a" || sig === "GIF89a") return "image/gif";
  }
  return null;
}
async function sha256hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}
async function verifyTurnstile(token, secret, ip) {
  if (!token || !secret) return false;
  const form = new FormData();
  form.append("secret", secret);
  form.append("response", token);
  if (ip) form.append("remoteip", ip);
  const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: form });
  if (!response.ok) return false;
  const result = await response.json();
  return result.success === true;
}


// Durable Object: atomic duplicate-vote guard per device/category, plus IP quota.
export class VoteRegistry {
  constructor(state, env) { this.state = state; this.env = env; }
  async fetch(request) {
    const url = new URL(request.url);
    if (request.method !== "POST") return new Response("Method not allowed", { status: 405 });
    const body = await request.json().catch(() => null);
    if (!body) return new Response("Bad JSON", { status: 400 });

    if (url.pathname === "/claim") {
      const { category, deviceHash, ipHash, day, claimId } = body;
      return this.state.blockConcurrencyWhile(async () => {
        const deviceKey = `voted:${category}:${deviceHash}`;
        const ipKey = `ipquota:${category}:${ipHash}:${day}`;
        const existing = await this.state.storage.get(deviceKey);
        if (existing) return new Response(JSON.stringify({ error: "device_already_voted" }), { status: 409 });
        const ipCount = (await this.state.storage.get(ipKey)) || 0;
        if (ipCount >= 5) return new Response(JSON.stringify({ error: "ip_quota" }), { status: 429 });
        await this.state.storage.put(deviceKey, { claimId, ipKey, createdAt: Date.now() });
        await this.state.storage.put(ipKey, ipCount + 1);
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      });
    }

    if (url.pathname === "/rollback") {
      const { category, deviceHash, claimId } = body;
      return this.state.blockConcurrencyWhile(async () => {
        const deviceKey = `voted:${category}:${deviceHash}`;
        const record = await this.state.storage.get(deviceKey);
        if (record && record.claimId === claimId) {
          const ipCount = (await this.state.storage.get(record.ipKey)) || 0;
          await this.state.storage.delete(deviceKey);
          if (ipCount <= 1) await this.state.storage.delete(record.ipKey);
          else await this.state.storage.put(record.ipKey, ipCount - 1);
        }
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      });
    }
    return new Response("Not found", { status: 404 });
  }
}


export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    if (request.method === "OPTIONS") {
      if (!ALLOWED_ORIGINS.has(origin)) return new Response(null, { status: 403 });
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }
    const url = new URL(request.url);
    if (request.method !== "POST" || !["/upload", "/vote"].includes(url.pathname)) return json({ error: "Not found" }, 404, origin);
    if (!ALLOWED_ORIGINS.has(origin)) return json({ error: "Origin not allowed" }, 403, origin);
    if (!env.DISCORD_WEBHOOK_URL) return json({ error: "Webhook не настроен." }, 500, origin);

    if (url.pathname === "/vote") {
      let claim = null;
      try {
        const body = await request.json();
        if (String(body.website || "").trim()) return json({ ok: true }, 200, origin);
        const usernameRaw = String(body.discordUsername || "").trim();
        const candidateRaw = String(body.candidate || "").trim();
        const category = String(body.category || "");
        const deviceId = String(body.deviceId || "");
        const token = String(body.turnstileToken || "");
        const username = usernameRaw.replace(/[\r\n@]/g, " ").slice(0, 80);
        const candidate = candidateRaw.replace(/[\r\n@]/g, " ").slice(0, 80);
        if (!username || !candidate || usernameRaw.length > 80 || candidateRaw.length > 80) return json({ error: "Заполни Discord-ник и имя номинанта (до 80 символов)." }, 400, origin);
        if (!VOTE_CATEGORIES.has(category)) return json({ error: "Неизвестная номинация." }, 400, origin);
        if (!/^[a-zA-Z0-9-]{20,120}$/.test(deviceId)) return json({ error: "Не удалось идентифицировать устройство. Разреши localStorage и обнови страницу." }, 400, origin);
        if (!env.TURNSTILE_SECRET_KEY) return json({ error: "Turnstile не настроен на сервере." }, 500, origin);
        const ip = request.headers.get("CF-Connecting-IP") || "";
        const captchaOK = await verifyTurnstile(token, env.TURNSTILE_SECRET_KEY, ip);
        if (!captchaOK) return json({ error: "Проверка антибота не пройдена. Пройди Turnstile ещё раз." }, 403, origin);
        if (!env.VOTE_REGISTRY) return json({ error: "Защита голосования не подключена (VOTE_REGISTRY)." }, 500, origin);

        const deviceHash = await sha256hex(deviceId);
        const ipHash = await sha256hex(ip || "no-ip");
        const day = new Date().toISOString().slice(0, 10);
        const claimId = crypto.randomUUID();
        const guard = env.VOTE_REGISTRY.get(env.VOTE_REGISTRY.idFromName("burdosley-vote-guard"));
        const claimResponse = await guard.fetch("https://vote-guard/claim", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ category, deviceHash, ipHash, day, claimId })
        });
        if (!claimResponse.ok) {
          const claimError = await claimResponse.json().catch(() => ({}));
          if (claimResponse.status === 409) return json({ error: "С этого устройства в этой номинации уже голосовали." }, 409, origin);
          if (claimResponse.status === 429) return json({ error: "Слишком много голосов с этого IP за сегодня. Попробуй завтра." }, 429, origin);
          return json({ error: claimError.error || "Не удалось зарегистрировать голос." }, 500, origin);
        }
        claim = { category, deviceHash, claimId, guard };
        const categoryLabel = category === "burmalda-king" ? "бурмалда-кинг" : "пантера бурмалды";
        const discordResponse = await fetch(env.DISCORD_WEBHOOK_URL, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            content: `🗳️ **Новая номинация — БУРДОСЛЕЙ**\nНоминация: **${categoryLabel}**\nDiscord: ${username}\nВыбор: **${candidate}**`,
            allowed_mentions: { parse: [] }
          })
        });
        if (!discordResponse.ok) {
          await claim.guard.fetch("https://vote-guard/rollback", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ category: claim.category, deviceHash: claim.deviceHash, claimId: claim.claimId }) });
          claim = null;
          console.error("Discord webhook returned status", discordResponse.status);
          return json({ error: "Discord не принял голос. Попробуй позже." }, 502, origin);
        }
        return json({ ok: true }, 200, origin);
      } catch (err) {
        console.error("Vote error", err);
        if (claim) {
          try { await claim.guard.fetch("https://vote-guard/rollback", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ category: claim.category, deviceHash: claim.deviceHash, claimId: claim.claimId }) }); } catch (_) {}
        }
        return json({ error: "Ошибка обработки голоса. Попробуй позже." }, 500, origin);
      }
    }


    const declaredLength = Number(request.headers.get("Content-Length") || 0);
    if (declaredLength > MAX_BYTES + 100_000) return json({ error: "Файл слишком большой. Максимум 8 МБ." }, 413, origin);
    try {
      const form = await request.formData();
      if (String(form.get("website") || "").trim()) return json({ ok: true }, 200, origin);
      const file = form.get("photo");
      if (!(file instanceof File)) return json({ error: "Фотография не найдена." }, 400, origin);
      if (file.size < 1 || file.size > MAX_BYTES) return json({ error: "Файл должен быть не больше 8 МБ." }, 400, origin);
      const bytes = new Uint8Array(await file.arrayBuffer());
      const mime = detectImage(bytes);
      if (!mime || !ALLOWED_TYPES.has(mime)) return json({ error: "Файл не является поддерживаемым изображением." }, 400, origin);
      const sender = String(form.get("sender") || "Анонимно").replace(/[\r\n@]/g, " ").trim().slice(0, 50) || "Анонимно";
      const ext = ({ "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif" })[mime];
      const discordForm = new FormData();
      discordForm.append("payload_json", JSON.stringify({ content: `📷 **Новая фотография с сайта BURMALDAA**\nОтправитель: ${sender}`, allowed_mentions: { parse: [] } }));
      discordForm.append("files[0]", new Blob([bytes], { type: mime }), `burmaldaa-${Date.now()}.${ext}`);
      const discordResponse = await fetch(env.DISCORD_WEBHOOK_URL, { method: "POST", body: discordForm });
      if (!discordResponse.ok) {
        console.error("Discord webhook returned status", discordResponse.status);
        return json({ error: "Discord не принял фотографию. Попробуй позже." }, 502, origin);
      }
      return json({ ok: true }, 200, origin);
    } catch (err) {
      console.error("Upload error", err);
      return json({ error: "Ошибка обработки фотографии." }, 500, origin);
    }
  }
};
