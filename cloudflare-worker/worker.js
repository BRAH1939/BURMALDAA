
const ALLOWED_ORIGINS = new Set([
  "https://brah1939.github.io",
  "https://burmaldaa.kozukhargg.workers.dev"
]);

const MAX_BYTES = 8 * 1024 * 1024;
const ALLOWED_TYPES = new Set([
  "image/jpeg",
  "image/png",
  "image/webp",
  "image/gif"
]);

function corsHeaders(origin) {
  const headers = {
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin"
  };

  if (ALLOWED_ORIGINS.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
  }

  return headers;
}

function json(data, status, origin) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...corsHeaders(origin)
    }
  });
}

function detectImage(bytes) {
  const b = bytes;

  // JPEG
  if (
    b.length >= 3 &&
    b[0] === 0xff &&
    b[1] === 0xd8 &&
    b[2] === 0xff
  ) {
    return "image/jpeg";
  }

  // PNG
  if (
    b.length >= 8 &&
    b[0] === 0x89 &&
    b[1] === 0x50 &&
    b[2] === 0x4e &&
    b[3] === 0x47
  ) {
    return "image/png";
  }

  // WEBP
  if (
    b.length >= 12 &&
    String.fromCharCode(...b.slice(0, 4)) === "RIFF" &&
    String.fromCharCode(...b.slice(8, 12)) === "WEBP"
  ) {
    return "image/webp";
  }

  // GIF
  if (b.length >= 6) {
    const sig = String.fromCharCode(...b.slice(0, 6));

    if (sig === "GIF87a" || sig === "GIF89a") {
      return "image/gif";
    }
  }

  return null;
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";

    // CORS preflight
    if (request.method === "OPTIONS") {
      if (!ALLOWED_ORIGINS.has(origin)) {
        return new Response(null, { status: 403 });
      }

      return new Response(null, {
        status: 204,
        headers: corsHeaders(origin)
      });
    }

    const url = new URL(request.url);

    // Разрешённые маршруты
    if (
      request.method !== "POST" ||
      !["/upload", "/vote"].includes(url.pathname)
    ) {
      return json({ error: "Not found" }, 404, origin);
    }

    // Проверка домена сайта
    if (!ALLOWED_ORIGINS.has(origin)) {
      return json({ error: "Origin not allowed" }, 403, origin);
    }

    // Проверка webhook
    if (!env.DISCORD_WEBHOOK_URL) {
      return json({ error: "Webhook не настроен." }, 500, origin);
    }

    // ==================================================
    // ГОЛОСОВАНИЕ
    // ==================================================
    if (url.pathname === "/vote") {
      try {
        const body = await request.json();

        // Honeypot
        if (String(body.website || "").trim()) {
          return json({ ok: true }, 200, origin);
        }

        const username = String(body.discordUsername || "").trim();
        const candidate = String(body.candidate || "").trim();

        // Список участников — добавляй новых сюда
        const candidates = [
          "LIBI"
        ];

        if (
          !username ||
          username.length > 80 ||
          /[\r\n]/.test(username)
        ) {
          return json(
            { error: "Укажи корректный Discord-юзернейм." },
            400,
            origin
          );
        }

        if (!candidates.includes(candidate)) {
          return json(
            { error: "Такого кандидата нет в списке." },
            400,
            origin
          );
        }

        const discordResponse = await fetch(env.DISCORD_WEBHOOK_URL, {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            content:
              `🗳️ **Новый голос**\n` +
              `Discord: ${username}\n` +
              `Голос за: **${candidate}**`,
            allowed_mentions: {
              parse: []
            }
          })
        });

        if (!discordResponse.ok) {
          console.error(
            "Discord webhook returned status:",
            discordResponse.status
          );

          return json(
            { error: "Discord не принял голос. Попробуй позже." },
            502,
            origin
          );
        }

        return json({ ok: true }, 200, origin);

      } catch (err) {
        console.error("Vote error:", err);

        return json(
          { error: "Не удалось обработать голос." },
          400,
          origin
        );
      }
    }

    // ==================================================
    // ОТПРАВКА ФОТОГРАФИЙ
    // ==================================================

    const declaredLength = Number(
      request.headers.get("Content-Length") || 0
    );

    if (declaredLength > MAX_BYTES + 100_000) {
      return json(
        { error: "Файл слишком большой. Максимум 8 МБ." },
        413,
        origin
      );
    }

    try {
      const form = await request.formData();

      // Honeypot для ботов
      if (String(form.get("website") || "").trim()) {
        return json({ ok: true }, 200, origin);
      }

      const file = form.get("photo");

      if (!(file instanceof File)) {
        return json(
          { error: "Фотография не найдена." },
          400,
          origin
        );
      }

      if (file.size < 1 || file.size > MAX_BYTES) {
        return json(
          { error: "Файл должен быть не больше 8 МБ." },
          400,
          origin
        );
      }

      const bytes = new Uint8Array(await file.arrayBuffer());
      const mime = detectImage(bytes);

      if (!mime || !ALLOWED_TYPES.has(mime)) {
        return json(
          { error: "Файл не является поддерживаемым изображением." },
          400,
          origin
        );
      }

      const sender = String(form.get("sender") || "Анонимно")
        .replace(/[\r\n@]/g, " ")
        .trim()
        .slice(0, 50) || "Анонимно";

      const ext = {
        "image/jpeg": "jpg",
        "image/png": "png",
        "image/webp": "webp",
        "image/gif": "gif"
      }[mime];

      const discordForm = new FormData();

      discordForm.append(
        "payload_json",
        JSON.stringify({
          content:
            `📷 **Новая фотография с сайта BURMALDAA**\n` +
            `Отправитель: ${sender}`,
          allowed_mentions: {
            parse: []
          }
        })
      );

      discordForm.append(
        "files[0]",
        new Blob([bytes], { type: mime }),
        `burmaldaa-${Date.now()}.${ext}`
      );

      const discordResponse = await fetch(env.DISCORD_WEBHOOK_URL, {
        method: "POST",
        body: discordForm
      });

      if (!discordResponse.ok) {
        console.error(
          "Discord webhook returned status:",
          discordResponse.status
        );

        return json(
          { error: "Discord не принял фотографию. Попробуй позже." },
          502,
          origin
        );
      }

      return json({ ok: true }, 200, origin);

    } catch (err) {
      console.error("Upload error:", err);

      return json(
        { error: "Ошибка обработки фотографии." },
        500,
        origin
      );
    }
  }
};
