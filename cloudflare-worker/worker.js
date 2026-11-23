const ALLOWED_ORIGINS = new Set([
  "https://brah1939.github.io",
  "https://burmaldaa.kozukhargg.workers.dev"
]);

const MAX_BYTES = 8 * 1024 * 1024;
const MAX_VOTES_PER_IP_PER_DAY = 5;

const ALLOWED_TYPES = new Set([
  "image/jpeg",
  "image/png",
  "image/webp",
  "image/gif"
]);

const VOTE_CATEGORIES = new Set([
  "burmalda-king",
  "panther-burmaldy"
]);

// ======================================================
// CORS
// ======================================================

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

function internalJson(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json"
    }
  });
}

// ======================================================
// IMAGE VALIDATION
// ======================================================

function detectImage(bytes) {
  // JPEG
  if (
    bytes.length >= 3 &&
    bytes[0] === 0xff &&
    bytes[1] === 0xd8 &&
    bytes[2] === 0xff
  ) {
    return "image/jpeg";
  }

  // PNG
  if (
    bytes.length >= 8 &&
    bytes[0] === 0x89 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x4e &&
    bytes[3] === 0x47
  ) {
    return "image/png";
  }

  // WebP
  if (
    bytes.length >= 12 &&
    String.fromCharCode(...bytes.slice(0, 4)) === "RIFF" &&
    String.fromCharCode(...bytes.slice(8, 12)) === "WEBP"
  ) {
    return "image/webp";
  }

  // GIF
  if (bytes.length >= 6) {
    const signature = String.fromCharCode(
      ...bytes.slice(0, 6)
    );

    if (signature === "GIF87a" || signature === "GIF89a") {
      return "image/gif";
    }
  }

  return null;
}

// ======================================================
// HASH
// ======================================================

async function sha256hex(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );

  return [...new Uint8Array(digest)]
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

// ======================================================
// TURNSTILE
// ======================================================

async function verifyTurnstile(token, secret, ip) {
  if (!secret) {
    return {
      success: false,
      errorCodes: ["missing-secret"]
    };
  }

  if (!token) {
    return {
      success: false,
      errorCodes: ["missing-token"]
    };
  }

  try {
    const params = new URLSearchParams();

    params.set("secret", secret);
    params.set("response", token);

    if (ip) {
      params.set("remoteip", ip);
    }

    const response = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: params.toString(),
        signal: AbortSignal.timeout(10000)
      }
    );

    const rawText = await response.text();

    let result = null;

    try {
      result = JSON.parse(rawText);
    } catch {
      result = null;
    }

    console.log("TURNSTILE DEBUG:", {
      httpStatus: response.status,
      responseBody: rawText.slice(0, 1000)
    });

    if (!response.ok) {
      return {
        success: false,
        errorCodes: [
          `siteverify-http-${response.status}`
        ]
      };
    }

    if (!result) {
      return {
        success: false,
        errorCodes: ["invalid-siteverify-response"]
      };
    }

    return {
      success: result.success === true,
      errorCodes: result["error-codes"] || [],
      hostname: result.hostname || ""
    };

  } catch (error) {
    console.error("Turnstile connection error:", {
      name: error?.name,
      message: error?.message
    });

    return {
      success: false,
      errorCodes: [
        error?.name === "TimeoutError"
          ? "siteverify-timeout"
          : "siteverify-network-error"
      ]
    };
  }
}

function turnstileFailureMessage(errorCodes = []) {
  const codes = new Set(errorCodes);

  if (
    codes.has("missing-secret") ||
    codes.has("missing-input-secret")
  ) {
    return "На сервере не задан TURNSTILE_SECRET_KEY.";
  }

  if (codes.has("invalid-input-secret")) {
    return "Secret Key Turnstile неверный.";
  }

  if (
    codes.has("missing-token") ||
    codes.has("missing-input-response")
  ) {
    return "Токен проверки не передался. Пройди капчу заново.";
  }

  if (codes.has("invalid-input-response")) {
    return "Токен капчи недействителен. Пройди проверку заново.";
  }

  if (codes.has("timeout-or-duplicate")) {
    return "Токен капчи истёк или уже использован. Пройди проверку заново.";
  }

  if (codes.has("siteverify-http-400")) {
    return "Turnstile вернул HTTP 400. Проверь Worker Logs.";
  }

  if (codes.has("siteverify-timeout")) {
    return "Сервис проверки капчи не ответил вовремя.";
  }

  if (
    codes.has("siteverify-network-error") ||
    codes.has("internal-error")
  ) {
    return "Не удалось соединиться с сервисом проверки Turnstile.";
  }

  return "Проверка антибота не пройдена. Попробуй ещё раз.";
}

// ======================================================
// DURABLE OBJECT: VoteRegistry
// ======================================================

export class VoteRegistry {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    if (request.method !== "POST") {
      return internalJson({
        error: "method_not_allowed"
      }, 405);
    }

    const url = new URL(request.url);

    const body = await request.json().catch(() => null);

    if (!body) {
      return internalJson({
        error: "invalid_json"
      }, 400);
    }

    // --------------------------------------------------
    // CLAIM VOTE
    // --------------------------------------------------

    if (url.pathname === "/claim") {
      const {
        category,
        deviceHash,
        ipHash,
        day,
        claimId
      } = body;

      if (!VOTE_CATEGORIES.has(category)) {
        return internalJson({
          error: "invalid_category"
        }, 400);
      }

      if (
        typeof deviceHash !== "string" ||
        !/^[a-f0-9]{64}$/.test(deviceHash)
      ) {
        return internalJson({
          error: "invalid_device_hash"
        }, 400);
      }

      if (
        typeof ipHash !== "string" ||
        !/^[a-f0-9]{64}$/.test(ipHash)
      ) {
        return internalJson({
          error: "invalid_ip_hash"
        }, 400);
      }

      if (
        typeof day !== "string" ||
        !/^\d{4}-\d{2}-\d{2}$/.test(day)
      ) {
        return internalJson({
          error: "invalid_day"
        }, 400);
      }

      if (
        typeof claimId !== "string" ||
        claimId.length < 10 ||
        claimId.length > 100
      ) {
        return internalJson({
          error: "invalid_claim_id"
        }, 400);
      }

      return this.state.blockConcurrencyWhile(async () => {
        const deviceKey =
          `voted:${category}:${deviceHash}`;

        const ipKey =
          `ipquota:${category}:${ipHash}:${day}`;

        // Уже голосовал с этого устройства
        const existing =
          await this.state.storage.get(deviceKey);

        if (existing) {
          return internalJson({
            error: "device_already_voted"
          }, 409);
        }

        // Проверка IP-лимита
        const ipCount =
          (await this.state.storage.get(ipKey)) || 0;

        if (ipCount >= MAX_VOTES_PER_IP_PER_DAY) {
          return internalJson({
            error: "ip_quota"
          }, 429);
        }

        // Регистрируем голос
        await this.state.storage.put(deviceKey, {
          claimId,
          ipKey,
          createdAt: Date.now()
        });

        await this.state.storage.put(
          ipKey,
          ipCount + 1
        );

        return internalJson({
          ok: true
        });
      });
    }

    // --------------------------------------------------
    // ROLLBACK VOTE
    // --------------------------------------------------

    if (url.pathname === "/rollback") {
      const {
        category,
        deviceHash,
        claimId
      } = body;

      if (!VOTE_CATEGORIES.has(category)) {
        return internalJson({
          error: "invalid_category"
        }, 400);
      }

      if (
        typeof deviceHash !== "string" ||
        !/^[a-f0-9]{64}$/.test(deviceHash)
      ) {
        return internalJson({
          error: "invalid_device_hash"
        }, 400);
      }

      return this.state.blockConcurrencyWhile(async () => {
        const deviceKey =
          `voted:${category}:${deviceHash}`;

        const record =
          await this.state.storage.get(deviceKey);

        // Удаляем только соответствующий текущий claim
        if (record && record.claimId === claimId) {
          const ipCount =
            (await this.state.storage.get(record.ipKey)) || 0;

          await this.state.storage.delete(deviceKey);

          if (ipCount <= 1) {
            await this.state.storage.delete(record.ipKey);
          } else {
            await this.state.storage.put(
              record.ipKey,
              ipCount - 1
            );
          }
        }

        return internalJson({
          ok: true
        });
      });
    }

    return internalJson({
      error: "not_found"
    }, 404);
  }
}

// ======================================================
// MAIN WORKER
// ======================================================

export default {
  async fetch(request, env) {
    const origin =
      request.headers.get("Origin") || "";

    const url = new URL(request.url);

    // --------------------------------------------------
    // OPTIONS / CORS PREFLIGHT
    // --------------------------------------------------

    if (request.method === "OPTIONS") {
      if (!ALLOWED_ORIGINS.has(origin)) {
        return new Response(null, {
          status: 403
        });
      }

      return new Response(null, {
        status: 204,
        headers: corsHeaders(origin)
      });
    }

    // --------------------------------------------------
    // ROUTE VALIDATION
    // --------------------------------------------------

    if (
      request.method !== "POST" ||
      !["/upload", "/vote"].includes(url.pathname)
    ) {
      return json({
        error: "Not found"
      }, 404, origin);
    }

    if (!ALLOWED_ORIGINS.has(origin)) {
      return json({
        error: "Origin not allowed"
      }, 403, origin);
    }

    if (!env.DISCORD_WEBHOOK_URL) {
      return json({
        error: "Webhook не настроен."
      }, 500, origin);
    }

    // ==================================================
    // VOTE ENDPOINT
    // ==================================================

    if (url.pathname === "/vote") {
      let claim = null;

      try {
        const body = await request.json();

        // Honeypot
        if (String(body.website || "").trim()) {
          return json({
            ok: true
          }, 200, origin);
        }

        const usernameRaw =
          String(body.discordUsername || "").trim();

        const candidateRaw =
          String(body.candidate || "").trim();

        const category =
          String(body.category || "");

        const deviceId =
          String(body.deviceId || "");

        const token =
          String(body.turnstileToken || "");

        // Никаких упоминаний @ в Discord
        const username = usernameRaw
          .replace(/[\r\n@]/g, " ")
          .slice(0, 80);

        const candidate = candidateRaw
          .replace(/[\r\n@]/g, " ")
          .slice(0, 80);

        // ------------------------------------------------
        // INPUT VALIDATION
        // ------------------------------------------------

        if (
          !username ||
          !candidate ||
          usernameRaw.length > 80 ||
          candidateRaw.length > 80
        ) {
          return json({
            error: "Заполни Discord-ник и имя номинанта (до 80 символов)."
          }, 400, origin);
        }

        if (!VOTE_CATEGORIES.has(category)) {
          return json({
            error: "Неизвестная номинация."
          }, 400, origin);
        }

        if (
          !/^[a-zA-Z0-9-]{20,120}$/.test(deviceId)
        ) {
          return json({
            error: "Не удалось определить устройство. Разреши localStorage и обнови страницу."
          }, 400, origin);
        }

        if (!env.TURNSTILE_SECRET_KEY) {
          return json({
            error: "Turnstile не настроен на сервере."
          }, 500, origin);
        }

        if (!env.VOTE_REGISTRY) {
          return json({
            error: "Durable Object VOTE_REGISTRY не подключён."
          }, 500, origin);
        }

        // ------------------------------------------------
        // TURNSTILE VALIDATION
        // ------------------------------------------------

        const ip =
          request.headers.get("CF-Connecting-IP") || "";

        const captchaResult =
          await verifyTurnstile(
            token,
            env.TURNSTILE_SECRET_KEY,
            ip
          );

        if (!captchaResult.success) {
          console.error(
            "Turnstile failed:",
            captchaResult.errorCodes
          );

          return json({
            error: turnstileFailureMessage(
              captchaResult.errorCodes
            )
          }, 403, origin);
        }

        // ------------------------------------------------
        // CREATE HASHES
        // ------------------------------------------------

        const deviceHash =
          await sha256hex(deviceId);

        const ipHash =
          await sha256hex(ip || "no-ip");

        // UTC date
        const day =
          new Date().toISOString().slice(0, 10);

        const claimId =
          crypto.randomUUID();

        // ------------------------------------------------
        // DURABLE OBJECT
        // ------------------------------------------------

        const guard =
          env.VOTE_REGISTRY.get(
            env.VOTE_REGISTRY.idFromName(
              "burdosley-vote-guard"
            )
          );

        // Резервируем голос до отправки в Discord
        const claimResponse =
          await guard.fetch(
            "https://vote-guard/claim",
            {
              method: "POST",
              headers: {
                "Content-Type": "application/json"
              },
              body: JSON.stringify({
                category,
                deviceHash,
                ipHash,
                day,
                claimId
              })
            }
          );

        if (!claimResponse.ok) {
          const claimError =
            await claimResponse.json().catch(() => ({}));

          if (claimResponse.status === 409) {
            return json({
              error: "С этого устройства в этой номинации уже голосовали."
            }, 409, origin);
          }

          if (claimResponse.status === 429) {
            return json({
              error: "Слишком много голосов с этого IP за сегодня. Попробуй завтра."
            }, 429, origin);
          }

          console.error("Vote claim failed:", claimError);

          return json({
            error: "Не удалось зарегистрировать голос."
          }, 500, origin);
        }

        // Запоминаем claim, чтобы можно было откатить
        claim = {
          category,
          deviceHash,
          claimId,
          guard
        };

        // ------------------------------------------------
        // SEND TO DISCORD
        // ------------------------------------------------

        const categoryLabel =
          category === "burmalda-king"
            ? "бурмалда-кинг"
            : "пантера бурмалды";

        const discordResponse =
          await fetch(
            env.DISCORD_WEBHOOK_URL,
            {
              method: "POST",
              headers: {
                "Content-Type": "application/json"
              },
              body: JSON.stringify({
                content:
                  `🗳️ **Новая номинация — БУРДОСЛЕЙ**\n` +
                  `Номинация: **${categoryLabel}**\n` +
                  `Discord: ${username}\n` +
                  `Выбор: **${candidate}**`,
                allowed_mentions: {
                  parse: []
                }
              })
            }
          );

        // Discord отказал
        if (!discordResponse.ok) {
          console.error(
            "Discord vote webhook status:",
            discordResponse.status
          );

          await rollbackClaim(claim);

          claim = null;

          return json({
            error: "Discord не принял голос. Попробуй позже."
          }, 502, origin);
        }

        // Успешная отправка
        claim = null;

        return json({
          ok: true
        }, 200, origin);

      } catch (error) {
        console.error("Vote endpoint error:", error);

        // Если голос зарезервирован, но произошла ошибка,
        // пытаемся вернуть возможность голосовать
        if (claim) {
          await rollbackClaim(claim);
          claim = null;
        }

        return json({
          error: "Ошибка обработки голоса. Попробуй позже."
        }, 500, origin);
      }
    }

    // ==================================================
    // PHOTO UPLOAD ENDPOINT
    // ==================================================

    const declaredLength =
      Number(request.headers.get("Content-Length") || 0);

    if (declaredLength > MAX_BYTES + 100_000) {
      return json({
        error: "Файл слишком большой. Максимум 8 МБ."
      }, 413, origin);
    }

    try {
      const form =
        await request.formData();

      // Honeypot
      if (String(form.get("website") || "").trim()) {
        return json({
          ok: true
        }, 200, origin);
      }

      const file =
        form.get("photo");

      if (!(file instanceof File)) {
        return json({
          error: "Фотография не найдена."
        }, 400, origin);
      }

      if (
        file.size < 1 ||
        file.size > MAX_BYTES
      ) {
        return json({
          error: "Файл должен быть не больше 8 МБ."
        }, 400, origin);
      }

      const bytes =
        new Uint8Array(await file.arrayBuffer());

      const mime =
        detectImage(bytes);

      if (
        !mime ||
        !ALLOWED_TYPES.has(mime)
      ) {
        return json({
          error: "Файл не является поддерживаемым изображением."
        }, 400, origin);
      }

      const sender =
        String(form.get("sender") || "Анонимно")
          .replace(/[\r\n@]/g, " ")
          .trim()
          .slice(0, 50) || "Анонимно";

      const ext = ({
        "image/jpeg": "jpg",
        "image/png": "png",
        "image/webp": "webp",
        "image/gif": "gif"
      })[mime];

      // ------------------------------------------------
      // DISCORD FORM DATA
      // ------------------------------------------------

      const discordForm =
        new FormData();

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
        new Blob([bytes], {
          type: mime
        }),
        `burmaldaa-${Date.now()}.${ext}`
      );

      const discordResponse =
        await fetch(
          env.DISCORD_WEBHOOK_URL,
          {
            method: "POST",
            body: discordForm
          }
        );

      if (!discordResponse.ok) {
        console.error(
          "Discord photo webhook status:",
          discordResponse.status
        );

        return json({
          error: "Discord не принял фотографию. Попробуй позже."
        }, 502, origin);
      }

      return json({
        ok: true
      }, 200, origin);

    } catch (error) {
      console.error("Upload endpoint error:", error);

      return json({
        error: "Ошибка обработки фотографии."
      }, 500, origin);
    }
  }
};

// ======================================================
// ROLLBACK HELPER
// ======================================================

async function rollbackClaim(claim) {
  if (!claim) return;

  try {
    const response =
      await claim.guard.fetch(
        "https://vote-guard/rollback",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            category: claim.category,
            deviceHash: claim.deviceHash,
            claimId: claim.claimId
          })
        }
      );

    if (!response.ok) {
      console.error(
        "Vote rollback failed:",
        response.status
      );
    }
  } catch (error) {
    console.error(
      "Vote rollback exception:",
      error
    );
  }
}
