import json
import os
import re
import sys
import urllib.request
import urllib.error
import urllib.parse
import uuid

MAX_BYTES = 8 * 1024 * 1024
ALLOWED_HOSTS = {"github.com", "user-images.githubusercontent.com", "private-user-images.githubusercontent.com"}
WEBHOOK = os.environ.get("DISCORD_WEBHOOK_URL", "")
EVENT_PATH = os.environ.get("GITHUB_EVENT_PATH", "")

def fail(message):
    print(message, file=sys.stderr)
    sys.exit(1)

def read_event():
    with open(EVENT_PATH, "r", encoding="utf-8") as f:
        event = json.load(f)
    issue = event.get("issue", {})
    body = issue.get("body") or ""
    nickname = "Анонимно"
    match = re.search(r"### Твой ник \(необязательно\)\s*\n+([^\n#]+)", body, re.I)
    if match:
        nickname = match.group(1).strip()[:50] or "Анонимно"
    return issue, body, nickname

def extract_image_url(body):
    # GitHub issue attachments normally use github.com/user-attachments/assets/...
    # or user-images.githubusercontent.com/...
    candidates = re.findall(r'https?://[^\s)>"]+', body)
    for raw in candidates:
        url = raw.rstrip(".,;")
        if "github.com/user-attachments/assets/" in url or "user-images.githubusercontent.com/" in url:
            return url
    return None

def download_image(url):
    req = urllib.request.Request(url, headers={"User-Agent": "BURMALDAA-GitHub-Actions"})
    with urllib.request.urlopen(req, timeout=25) as response:
        final_host = urllib.parse.urlparse(response.geturl()).hostname
        if final_host not in ALLOWED_HOSTS:
            fail("Ссылка на файл перенаправлена на неподдерживаемый домен.")
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        fail("Фотография больше 8 МБ.")
    if data.startswith(b"\xff\xd8\xff"):
        return data, "image/jpeg", "photo.jpg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return data, "image/png", "photo.png"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return data, "image/gif", "photo.gif"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return data, "image/webp", "photo.webp"
    fail("Файл не распознан как JPG, PNG, GIF или WEBP.")

def post_to_discord(data, mime, filename, nickname, issue_url):
    boundary = "----Burmaldaa" + uuid.uuid4().hex
    payload = {
        "content": f"📷 **Новая фотография с сайта BURMALDAA**\nОтправитель: {nickname}\nЗаявка: {issue_url}",
        "allowed_mentions": {"parse": []}
    }
    parts = []
    def field(name, value, content_type=None, file_name=None):
        header = f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\""
        if file_name:
            header += f'; filename="{file_name}"'
        header += "\r\n"
        if content_type:
            header += f"Content-Type: {content_type}\r\n"
        parts.append(header.encode() + b"\r\n" + value + b"\r\n")
    field("payload_json", json.dumps(payload, ensure_ascii=False).encode(), "application/json")
    field("files[0]", data, mime, filename)
    body = b"".join(parts) + f"--{boundary}--\r\n".encode()
    req = urllib.request.Request(
        WEBHOOK + "?wait=true",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}", "User-Agent": "BURMALDAA-GitHub-Actions"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        if response.status not in (200, 204):
            fail(f"Discord вернул HTTP {response.status}.")

def main():
    if not WEBHOOK or not EVENT_PATH:
        fail("Не настроен DISCORD_WEBHOOK_URL или GITHUB_EVENT_PATH.")
    issue, body, nickname = read_event()
    image_url = extract_image_url(body)
    if not image_url:
        fail("Не найдена ссылка на вложение GitHub. Прикрепи изображение именно в поле формы.")
    data, mime, filename = download_image(image_url)
    post_to_discord(data, mime, filename, nickname, issue.get("html_url", ""))
    print("Фотография успешно отправлена в Discord.")

if __name__ == "__main__":
    main()
