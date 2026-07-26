import asyncio
import html
import json
import logging
import os
from contextlib import suppress
from typing import Any

import httpx
from aiogram import Bot, Dispatcher, F
from aiogram.exceptions import TelegramBadRequest
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (
    BotCommand,
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)

from translations import LANGUAGES, TEXT, status_text, tr

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("netauto-bot")

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
ENABLED = os.getenv("TELEGRAM_BOT_ENABLED", "false").lower() == "true"
API_BASE = os.getenv("TELEGRAM_API_BASE", "http://api:8000").rstrip("/")
WEB_BASE = os.getenv("APP_BASE_URL", "https://tunnel.softarg.ir").rstrip("/")
BOT_KEY = os.getenv("BOT_INTERNAL_API_KEY", "").strip()
BRAND = os.getenv("APP_SHORT_NAME", os.getenv("APP_NAME", "TehranNetwork")).strip()

CONTROL = "/api/v1/bot-control"
EXISTING = "/api/v1/bot"
TERMINAL = {"SUCCESS", "FAILED", "WARNING", "CANCELLED", "ROLLED_BACK"}

STEP_PROMPTS = {
    "en": {"name": "Endpoint name:", "host": "IP address or hostname:", "port": "SSH port (default 22):", "ssh_username": "SSH username:", "display_location": "Location label:", "auth_method": "SSH authentication method:", "secret": "SSH password or private key:", "sudo_mode": "Sudo mode:", "sudo_password": "Sudo password:", "description": "Description, or send - to leave empty:", "review": "Review and confirm the endpoint."},
    "fa": {"name": "نام سرور:", "host": "آدرس IP یا دامنه:", "port": "پورت SSH؛ پیش‌فرض ۲۲:", "ssh_username": "نام کاربری SSH:", "display_location": "نام موقعیت سرور:", "auth_method": "روش ورود SSH:", "secret": "رمز SSH یا کلید خصوصی:", "sudo_mode": "نوع دسترسی Sudo:", "sudo_password": "رمز Sudo:", "description": "توضیحات؛ برای خالی‌گذاشتن - بفرست:", "review": "اطلاعات را بررسی و تأیید کن."},
    "ru": {"name": "Имя сервера:", "host": "IP-адрес или домен:", "port": "Порт SSH, по умолчанию 22:", "ssh_username": "Пользователь SSH:", "display_location": "Расположение:", "auth_method": "Метод SSH-аутентификации:", "secret": "Пароль SSH или закрытый ключ:", "sudo_mode": "Режим Sudo:", "sudo_password": "Пароль Sudo:", "description": "Описание или - для пустого значения:", "review": "Проверьте и подтвердите данные."},
    "zh-CN": {"name": "服务器名称：", "host": "IP 地址或域名：", "port": "SSH 端口，默认 22：", "ssh_username": "SSH 用户名：", "display_location": "位置标签：", "auth_method": "SSH 认证方式：", "secret": "SSH 密码或私钥：", "sudo_mode": "Sudo 模式：", "sudo_password": "Sudo 密码：", "description": "说明；发送 - 表示留空：", "review": "请检查并确认服务器信息。"},
    "de": {"name": "Servername:", "host": "IP-Adresse oder Domain:", "port": "SSH-Port, Standard 22:", "ssh_username": "SSH-Benutzer:", "display_location": "Standort:", "auth_method": "SSH-Authentifizierung:", "secret": "SSH-Passwort oder privater Schlüssel:", "sudo_mode": "Sudo-Modus:", "sudo_password": "Sudo-Passwort:", "description": "Beschreibung oder - für leer:", "review": "Serverdaten prüfen und bestätigen."},
}

CHOICE_LABELS = {
    "en": {"PASSWORD": "Password", "PRIVATE_KEY": "Private key", "NONE": "No sudo", "PASSWORDLESS": "Passwordless sudo"},
    "fa": {"PASSWORD": "رمز عبور", "PRIVATE_KEY": "کلید خصوصی", "NONE": "بدون Sudo", "PASSWORDLESS": "Sudo بدون رمز"},
    "ru": {"PASSWORD": "Пароль", "PRIVATE_KEY": "Закрытый ключ", "NONE": "Без sudo", "PASSWORDLESS": "Sudo без пароля"},
    "zh-CN": {"PASSWORD": "密码", "PRIVATE_KEY": "私钥", "NONE": "无 Sudo", "PASSWORDLESS": "免密 Sudo"},
    "de": {"PASSWORD": "Passwort", "PRIVATE_KEY": "Privater Schlüssel", "NONE": "Kein Sudo", "PASSWORDLESS": "Sudo ohne Passwort"},
}


class Flow(StatesGroup):
    endpoint_value = State()
    plan_name = State()


dp = Dispatcher(storage=MemoryStorage())
CATALOG_CACHE: dict[str, Any] = {"data": None, "expires": 0.0}
TASKS: set[asyncio.Task] = set()


class ApiError(Exception):
    def __init__(self, status: int, detail: Any):
        self.status = status
        self.detail = detail
        super().__init__(str(detail))


def esc(value: Any) -> str:
    if value in (None, ""):
        value = "-"
    return html.escape(str(value))


def kb(rows):
    return InlineKeyboardMarkup(inline_keyboard=rows)


def button(text, data=None, url=None):
    return InlineKeyboardButton(text=text, callback_data=data, url=url)


def track(task: asyncio.Task):
    TASKS.add(task)
    task.add_done_callback(TASKS.discard)


async def request(method: str, path: str, payload=None):
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(30, connect=10)) as client:
            response = await client.request(
                method,
                f"{API_BASE}{path}",
                json=payload,
                headers={"X-Bot-Api-Key": BOT_KEY},
            )
    except httpx.HTTPError as exc:
        raise ApiError(503, type(exc).__name__) from exc
    if response.status_code >= 400:
        try:
            detail = response.json().get("detail", response.text)
        except Exception:
            detail = response.text
        raise ApiError(response.status_code, detail)
    return response.json() if response.content else {}


async def api_get(path):
    return await request("GET", path)


async def api_post(path, payload=None):
    return await request("POST", path, payload or {})


async def api_delete(path):
    return await request("DELETE", path)


async def context(telegram_id: int):
    return await api_get(f"{CONTROL}/context/{telegram_id}")


async def language(telegram_id: int):
    try:
        value = (await context(telegram_id)).get("language", "en")
        return value if value in LANGUAGES else "en"
    except Exception:
        return "en"


async def edit(message: Message, text: str, markup=None):
    with suppress(TelegramBadRequest):
        await message.edit_text(
            text,
            reply_markup=markup,
            parse_mode="HTML",
            disable_web_page_preview=True,
        )


async def fail(target: Message | CallbackQuery, lang: str, exc: Exception):
    if isinstance(exc, ApiError):
        detail = exc.detail
        if isinstance(detail, dict):
            detail = detail.get("code", json.dumps(detail, ensure_ascii=False))
        text = tr(lang, "error", detail=esc(detail))
    else:
        logger.exception("Handler error", exc_info=exc)
        text = tr(lang, "api_unavailable")
    if isinstance(target, CallbackQuery):
        await target.answer(html.unescape(text), show_alert=True)
    else:
        await target.answer(text, parse_mode="HTML")


def language_keyboard():
    return kb([[button(name, f"lang:{code}")] for code, name in LANGUAGES.items()])


def home_keyboard(lang: str, role: str):
    rows = [
        [button(tr(lang, "endpoints"), "ep:list:0"), button(tr(lang, "tunnels"), "pl:list:0")],
        [button(tr(lang, "prechecks"), "pc:list:0"), button(tr(lang, "jobs"), "job:list:0")],
        [button(tr(lang, "methods"), "method:cats"), button(tr(lang, "language"), "lang:menu")],
    ]
    if role in {"ADMIN", "SUPER_ADMIN"}:
        rows.append([button(tr(lang, "admin"), "admin")])
    rows.append([button(tr(lang, "open_panel"), url=f"{WEB_BASE}/admin" if role in {"ADMIN", "SUPER_ADMIN"} else f"{WEB_BASE}/app")])
    return kb(rows)


def nav(lang: str, back="home"):
    return kb([[button(tr(lang, "back"), back), button(tr(lang, "home"), "home")]])


async def render_home(message: Message, telegram_id: int, do_edit: bool):
    ctx = await context(telegram_id)
    lang = ctx.get("language", "en") if ctx.get("language") in LANGUAGES else "en"
    if not (ctx.get("linked") and ctx.get("is_active")):
        text = tr(lang, "not_linked")
        markup = kb([
            [button(tr(lang, "open_panel"), url=f"{WEB_BASE}/app")],
            [button(tr(lang, "language"), "lang:menu")],
        ])
    else:
        data = await api_get(f"{CONTROL}/dashboard/{telegram_id}")
        user, counts = data["user"], data["counts"]
        text = "\n\n".join([
            tr(lang, "title", brand=esc(BRAND)),
            tr(lang, "account", username=esc(user["username"]), role=esc(user["role"])),
            tr(lang, "dashboard", ready=counts["ready_endpoints"], endpoints=counts["endpoints"], plans=counts["plans"], jobs=counts["active_jobs"], runs=counts["active_runs"], methods=counts["methods"]),
        ])
        markup = home_keyboard(lang, user["role"])
    if do_edit:
        await edit(message, text, markup)
    else:
        await message.answer(text, reply_markup=markup, parse_mode="HTML")


async def catalog(telegram_id: int):
    now = asyncio.get_running_loop().time()
    if CATALOG_CACHE["data"] and CATALOG_CACHE["expires"] > now:
        return CATALOG_CACHE["data"]
    data = await api_get(f"{CONTROL}/catalog/{telegram_id}")
    CATALOG_CACHE.update(data=data, expires=now + 120)
    return data


@dp.message(CommandStart())
async def start(message: Message, state: FSMContext):
    await state.clear()
    try:
        ctx = await context(message.from_user.id)
        if not ctx.get("has_profile"):
            await message.answer("🌐 Choose language / انتخاب زبان", reply_markup=language_keyboard())
        else:
            await render_home(message, message.from_user.id, False)
    except Exception as exc:
        await fail(message, "en", exc)


@dp.message(Command("menu"))
async def menu(message: Message, state: FSMContext):
    await state.clear()
    try:
        await render_home(message, message.from_user.id, False)
    except Exception as exc:
        await fail(message, await language(message.from_user.id), exc)


@dp.callback_query(F.data == "home")
async def home_cb(callback: CallbackQuery, state: FSMContext):
    await state.clear()
    try:
        await render_home(callback.message, callback.from_user.id, True)
        await callback.answer()
    except Exception as exc:
        await fail(callback, await language(callback.from_user.id), exc)


@dp.callback_query(F.data == "lang:menu")
async def lang_menu(callback: CallbackQuery):
    lang = await language(callback.from_user.id)
    await edit(callback.message, tr(lang, "choose_language"), language_keyboard())
    await callback.answer()


@dp.callback_query(F.data.startswith("lang:"))
async def lang_set(callback: CallbackQuery):
    code = callback.data.split(":", 1)[1]
    if code == "menu":
        return
    if code not in LANGUAGES:
        await callback.answer("Unsupported language", show_alert=True)
        return
    try:
        await api_post(f"{CONTROL}/language", {"telegram_id": callback.from_user.id, "username": callback.from_user.username, "language": code})
        await render_home(callback.message, callback.from_user.id, True)
        await callback.answer(tr(code, "language_saved"))
    except Exception as exc:
        await fail(callback, code, exc)


async def endpoints_view(message: Message, telegram_id: int, page: int):
    lang = await language(telegram_id)
    data = await api_get(f"{CONTROL}/endpoints/{telegram_id}")
    all_items = data.get("items", [])
    size, pages = 8, max(1, (len(all_items) + 7) // 8)
    page = max(0, min(page, pages - 1))
    items = all_items[page * size:(page + 1) * size]
    rows = [[button(("✅ " if item["status"] == "READY" else "⚠️ ") + item["name"][:45], f"ep:view:{item['id']}")] for item in items]
    pager = []
    if page:
        pager.append(button(tr(lang, "previous"), f"ep:list:{page-1}"))
    if page + 1 < pages:
        pager.append(button(tr(lang, "next"), f"ep:list:{page+1}"))
    if pager:
        rows.append(pager)
    rows += [[button(tr(lang, "endpoint_add"), "ep:add")], [button(tr(lang, "home"), "home")]]
    text = tr(lang, "endpoint_list") + ("\n\n" + tr(lang, "endpoint_empty") if not all_items else "")
    await edit(message, text, kb(rows))


@dp.callback_query(F.data.startswith("ep:list:"))
async def ep_list(callback: CallbackQuery):
    try:
        await endpoints_view(callback.message, callback.from_user.id, int(callback.data.rsplit(":", 1)[1]))
        await callback.answer()
    except Exception as exc:
        await fail(callback, await language(callback.from_user.id), exc)


async def find_endpoint(telegram_id: int, endpoint_id: int):
    data = await api_get(f"{CONTROL}/endpoints/{telegram_id}")
    return next((item for item in data["items"] if item["id"] == endpoint_id), None)


@dp.callback_query(F.data.startswith("ep:view:"))
async def ep_view(callback: CallbackQuery):
    lang = await language(callback.from_user.id)
    try:
        endpoint_id = int(callback.data.rsplit(":", 1)[1])
        item = await find_endpoint(callback.from_user.id, endpoint_id)
        if not item:
            raise ApiError(404, "ENDPOINT_NOT_FOUND")
        inventory = item.get("inventory", {})
        text = tr(lang, "endpoint_detail", name=esc(item["name"]), id=item["id"], host=esc(item["host"]), port=item["port"], status=status_text(lang, item["status"]), os=esc(item.get("detected_os")), arch=esc(item.get("detected_arch")), location=esc(item.get("display_location")), inventory=status_text(lang, inventory.get("status")))
        await edit(callback.message, text, kb([
            [button(tr(lang, "inventory"), f"ep:inv:{endpoint_id}"), button(tr(lang, "inventory_refresh"), f"ep:scan:{endpoint_id}")],
            [button(tr(lang, "delete"), f"ep:delete:{endpoint_id}")],
            [button(tr(lang, "back"), "ep:list:0"), button(tr(lang, "home"), "home")],
        ]))
        await callback.answer()
    except Exception as exc:
        await fail(callback, lang, exc)


@dp.callback_query(F.data.startswith("ep:inv:"))
async def ep_inventory(callback: CallbackQuery):
    lang = await language(callback.from_user.id)
    try:
        endpoint_id = int(callback.data.rsplit(":", 1)[1])
        data = await api_get(f"{EXISTING}/endpoints/{callback.from_user.id}/{endpoint_id}/inventory")
        summary = json.dumps(data.get("summary", {}), ensure_ascii=False, indent=2)[:2800]
        await edit(callback.message, tr(lang, "inventory_detail", name=esc(data.get("endpoint", {}).get("name", endpoint_id)), status=status_text(lang, data.get("status")), scanned=esc(data.get("scanned_at")), summary=esc(summary)), kb([
            [button(tr(lang, "inventory_refresh"), f"ep:scan:{endpoint_id}")],
            [button(tr(lang, "back"), f"ep:view:{endpoint_id}"), button(tr(lang, "home"), "home")],
        ]))
        await callback.answer()
    except Exception as exc:
        await fail(callback, lang, exc)


async def monitor_job(bot: Bot, chat_id: int, message_id: int, telegram_id: int, job_id: int, lang: str):
    previous = None
    for _ in range(200):
        try:
            data = await api_get(f"{EXISTING}/jobs/{telegram_id}/{job_id}")
            events = "\n".join(f"• {esc(event.get('message'))}" for event in data.get("events", [])[-8:]) or "-"
            text = tr(lang, "job_detail", id=data["id"], type=esc(data.get("job_type", "-")), status=status_text(lang, data.get("status")), progress=data.get("progress", 0), step=esc(data.get("current_step")), events=events)
            if text != previous:
                with suppress(TelegramBadRequest):
                    await bot.edit_message_text(text, chat_id=chat_id, message_id=message_id, parse_mode="HTML", reply_markup=nav(lang, "job:list:0"))
                previous = text
            if data.get("status") in {"SUCCESS", "FAILED", "CANCELLED"}:
                return
        except Exception:
            logger.exception("Job monitor error")
        await asyncio.sleep(3)


@dp.callback_query(F.data.startswith("ep:scan:"))
async def ep_scan(callback: CallbackQuery):
    lang = await language(callback.from_user.id)
    try:
        endpoint_id = int(callback.data.rsplit(":", 1)[1])
        result = await api_post(f"{EXISTING}/endpoints/{callback.from_user.id}/{endpoint_id}/inventory/refresh")
        sent = await callback.message.answer(tr(lang, "job_detail", id=result["job_id"], type="ENDPOINT_INVENTORY", status=status_text(lang, "QUEUED"), progress=0, step="queue", events="-"), parse_mode="HTML")
        track(asyncio.create_task(monitor_job(callback.bot, sent.chat.id, sent.message_id, callback.from_user.id, result["job_id"], lang)))
        await callback.answer()
    except Exception as exc:
        await fail(callback, lang, exc)


async def render_draft(message: Message, telegram_id: int, lang: str, draft: dict, do_edit: bool):
    step = draft.get("step", "name")
    prompt = STEP_PROMPTS[lang].get(step, tr(lang, "draft_prompt"))
    rows = []
    if step == "review":
        s = draft.get("summary", {})
        text = tr(lang, "draft_review", name=esc(s.get("name")), host=esc(s.get("host")), port=esc(s.get("port")), username=esc(s.get("ssh_username")), location=esc(s.get("display_location")), auth=esc(s.get("auth_method")), sudo=esc(s.get("sudo_mode")), description=esc(s.get("description")))
        rows = [[button(tr(lang, "confirm"), "draft:commit")], [button(tr(lang, "back"), "draft:back"), button(tr(lang, "cancel"), "draft:cancel")]]
    elif draft.get("type") == "choice":
        text = prompt
        for choice in draft.get("choices", []):
            rows.append([button(CHOICE_LABELS[lang].get(choice, choice), f"draft:value:{choice}")])
        rows.append([button(tr(lang, "back"), "draft:back"), button(tr(lang, "cancel"), "draft:cancel")])
    else:
        text = prompt + "\n\n" + tr(lang, "draft_prompt")
        rows = [[button(tr(lang, "back"), "draft:back"), button(tr(lang, "cancel"), "draft:cancel")]]
    if do_edit:
        await edit(message, text, kb(rows))
    else:
        await message.answer(text, reply_markup=kb(rows), parse_mode="HTML")


@dp.callback_query(F.data == "ep:add")
async def ep_add(callback: CallbackQuery, state: FSMContext):
    lang = await language(callback.from_user.id)
    try:
        draft = await api_post(f"{EXISTING}/endpoint-drafts/start", {"telegram_id": callback.from_user.id})
        await state.set_state(Flow.endpoint_value)
        await render_draft(callback.message, callback.from_user.id, lang, draft, True)
        await callback.answer()
    except Exception as exc:
        await fail(callback, lang, exc)


@dp.message(Flow.endpoint_value)
async def draft_text(message: Message, state: FSMContext):
    lang = await language(message.from_user.id)
    try:
        current = await api_get(f"{EXISTING}/endpoint-drafts/{message.from_user.id}")
        secret = current.get("type") == "secret"
        result = await api_post(f"{EXISTING}/endpoint-drafts/advance", {"telegram_id": message.from_user.id, "value": message.text or ""})
        if secret:
            with suppress(TelegramBadRequest):
                await message.delete()
        await render_draft(message, message.from_user.id, lang, result, False)
    except Exception as exc:
        await fail(message, lang, exc)


@dp.callback_query(F.data.startswith("draft:"))
async def draft_action(callback: CallbackQuery, state: FSMContext):
    lang = await language(callback.from_user.id)
    action = callback.data.split(":", 2)[1]
    try:
        if action == "value":
            value = callback.data.split(":", 2)[2]
            result = await api_post(f"{EXISTING}/endpoint-drafts/advance", {"telegram_id": callback.from_user.id, "value": value})
            await render_draft(callback.message, callback.from_user.id, lang, result, True)
        elif action == "back":
            result = await api_post(f"{EXISTING}/endpoint-drafts/back", {"telegram_id": callback.from_user.id})
            await render_draft(callback.message, callback.from_user.id, lang, result, True)
        elif action == "cancel":
            await api_post(f"{EXISTING}/endpoint-drafts/cancel", {"telegram_id": callback.from_user.id})
            await state.clear()
            await endpoints_view(callback.message, callback.from_user.id, 0)
            await callback.answer(tr(lang, "draft_cancelled"))
            return
        elif action == "commit":
            result = await api_post(f"{EXISTING}/endpoint-drafts/commit", {"telegram_id": callback.from_user.id})
            await state.clear()
            await edit(callback.message, tr(lang, "draft_saved", job_id=result["job_id"]), nav(lang, "ep:list:0"))
            track(asyncio.create_task(monitor_job(callback.bot, callback.message.chat.id, callback.message.message_id, callback.from_user.id, result["job_id"], lang)))
        await callback.answer()
    except Exception as exc:
        await fail(callback, lang, exc)


@dp.callback_query(F.data.startswith("ep:delete:"))
async def ep_delete_question(callback: CallbackQuery):
    lang = await language(callback.from_user.id)
    try:
        endpoint_id = int(callback.data.rsplit(":", 1)[1])
        item = await find_endpoint(callback.from_user.id, endpoint_id)
        if not item:
            raise ApiError(404, "ENDPOINT_NOT_FOUND")
        await edit(callback.message, tr(lang, "endpoint_delete_question", name=esc(item["name"])), kb([[button(tr(lang, "confirm"), f"ep:deleteok:{endpoint_id}")], [button(tr(lang, "back"), f"ep:view:{endpoint_id}")]]))
        await callback.answer()
    except Exception as exc:
        await fail(callback, lang, exc)


@dp.callback_query(F.data.startswith("ep:deleteok:"))
async def ep_delete(callback: CallbackQuery):
    lang = await language(callback.from_user.id)
    try:
        endpoint_id = int(callback.data.rsplit(":", 1)[1])
        await api_delete(f"{EXISTING}/endpoints/{callback.from_user.id}/{endpoint_id}")
        await endpoints_view(callback.message, callback.from_user.id, 0)
        await callback.answer(tr(lang, "endpoint_deleted"))
    except Exception as exc:
        await fail(callback, lang, exc)


async def plans_view(message: Message, telegram_id: int, page: int):
    lang = await language(telegram_id)
    data = await api_get(f"{CONTROL}/plans/{telegram_id}")
    all_items, size = data.get("items", []), 8
    total = max(1, (len(all_items) + size - 1) // size)
    page = max(0, min(page, total - 1))
    items = all_items[page * size:(page + 1) * size]
    rows = [[button(f"{status_text(lang, item['status'])} · {item['name']}"[:55], f"pl:view:{item['id']}")] for item in items]
    pager = []
    if page:
        pager.append(button(tr(lang, "previous"), f"pl:list:{page-1}"))
    if page + 1 < total:
        pager.append(button(tr(lang, "next"), f"pl:list:{page+1}"))
    if pager:
        rows.append(pager)
    rows += [[button(tr(lang, "plan_create"), "wizard:start")], [button(tr(lang, "composer"), url=f"{WEB_BASE}/composer.html")], [button(tr(lang, "home"), "home")]]
    text = tr(lang, "plan_list") + ("\n\n" + tr(lang, "plan_empty") if not all_items else "")
    await edit(message, text, kb(rows))


@dp.callback_query(F.data.startswith("pl:list:"))
async def pl_list(callback: CallbackQuery):
    try:
        await plans_view(callback.message, callback.from_user.id, int(callback.data.rsplit(":", 1)[1]))
        await callback.answer()
    except Exception as exc:
        await fail(callback, await language(callback.from_user.id), exc)


def plan_keyboard(lang: str, plan: dict):
    rows = []
    run = plan.get("latest_run")
    if run and run.get("status") in {"QUEUED", "RUNNING", "CANCEL_REQUESTED", "ROLLING_BACK"}:
        rows.append([button(tr(lang, "details"), f"run:view:{run['id']}"), button(tr(lang, "stop"), f"run:cancel:{run['id']}")])
    else:
        rows.append([button(tr(lang, "execute"), f"pl:execute:{plan['id']}")])
    if plan.get("status") == "DRAFT":
        rows.append([button(tr(lang, "delete"), f"pl:delete:{plan['id']}")])
    rows.append([button(tr(lang, "refresh"), f"pl:view:{plan['id']}"), button(tr(lang, "back"), "pl:list:0")])
    return kb(rows)


@dp.callback_query(F.data.startswith("pl:view:"))
async def pl_view(callback: CallbackQuery):
    lang = await language(callback.from_user.id)
    try:
        plan_id = int(callback.data.rsplit(":", 1)[1])
        plan = await api_get(f"{CONTROL}/plans/{callback.from_user.id}/{plan_id}")
        item = (plan.get("items") or [{}])[0]
        readiness = plan.get("readiness", {})
        text = tr(lang, "plan_detail", name=esc(plan["name"]), id=plan["id"], status=status_text(lang, plan["status"]), items=plan.get("total_items", len(plan.get("items", []))), method=esc(item.get("method_name") or item.get("method_id")), a=esc(item.get("endpoint_a", {}).get("name")), b=esc(item.get("endpoint_b", {}).get("name")), direction=esc(item.get("traffic_direction")), readiness=tr(lang, "ready") if readiness.get("ready") else tr(lang, "not_ready"))
        await edit(callback.message, text, plan_keyboard(lang, plan))
        await callback.answer()
    except Exception as exc:
        await fail(callback, lang, exc)


async def choose_endpoint(message: Message, telegram_id: int, lang: str, role: str, exclude=None):
    data = await api_get(f"{CONTROL}/endpoints/{telegram_id}")
    items = [item for item in data["items"] if item["status"] == "READY" and item["id"] != exclude]
    prefix = "wa" if role == "a" else "wb"
    rows = [[button(item["name"][:55], f"wizard:{prefix}:{item['id']}")] for item in items[:40]]
    rows.append([button(tr(lang, "back"), "pl:list:0")])
    await edit(message, tr(lang, "select_a" if role == "a" else "select_b"), kb(rows))


@dp.callback_query(F.data == "wizard:start")
async def wizard_start(callback: CallbackQuery, state: FSMContext):
    await state.clear()
    lang = await language(callback.from_user.id)
    try:
        await choose_endpoint(callback.message, callback.from_user.id, lang, "a")
        await callback.answer()
    except Exception as exc:
        await fail(callback, lang, exc)


@dp.callback_query(F.data.startswith("wizard:wa:"))
async def wizard_a(callback: CallbackQuery, state: FSMContext):
    lang = await language(callback.from_user.id)
    endpoint_a = int(callback.data.rsplit(":", 1)[1])
    await state.update_data(endpoint_a_id=endpoint_a)
    try:
        await choose_endpoint(callback.message, callback.from_user.id, lang, "b", endpoint_a)
        await callback.answer()
    except Exception as exc:
        await fail(callback, lang, exc)


@dp.callback_query(F.data.startswith("wizard:wb:"))
async def wizard_b(callback: CallbackQuery, state: FSMContext):
    lang = await language(callback.from_user.id)
    try:
        await state.update_data(endpoint_b_id=int(callback.data.rsplit(":", 1)[1]))
        data = await catalog(callback.from_user.id)
        rows = [[button(category[:55], f"wizard:cat:{index}")] for index, category in enumerate(data["categories"])]
        rows.append([button(tr(lang, "back"), "wizard:start")])
        await edit(callback.message, tr(lang, "select_category"), kb(rows))
        await callback.answer()
    except Exception as exc:
        await fail(callback, lang, exc)


@dp.callback_query(F.data.startswith("wizard:cat:"))
async def wizard_category(callback: CallbackQuery, state: FSMContext):
    lang = await language(callback.from_user.id)
    try:
        index = int(callback.data.rsplit(":", 1)[1])
        data = await catalog(callback.from_user.id)
        category = data["categories"][index]
        await state.update_data(category_index=index)
        items = [item for item in data["methods"] if item["category"] == category and item.get("executable")]
        rows = [[button(item["name"][:55], f"wizard:method:{item['id']}")] for item in items]
        rows.append([button(tr(lang, "back"), "wizard:start")])
        await edit(callback.message, tr(lang, "select_method"), kb(rows))
        await callback.answer()
    except Exception as exc:
        await fail(callback, lang, exc)


@dp.callback_query(F.data.startswith("wizard:method:"))
async def wizard_method(callback: CallbackQuery, state: FSMContext):
    lang = await language(callback.from_user.id)
    try:
        method_id = callback.data.split(":", 2)[2]
        data = await catalog(callback.from_user.id)
        method = next(item for item in data["methods"] if item["id"] == method_id)
        await state.update_data(method_id=method_id)
        rows = [[button(direction, f"wizard:direction:{direction}")] for direction in method.get("directions", ["BIDIRECTIONAL"])]
        rows.append([button(tr(lang, "back"), f"wizard:cat:{(await state.get_data()).get('category_index', 0)}")])
        await edit(callback.message, tr(lang, "select_direction"), kb(rows))
        await callback.answer()
    except Exception as exc:
        await fail(callback, lang, exc)


@dp.callback_query(F.data.startswith("wizard:direction:"))
async def wizard_direction(callback: CallbackQuery, state: FSMContext):
    lang = await language(callback.from_user.id)
    await state.update_data(traffic_direction=callback.data.split(":", 2)[2])
    await state.set_state(Flow.plan_name)
    await edit(callback.message, tr(lang, "send_plan_name"), nav(lang, "pl:list:0"))
    await callback.answer()


@dp.message(Flow.plan_name)
async def wizard_name(message: Message, state: FSMContext):
    lang = await language(message.from_user.id)
    try:
        values = await state.get_data()
        result = await api_post(f"{CONTROL}/plans/simple", {
            "telegram_id": message.from_user.id,
            "name": (message.text or "").strip(),
            "endpoint_a_id": values["endpoint_a_id"],
            "endpoint_b_id": values["endpoint_b_id"],
            "method_id": values["method_id"],
            "traffic_direction": values["traffic_direction"],
            "target_port": 22,
        })
        await state.clear()
        await message.answer(tr(lang, "plan_created"), parse_mode="HTML")
        await message.answer(
            tr(lang, "plan_detail", name=esc(result["plan"]["name"]), id=result["plan"]["id"], status=status_text(lang, result["plan"]["status"]), items=result["plan"]["total_items"], method=esc(result["plan"]["items"][0]["method_id"]), a=esc(result["plan"]["items"][0]["endpoint_a"]["name"]), b=esc(result["plan"]["items"][0]["endpoint_b"]["name"]), direction=esc(result["plan"]["items"][0]["traffic_direction"]), readiness=tr(lang, "not_ready")),
            reply_markup=nav(lang, "pl:list:0"), parse_mode="HTML"
        )
    except Exception as exc:
        await fail(message, lang, exc)


@dp.callback_query(F.data.startswith("pl:delete:"))
async def pl_delete(callback: CallbackQuery):
    lang = await language(callback.from_user.id)
    try:
        plan_id = int(callback.data.rsplit(":", 1)[1])
        await api_delete(f"{CONTROL}/plans/{callback.from_user.id}/{plan_id}")
        await plans_view(callback.message, callback.from_user.id, 0)
        await callback.answer(tr(lang, "plan_deleted"))
    except Exception as exc:
        await fail(callback, lang, exc)


def format_run(lang: str, run: dict):
    items = "\n".join(f"• <code>{esc(item.get('method_id'))}</code> — {status_text(lang, item.get('status'))}" for item in run.get("items", [])) or "-"
    events = "\n".join(f"• {esc(event.get('message'))}" for event in run.get("events", [])[-8:]) or "-"
    return tr(lang, "run_detail", id=run["id"], status=status_text(lang, run.get("status")), current=run.get("current_order", 0), total=run.get("total_items", 0), items=items, events=events)


def run_markup(lang: str, run: dict):
    rows = [[button(tr(lang, "refresh"), f"run:view:{run['id']}")]]
    if run.get("status") in {"QUEUED", "RUNNING"}:
        rows.append([button(tr(lang, "stop"), f"run:cancel:{run['id']}")])
    rows.append([button(tr(lang, "back"), f"pl:view:{run['plan_id']}")])
    return kb(rows)


async def monitor_run(bot: Bot, chat_id: int, message_id: int, telegram_id: int, run_id: int, lang: str):
    previous = None
    for _ in range(600):
        try:
            run = await api_get(f"{CONTROL}/runs/{telegram_id}/{run_id}")
            text = format_run(lang, run)
            if text != previous:
                with suppress(TelegramBadRequest):
                    await bot.edit_message_text(text, chat_id=chat_id, message_id=message_id, parse_mode="HTML", reply_markup=run_markup(lang, run))
                previous = text
            if run.get("status") in TERMINAL:
                return
        except Exception:
            logger.exception("Run monitor error")
        await asyncio.sleep(3)


@dp.callback_query(F.data.startswith("pl:execute:"))
async def pl_execute(callback: CallbackQuery):
    lang = await language(callback.from_user.id)
    try:
        plan_id = int(callback.data.rsplit(":", 1)[1])
        result = await api_post(f"{CONTROL}/plans/{callback.from_user.id}/{plan_id}/execute")
        run_id = result["run_id"]
        await edit(callback.message, tr(lang, "run_queued", run_id=run_id), kb([[button(tr(lang, "details"), f"run:view:{run_id}")]]))
        track(asyncio.create_task(monitor_run(callback.bot, callback.message.chat.id, callback.message.message_id, callback.from_user.id, run_id, lang)))
        await callback.answer()
    except ApiError as exc:
        if isinstance(exc.detail, dict) and exc.detail.get("code") == "EXECUTION_READINESS_REQUIRED":
            await callback.answer(tr(lang, "readiness_required"), show_alert=True)
            await prechecks_view(callback.message, callback.from_user.id, 0)
        else:
            await fail(callback, lang, exc)
    except Exception as exc:
        await fail(callback, lang, exc)


@dp.callback_query(F.data.startswith("run:view:"))
async def run_view(callback: CallbackQuery):
    lang = await language(callback.from_user.id)
    try:
        run_id = int(callback.data.rsplit(":", 1)[1])
        run = await api_get(f"{CONTROL}/runs/{callback.from_user.id}/{run_id}")
        await edit(callback.message, format_run(lang, run), run_markup(lang, run))
        await callback.answer()
    except Exception as exc:
        await fail(callback, lang, exc)


@dp.callback_query(F.data.startswith("run:cancel:"))
async def run_cancel(callback: CallbackQuery):
    lang = await language(callback.from_user.id)
    try:
        run_id = int(callback.data.rsplit(":", 1)[1])
        await api_post(f"{CONTROL}/runs/{callback.from_user.id}/{run_id}/cancel")
        await callback.answer(tr(lang, "run_cancelled"))
        run = await api_get(f"{CONTROL}/runs/{callback.from_user.id}/{run_id}")
        await edit(callback.message, format_run(lang, run), run_markup(lang, run))
    except Exception as exc:
        await fail(callback, lang, exc)


async def prechecks_view(message: Message, telegram_id: int, page: int):
    lang = await language(telegram_id)
    data = await api_get(f"{CONTROL}/prechecks/{telegram_id}")
    all_items, size = data.get("items", []), 8
    total = max(1, (len(all_items) + size - 1) // size)
    page = max(0, min(page, total - 1))
    items = all_items[page * size:(page + 1) * size]
    rows = [[button(f"{status_text(lang, item['status'])} · {item['endpoint_a']['name']} ↔ {item['endpoint_b']['name']}"[:55], f"pc:view:{item['id']}")] for item in items]
    pager = []
    if page:
        pager.append(button(tr(lang, "previous"), f"pc:list:{page-1}"))
    if page + 1 < total:
        pager.append(button(tr(lang, "next"), f"pc:list:{page+1}"))
    if pager:
        rows.append(pager)
    rows += [[button(tr(lang, "precheck_new"), "pc:start")], [button(tr(lang, "home"), "home")]]
    text = tr(lang, "precheck_list") + ("\n\n" + tr(lang, "precheck_empty") if not all_items else "")
    await edit(message, text, kb(rows))


@dp.callback_query(F.data.startswith("pc:list:"))
async def pc_list(callback: CallbackQuery):
    try:
        await prechecks_view(callback.message, callback.from_user.id, int(callback.data.rsplit(":", 1)[1]))
        await callback.answer()
    except Exception as exc:
        await fail(callback, await language(callback.from_user.id), exc)


@dp.callback_query(F.data == "pc:start")
async def pc_start(callback: CallbackQuery, state: FSMContext):
    await state.clear()
    lang = await language(callback.from_user.id)
    try:
        data = await api_get(f"{CONTROL}/endpoints/{callback.from_user.id}")
        items = [item for item in data["items"] if item["status"] == "READY"]
        rows = [[button(item["name"][:55], f"pc:a:{item['id']}")] for item in items]
        rows.append([button(tr(lang, "back"), "pc:list:0")])
        await edit(callback.message, tr(lang, "select_a"), kb(rows))
        await callback.answer()
    except Exception as exc:
        await fail(callback, lang, exc)


@dp.callback_query(F.data.startswith("pc:a:"))
async def pc_a(callback: CallbackQuery, state: FSMContext):
    lang = await language(callback.from_user.id)
    try:
        a = int(callback.data.rsplit(":", 1)[1])
        await state.update_data(precheck_a=a)
        data = await api_get(f"{CONTROL}/endpoints/{callback.from_user.id}")
        items = [item for item in data["items"] if item["status"] == "READY" and item["id"] != a]
        rows = [[button(item["name"][:55], f"pc:b:{item['id']}")] for item in items]
        rows.append([button(tr(lang, "back"), "pc:start")])
        await edit(callback.message, tr(lang, "select_b"), kb(rows))
        await callback.answer()
    except Exception as exc:
        await fail(callback, lang, exc)


@dp.callback_query(F.data.startswith("pc:b:"))
async def pc_b(callback: CallbackQuery, state: FSMContext):
    lang = await language(callback.from_user.id)
    try:
        values = await state.get_data()
        result = await api_post(f"{CONTROL}/prechecks", {"telegram_id": callback.from_user.id, "endpoint_a_id": values["precheck_a"], "endpoint_b_id": int(callback.data.rsplit(":", 1)[1])})
        await state.clear()
        await edit(callback.message, tr(lang, "precheck_queued", id=result["precheck_id"]), kb([[button(tr(lang, "details"), f"pc:view:{result['precheck_id']}")]]))
        await callback.answer()
    except Exception as exc:
        await fail(callback, lang, exc)


def mark(value):
    if value is True:
        return "✅"
    if isinstance(value, dict) and any(value.get(key) is True for key in ("ok", "reachable", "success")):
        return "✅"
    if value is False:
        return "❌"
    return "—"


@dp.callback_query(F.data.startswith("pc:view:"))
async def pc_view(callback: CallbackQuery):
    lang = await language(callback.from_user.id)
    try:
        precheck_id = int(callback.data.rsplit(":", 1)[1])
        data = await api_get(f"{CONTROL}/prechecks/{callback.from_user.id}/{precheck_id}")
        result, job = data.get("result", {}), data.get("job", {})
        a_to_b = result.get("a_to_b") or result.get("A_TO_B") or {}
        b_to_a = result.get("b_to_a") or result.get("B_TO_A") or {}
        text = tr(lang, "precheck_detail", id=data["id"], status=status_text(lang, data.get("status")), connectivity=esc(result.get("connectivity", "-")), a_to_b=mark(a_to_b), b_to_a=mark(b_to_a), progress=job.get("progress", 0))
        await edit(callback.message, text, kb([[button(tr(lang, "refresh"), f"pc:view:{precheck_id}")], [button(tr(lang, "back"), "pc:list:0")]]))
        await callback.answer()
    except Exception as exc:
        await fail(callback, lang, exc)


async def jobs_view(message: Message, telegram_id: int, page: int):
    lang = await language(telegram_id)
    data = await api_get(f"{CONTROL}/jobs/{telegram_id}")
    all_items, size = data.get("items", []), 8
    total = max(1, (len(all_items) + size - 1) // size)
    page = max(0, min(page, total - 1))
    items = all_items[page * size:(page + 1) * size]
    rows = [[button(f"{status_text(lang, item['status'])} · #{item['id']} {item['job_type']}"[:55], f"job:view:{item['id']}")] for item in items]
    pager = []
    if page:
        pager.append(button(tr(lang, "previous"), f"job:list:{page-1}"))
    if page + 1 < total:
        pager.append(button(tr(lang, "next"), f"job:list:{page+1}"))
    if pager:
        rows.append(pager)
    rows.append([button(tr(lang, "home"), "home")])
    text = tr(lang, "job_list") + ("\n\n" + tr(lang, "job_empty") if not all_items else "")
    await edit(message, text, kb(rows))


@dp.callback_query(F.data.startswith("job:list:"))
async def job_list(callback: CallbackQuery):
    try:
        await jobs_view(callback.message, callback.from_user.id, int(callback.data.rsplit(":", 1)[1]))
        await callback.answer()
    except Exception as exc:
        await fail(callback, await language(callback.from_user.id), exc)


@dp.callback_query(F.data.startswith("job:view:"))
async def job_view(callback: CallbackQuery):
    lang = await language(callback.from_user.id)
    try:
        job_id = int(callback.data.rsplit(":", 1)[1])
        data = await api_get(f"{EXISTING}/jobs/{callback.from_user.id}/{job_id}")
        events = "\n".join(f"• {esc(item.get('message'))}" for item in data.get("events", [])[-10:]) or "-"
        text = tr(lang, "job_detail", id=data["id"], type=esc(data.get("job_type", "-")), status=status_text(lang, data.get("status")), progress=data.get("progress", 0), step=esc(data.get("current_step")), events=events)
        await edit(callback.message, text, kb([[button(tr(lang, "refresh"), f"job:view:{job_id}")], [button(tr(lang, "back"), "job:list:0")]]))
        await callback.answer()
    except Exception as exc:
        await fail(callback, lang, exc)


@dp.callback_query(F.data == "method:cats")
async def method_cats(callback: CallbackQuery):
    lang = await language(callback.from_user.id)
    try:
        data = await catalog(callback.from_user.id)
        rows = [[button(category[:55], f"method:cat:{index}")] for index, category in enumerate(data["categories"])]
        rows.append([button(tr(lang, "home"), "home")])
        await edit(callback.message, tr(lang, "method_categories", count=data["implemented_count"]), kb(rows))
        await callback.answer()
    except Exception as exc:
        await fail(callback, lang, exc)


@dp.callback_query(F.data.startswith("method:cat:"))
async def method_cat(callback: CallbackQuery):
    lang = await language(callback.from_user.id)
    try:
        index = int(callback.data.rsplit(":", 1)[1])
        data = await catalog(callback.from_user.id)
        category = data["categories"][index]
        items = [item for item in data["methods"] if item["category"] == category]
        rows = [[button(item["name"][:55], f"method:view:{item['id']}")] for item in items]
        rows.append([button(tr(lang, "back"), "method:cats")])
        lines = "\n".join(f"• <code>{esc(item['id'])}</code>" for item in items)
        await edit(callback.message, tr(lang, "method_list", category=esc(category), methods=lines), kb(rows))
        await callback.answer()
    except Exception as exc:
        await fail(callback, lang, exc)


@dp.callback_query(F.data.startswith("method:view:"))
async def method_view(callback: CallbackQuery):
    lang = await language(callback.from_user.id)
    try:
        method_id = callback.data.split(":", 2)[2]
        data = await catalog(callback.from_user.id)
        item = next(row for row in data["methods"] if row["id"] == method_id)
        text = tr(lang, "method_detail", name=esc(item["name"]), id=esc(item["id"]), category=esc(item["category"]), layer=esc(item["layer"]), directions=esc(", ".join(item.get("directions", []))), flags=esc(", ".join(item.get("flags", []))), description=esc(item.get("description", "-")))
        category_index = data["categories"].index(item["category"])
        await edit(callback.message, text, kb([[button(tr(lang, "plan_create"), "wizard:start")], [button(tr(lang, "back"), f"method:cat:{category_index}")]]))
        await callback.answer()
    except Exception as exc:
        await fail(callback, lang, exc)


@dp.callback_query(F.data == "admin")
async def admin(callback: CallbackQuery):
    lang = await language(callback.from_user.id)
    await edit(callback.message, tr(lang, "admin_detail"), kb([[button(tr(lang, "open_panel"), url=f"{WEB_BASE}/admin")], [button(tr(lang, "home"), "home")]]))
    await callback.answer()


async def set_commands(bot: Bot):
    values = {
        "en": ("Open NetAuto", "Main menu"),
        "fa": ("شروع ربات", "منوی اصلی"),
        "ru": ("Запустить", "Главное меню"),
        "zh": ("启动机器人", "主菜单"),
        "de": ("Bot starten", "Hauptmenü"),
    }
    await bot.set_my_commands([BotCommand(command="start", description=values["en"][0]), BotCommand(command="menu", description=values["en"][1])])
    for code, labels in values.items():
        with suppress(Exception):
            await bot.set_my_commands([BotCommand(command="start", description=labels[0]), BotCommand(command="menu", description=labels[1])], language_code=code)


async def main():
    if not ENABLED:
        logger.warning("Telegram bot is disabled")
        while True:
            await asyncio.sleep(3600)
    if not TOKEN:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is empty")
    if not BOT_KEY:
        raise RuntimeError("BOT_INTERNAL_API_KEY is empty")
    bot = Bot(TOKEN)
    await set_commands(bot)
    logger.info("%s multilingual Telegram bot started", BRAND)
    await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())


if __name__ == "__main__":
    asyncio.run(main())
