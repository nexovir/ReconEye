import asyncio
import time
import colorama
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Bot
from telegram.request import HTTPXRequest
import nest_asyncio

# حل مشکل event loop بسته‌شده
nest_asyncio.apply()

BOT_TOKEN = "6348870305:AAHawStCiN6XfiAu_ZwQJU-x8C1XtKjZ2XA"
GROUP_ID = -1002632654795
TOPIC_ID = 16
SUMMARY_CHANNEL_ID = -1002451703408 

request = HTTPXRequest(
    connect_timeout=10,
    read_timeout=10,
    pool_timeout=30,
    proxy="socks5://127.0.0.1:1080"
)

bot = Bot(token=BOT_TOKEN, request=request)
sem = asyncio.Semaphore(1) 

async def send_message_to_channel(name, scope, platform, time_date, url, target_type, _type):
    try:
        keyboard = [
            [InlineKeyboardButton(f"⚡️ Visit {target_type} on {platform.upper()} ⚡️", url=url)],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await bot.send_message(
            chat_id=GROUP_ID,
            message_thread_id=TOPIC_ID,
            text=f'''🔺 <b>NEW {target_type.upper()}</b> 🔻

Name : <b>{name}</b>

{target_type} : <pre>{scope}</pre>      
Platform : <b>{platform.upper()}</b>   

Date : <i>{time_date}</i>     

Type : <b>{_type.upper()}</b>

<i>Tags :</i> 
#new_{target_type} #zerosec #bugbounty
#{platform}

──────────────
📡 Follow :
👉 @zerosec_team
''',
            reply_markup=reply_markup,
            parse_mode="HTML",
        )

        await asyncio.sleep(1)

    except Exception as e:
        print(colorama.Fore.RED + f"[!] Error sending message: {e}" + colorama.Style.RESET_ALL)

async def startbot(name, scope, platform, time_date, url, target_type, _type):
    async with sem:
        await send_message_to_channel(name, scope, platform, time_date, url, target_type, _type)
        await asyncio.sleep(5)



async def send_summary_to_channel(platform_counter):
    try:
        summary_lines = ["📊 <b>Watcher Summary Report</b>\n"]
        for plat, count in platform_counter.items():
            summary_lines.append(f"🔹 <b>{plat.upper()}</b>: {count} new item{'s' if count > 1 else ''}")

        summary_lines.append('\n🔗 Details: <a href="https://t.me/zerosec_group/16">Click here</a>')
        summary_lines.append('\n#zerosec #bugbounty #watcher #summary_report')
        summary_lines.append("\n──────────────")
        summary_lines.append("📡 Follow :\n👉 @zerosec_team")

        summary_text = "\n".join(summary_lines)

        keyboard = [
            [InlineKeyboardButton("🚀 Visit Details on ZeroSec", url="https://t.me/zerosec_group/16")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await bot.send_message(
            chat_id=SUMMARY_CHANNEL_ID,
            text=summary_text,
            reply_markup=reply_markup,
            parse_mode="HTML",
            disable_web_page_preview=True,
        )
        print("Summary sent successfully.")

    except Exception as e:
        print(colorama.Fore.RED + f"[!] Error sending summary message: {e}" + colorama.Style.RESET_ALL)



def startbot_sync(name, scope, platform, time_date, url, target_type, _type):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        asyncio.create_task(startbot(name, scope, platform, time_date, url, target_type, _type))
    else:
        asyncio.run(startbot(name, scope, platform, time_date, url, target_type, _type))
