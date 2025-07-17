import colorama , time , asyncio , os
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Bot
from telegram.request import HTTPXRequest
import nest_asyncio

nest_asyncio.apply()
BOT_TOKEN = "6348870305:AAHawStCiN6XfiAu_ZwQJU-x8C1XtKjZ2XA"
GROUP_ID = -1002827285846

request = HTTPXRequest(
    connect_timeout=10,
    read_timeout=10,
    pool_timeout=30,
    proxy="socks5://127.0.0.1:1080"
)

bot = Bot(token=BOT_TOKEN, request=request)
sem = asyncio.Semaphore(1) 


def httpx(sub):
    sub_httpx = os.popen(f"httpx -u {sub.strip()} -silent").read().strip()
    return sub_httpx


async def send_new_assets(domain, subdomain, tool, time_date):
    try:
        keyboard = [
            [InlineKeyboardButton(f"⚡️ Visit {subdomain}⚡️", url=httpx(subdomain))],
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await bot.send_message(
            chat_id=GROUP_ID,
            message_thread_id=1818,
            text=f'''🔺 <b>NEW ASSET</b> 🔻

Domain : <b>{domain}</b>

Asset : <pre>{subdomain}</pre>  

Tool : {tool}

Date : <i>{time_date}</i>     

<i>Tags :</i> 
#new_asset #zerosec #bugbounty #{domain} #asset

──────────────
📡 Follow :
👉 @zerosec_team
''',
            reply_markup=reply_markup,
            parse_mode="HTML",
        )

        await asyncio.sleep(3)

    except Exception as e:
        print(colorama.Fore.RED + f"[!] Error sending message: {e}" + colorama.Style.RESET_ALL)



async def send_new_httpx(message_title ,httpx_result , status_code , server , technologies , ip_port , has_cdn , title , hash_header , hash_body , time_date):
    try:
        await bot.send_message(
            chat_id=GROUP_ID,
            message_thread_id=1818,
            text=f'''🔺 <b>NEW {message_title.upper()} RESULT</b> 🔻

httpx_result : <pre>{httpx_result}</pre>  

status_code : <b>{status_code}</b>

server : <i>{server}</i>     

technologies : <i>{technologies}</i>

ip_port : <b>{ip_port}</b>

has_cdn : <b>{has_cdn}</b>

title : <i>{title}</i>

hash_header : <b>{hash_header}</b>

hash_body : <b>{hash_body}</b>

Date : <i>{time_date}</i>


<i>Tags :</i> 
#new_asset #zerosec #bugbounty #{message_title.replace(" " , "_").lower()}

──────────────
📡 Follow :
👉 @zerosec_team
''',
            parse_mode="HTML",
        )

        await asyncio.sleep(5)

    except Exception as e:
        print(colorama.Fore.RED + f"[!] Error sending message: {e}" + colorama.Style.RESET_ALL)



async def send_new_cidr(message_title ,ip , port , time_date , status_code):
    try:
        await bot.send_message(
            chat_id=GROUP_ID,
            message_thread_id=1818,
            text=f'''🔺 <b>NEW {message_title.upper()} RESULT</b> 🔻

ip : <pre>{ip}{port}</pre>  

status_code : <b>{status_code}</b>

Date : <i>{time_date}</i>


<i>Tags :</i> 
#new_asset #zerosec #bugbounty #{message_title.replace(" " , "_").lower()}

──────────────
📡 Follow :
👉 @zerosec_team
''',
            parse_mode="HTML",
        )

        await asyncio.sleep(5)

    except Exception as e:
        print(colorama.Fore.RED + f"[!] Error sending message: {e}" + colorama.Style.RESET_ALL)





async def startbot(domain, subdomain, tool, time_date):
    async with sem:
        await send_new_assets(domain, subdomain, tool, time_date)
        await asyncio.sleep(5)



def startbot_sync(domain, subdomain, tool, time_date):
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        asyncio.create_task(startbot(domain, subdomain, tool, time_date))
    else:
        asyncio.run(startbot(domain, subdomain, tool, time_date))




