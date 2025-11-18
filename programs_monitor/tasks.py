from celery import shared_task
from .models import ProgramWatcher
from django.utils.timezone import now
import colorama , json , requests , time , subprocess
from requests.exceptions import RequestException
from .models import *
from .telegram_bot import * # type: ignore
from infodisclosure_backend.settings import *
from urllib.parse import quote_plus
import threading
# if you want this 

publicwatcher_summary = {
    "Bugcrowd" : 0,
    "Hackerone" : 0,
    "Intigriti" : 0,
    "Yeswehack" : 0,
    "Federacy" : 0,
}


def sendmessage(message: str, telegram: bool = False, colour: str = "YELLOW", logger: bool = True):
    color = getattr(colorama.Fore, colour.upper(), colorama.Fore.YELLOW)
    print(color + message + colorama.Style.RESET_ALL)

    timestamp = time.strftime("%d/%m/%Y, %H:%M:%S", time.localtime())
    if logger:
        with open('logger.txt', 'a', encoding='utf-8') as file:
            file.write(f"{message} -> {timestamp}\n")

    if telegram:
        escaped_message = message.replace(' ', '+')
        command = (
            f'curl -X POST "https://api.telegram.org/bot{TELEGRAM_CONF["token"]}/sendMessage" '
            f'-d "chat_id={TELEGRAM_CONF["chat_id"]}&text=<code>{escaped_message}</code>&parse_mode=HTML"'
        )
        subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(1)



def request(url: str, name:str ,  retries: int = 20, delay: int = 5) -> dict:
    sendmessage (f"[Program-Watcher] ℹ️ getting new programs from {name} " , telegram=True)
    attempts = 0
    while attempts < retries:
        try:
            response = requests.get(url , timeout=10)
            response.raise_for_status()
            data = response.json()
            sendmessage(f"[Program-Watcher] ℹ️ Connection OK" , colour='GREEN' , telegram=True)
            return data
        except (RequestException, json.JSONDecodeError) as e:
            sendmessage(f"  [Program-Watcher] ❌ Failed to retrieve data: {e}. Retrying in {delay} seconds...", colour='RED',telegram=True)
            attempts += 1
            time.sleep(delay)
        except Exception as e:
            sendmessage(f"  [Program-Watcher] ❌ An unexpected error occurred: {e}" , colour='RED',telegram=True)
            break
    sendmessage(f"  [Program-Watcher] ❌ Failed to retrieve data after {retries} attempts." , colour='RED',telegram=True)
    return None # type: ignore




def delete_label (watcherprogram):
    try : 
        program_obj = DiscoverdProgram.objects.filter(watcher = watcherprogram)
        program_obj.update(label = "available")
        DiscoverdScope.objects.filter(discovered_program__in=program_obj).update(label='available')
        DiscoverdProgram.objects.filter(watcher=watcherprogram).update(label='available')

    except Exception as e :
        sendmessage(f"  [Program-Watcher] ❌ error while deleting label {e}", colour='RED',telegram=True)




def get_bugcrowd_programs(data, watcherprogram):
    def map_asset_type(asset_type):
        if asset_type == 'website':
            return 'web'
        elif asset_type == 'api':
            return 'api'
        elif asset_type == 'hardware':
            return 'iot'
        elif asset_type in ['ios', 'android']:
            return 'mobile'
        else:
            return 'others'

    def save_scope(program_obj, item, scope_type):
        obj, created = DiscoverdScope.objects.update_or_create(
            discovered_program=program_obj,
            name=item.get('name', ''),
            defaults={
                'type': map_asset_type(item.get('type')),
                'scope_type': scope_type
            }
        )
        if created:
            publicwatcher_summary["Bugcrowd"] += 1
            # asyncio.run(startbot(program_obj.name, item.get('target' , ''), program_obj.watcher.platform_name, program_obj.updated_at.strftime("%Y-%m-%d | %H:%M:%S"), program_obj.url , scope_type , program_obj.type))
            obj.label = 'new'
            obj.save()

            
    try:
        for program in data:
            program_obj, created = DiscoverdProgram.objects.update_or_create(
                name=program.get("name", ""),
                defaults={
                    "watcher": watcherprogram,
                    "url": program.get("url", ""),
                    "type": 'vdp' if program.get("allows_disclosure") else 'rdp'
                }
            )

            if created:                
                program_obj.label = "new"
                program_obj.save()

            for item in program.get("targets", {}).get("in_scope", []):
                try:
                    save_scope(program_obj, item, 'in_scope')
                except Exception as e:
                    sendmessage(f"  [Program-Watcher] ❌ in_scope error: {e}", colour='RED',telegram=True)

            for item in program.get("targets", {}).get("out_of_scope", []):
                try:
                    save_scope(program_obj, item, 'out_of_scope')
                except Exception as e:
                    sendmessage(f"  [Program-Watcher] ❌ out_of_scope error: {e}", colour='RED',telegram=True)

        sendmessage('       [Program-Watcher] ✅ Bugcrowd Data Inserting Successfully', colour='GREEN',telegram=True)

    except Exception as e:
        sendmessage(f'  [Program-Watcher] ❌ Error: {e}', colour='RED',telegram=True)





def get_hackerone_programs(data, watcherprogram):
    def map_asset_type(asset_type):
        if asset_type == 'AI_MODEL':
            return 'ai_model'
        elif asset_type == 'API':
            return 'api'
        elif asset_type in ['APPLE_STORE_APP_ID', 'GOOGLE_PLAY_APP_ID', 'WINDOWS_APP_STORE_APP_ID', 'OTHER_APK', 'OTHER_IPA', 'TESTFLIGHT']:
            return 'mobile'
        elif asset_type in ['CIDR', 'IP_ADDRESS']:
            return 'infrastructure'
        elif asset_type == 'HARDWARE':
            return 'iot'
        elif asset_type == 'SMART_CONTRACT':
            return 'web3'
        elif asset_type == 'DOWNLOADABLE_EXECUTABLES':
            return 'desktop'
        elif asset_type == 'WILDCARD':
            return 'wildcard'
        elif asset_type == 'URL':
            return 'web'
        elif asset_type == 'SOURCE_CODE':
            return 'code'
        else:
            return 'others'

    def save_scope(program_obj, item, scope_type):
        obj, created = DiscoverdScope.objects.update_or_create(
            discovered_program=program_obj,
            name=item.get('asset_identifier', ''),
            defaults={
                'type': map_asset_type(item.get('asset_type')),
                'scope_type': scope_type
            }
        )
        if created:
            publicwatcher_summary["Hackerone"] += 1
            # asyncio.run(startbot(program_obj.name, item.get('asset_identifier' , ''), program_obj.watcher.platform_name, program_obj.updated_at.strftime("%Y-%m-%d | %H:%M:%S"), program_obj.url , scope_type , program_obj.type))
            obj.label = 'new'
            obj.save()
    try:
        for program in data:
            program_obj, created = DiscoverdProgram.objects.update_or_create(
                name=program.get("name", ""),
                defaults={
                    "watcher": watcherprogram,
                    "url": program.get("url", ""),
                    "type": 'rdp' if program.get("offers_bounties") else 'vdp'
                }
            )

            if created:
                program_obj.label = "new"
                program_obj.save()

            for item in program.get("targets", {}).get("in_scope", []):
                try:
                    save_scope(program_obj, item, 'in_scope')
                except Exception as e:
                    sendmessage(f"  [Program-Watcher] ❌ in_scope error: {e}", colour='RED',telegram=True)

            for item in program.get("targets", {}).get("out_of_scope", []):
                try:
                    save_scope(program_obj, item, 'out_of_scope')
                except Exception as e:
                    sendmessage(f"  [Program-Watcher] ❌ out_of_scope error: {e}", colour='RED',telegram=True)

        sendmessage('       [Program-Watcher] ✅ Hackerone Data Inserting Successfully', colour='GREEN' , telegram=True)

    except Exception as e:
        sendmessage(f"  [Program-Watcher] ❌ Error: {e}", colour='RED',telegram=True)



def get_federacy_programs(data, watcherprogram):
    def map_asset_type(asset_type):
        if asset_type == 'api':
            return 'api'
        elif asset_type == 'desktop':
            return 'desktop'
        elif asset_type == 'mobile':
            return 'mobile'
        elif asset_type == 'website':
            return 'web'
        else:
            return 'others'
        
        
    def save_scope(program_obj, item, scope_type):
        obj, created = DiscoverdScope.objects.update_or_create(
            discovered_program=program_obj,
            name=item.get('target', ''),
            defaults={
                'type': map_asset_type(item.get('type')),
                'scope_type': scope_type
            }
        )
        if created:
            publicwatcher_summary["Federacy"] += 1
            # asyncio.run(startbot(program_obj.name, item.get('target' , ''), program_obj.watcher.platform_name, program_obj.updated_at.strftime("%Y-%m-%d | %H:%M:%S"), program_obj.url , scope_type , program_obj.type))
            obj.label = 'new'
            obj.save()

    try:
        for program in data:
            program_obj, created = DiscoverdProgram.objects.update_or_create(
                name=program.get("name", ""),
                defaults={
                    "watcher": watcherprogram,
                    "url": program.get("url", ""),
                    "type": 'rdp' if program.get("offers_awards") else 'vdp'
                }
            )

            if created:
                program_obj.label = "new"
                program_obj.save()

            for item in program.get("targets", {}).get("in_scope", []):
                try:
                    save_scope(program_obj, item, 'in_scope')
                except Exception as e:
                    sendmessage(f"  [Program-Watcher] ❌ in_scope error: {e}", colour='RED',telegram=True)

            for item in program.get("targets", {}).get("out_of_scope", []):
                try:
                    save_scope(program_obj, item, 'out_of_scope')
                except Exception as e:
                    sendmessage(f"  [Program-Watcher] ❌ out_of_scope error: {e}", colour='RED',telegram=True)

        sendmessage('       [Program-Watcher] ✅ Federacy Data Inserting Successfully', colour='GREEN' , telegram=True)

    except Exception as e:
        sendmessage(f"  [Program-Watcher] ❌ Error: {e}", colour='RED',telegram=True)




def get_intigriti_programs (data, watcherprogram):
    def map_asset_type(asset_type):
        if asset_type in ['android' , 'ios']:
            return 'mobile'
        elif asset_type == 'device':
            return 'iot'
        elif asset_type == 'iprange':
            return 'infrastructure'
        elif asset_type == 'url':
            return 'web'
        elif asset_type == 'wildcard':
            return 'wildcard'
        else:
            return 'others'
        
        
    def save_scope(program_obj, item, scope_type):
        obj, created = DiscoverdScope.objects.update_or_create(
            discovered_program=program_obj,
            name=item.get('endpoint', ''),
            defaults={
                'type': map_asset_type(item.get('type')),
                'scope_type': scope_type
            }
        )
        if created:
            publicwatcher_summary["Intigriti"] += 1
            # asyncio.run(startbot(program_obj.name, item.get('endpoint' , ''), program_obj.watcher.platform_name, program_obj.updated_at.strftime("%Y-%m-%d | %H:%M:%S"), program_obj.url , scope_type , program_obj.type))
            obj.label = 'new'
            obj.save()

    try:
        for program in data:
            program_obj, created = DiscoverdProgram.objects.update_or_create(
                name=program.get("name", ""),
                defaults={
                    "watcher": watcherprogram,
                    "url": program.get("url", ""),
                    "type": "rdp" if program.get("min_bounty", {}).get("value", 0) > 0 else "vdp",
                }
            )

            if created:
                program_obj.label = "new"
                program_obj.save()

            for item in program.get("targets", {}).get("in_scope", []):
                try:
                    save_scope(program_obj, item, 'in_scope')
                except Exception as e:
                    sendmessage(f"  [Program-Watcher] ❌ in_scope error: {e}", colour='RED',telegram=True)

            for item in program.get("targets", {}).get("out_of_scope", []):
                try:
                    save_scope(program_obj, item, 'out_of_scope')
                except Exception as e:
                    sendmessage(f"  [Program-Watcher] ❌ out_of_scope error: {e}", colour='RED',telegram=True)

        sendmessage('       [Program-Watcher] ✅ Intigriti Data Inserting Successfully', colour='GREEN' , telegram=True)

    except Exception as e:
        sendmessage(f"  [Program-Watcher] ❌ Error: {e}", colour='RED',telegram=True)




def get_yeswehack_programs (data, watcherprogram):
    def map_asset_type(asset_type , target):
        if asset_type in ['mobile-application' , 'mobile-application-android' , 'mobile-application-ios' , 'application']:
            return 'mobile'
        elif asset_type == 'api':
            return 'api'
        elif asset_type == 'web-application':
            return 'web'
        elif '*' in target:
            return 'wildcard'
        else:
            return 'others'
        
        
    def save_scope(program_obj, item, scope_type):
        obj, created = DiscoverdScope.objects.update_or_create(
            discovered_program=program_obj,
            name=item.get('target', ''),
            defaults={
                'type': map_asset_type(item.get('type') , item.get('target')),
                'scope_type': scope_type
            }
        )
        if created:
            publicwatcher_summary["Yeswehack"] += 1
            # asyncio.run(startbot(program_obj.name, item.get('target' , ''), program_obj.watcher.platform_name, program_obj.updated_at.strftime("%Y-%m-%d | %H:%M:%S"), 'https://yeswehack.com' , scope_type , program_obj.type))
            obj.label = 'new'
            obj.save()
    try:
        for program in data:
            program_obj, created = DiscoverdProgram.objects.update_or_create(
                name=program.get("name", ""),
                defaults={
                    "watcher": watcherprogram,
                    "url": program.get("url", ""),
                    "type": "vdp" if program.get("min_bounty")=="null" else "rdp",
                }
            )

            if created:
                program_obj.label = "new"
                program_obj.save()

            for item in program.get("targets", {}).get("in_scope", []):
                try:
                    save_scope(program_obj, item, 'in_scope')
                except Exception as e:
                    sendmessage(f"  [Program-Watcher] ❌ in_scope error: {e}", colour='RED',telegram=True)

            for item in program.get("targets", {}).get("out_of_scope", []):
                try:
                    save_scope(program_obj, item, 'out_of_scope')
                except Exception as e:
                    sendmessage(f"  [Program-Watcher] ❌ out_of_scope error: {e}", colour='RED',telegram=True)

        sendmessage('       [Program-Watcher] ✅ Yeswehack Data Inserting Successfully', colour='GREEN' , telegram=True)

    except Exception as e:
        sendmessage(f"  [Program-Watcher] ❌ Error: {e}", colour='RED',telegram=True)




@shared_task
def check_programs():
    
    watcherprograms = ProgramWatcher.objects.filter(is_active = True)
    ProgramWatcher.objects.filter(is_active = True ).update(status='pending')

    for program in watcherprograms :
        try : 
            data = request(program.platform_url , program.platform_name)
            program.status = 'running'
            program.save()
            delete_label(program)
            if program.platform_name == 'Bugcrowd':
                get_bugcrowd_programs(data , program)

            if program.platform_name == 'Hackerone':
                get_hackerone_programs(data , program)

            if program.platform_name == 'Federacy':
                get_federacy_programs(data ,program)

            if program.platform_name == 'Intigriti':
                get_intigriti_programs(data, program)

            if program.platform_name == 'Yeswehack':
                get_yeswehack_programs (data , program)

            program.status = 'completed'
            program.save()

        except TypeError as e :
            program.status = 'failed'
            program.save()
            
            sendmessage(f'[Program-Watcher] ❌ While Check Programs: {e}' , colour='RED',telegram=True)
    
    sendmessage(f"[Program-Watcher] ✅ Program Monitoring Successfully Done" , colour="CYAN",telegram=True)

    asyncio.run(send_summary_to_channel(publicwatcher_summary))
            