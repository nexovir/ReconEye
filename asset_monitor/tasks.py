from celery import shared_task
from django.utils.timezone import now  # type: ignore
import colorama, json, time, subprocess, pydig, os , tempfile
from .models import *
from datetime import datetime
from .telegram_bot import *
from programs_monitor.tasks import *

OUTPUT_PATH = 'asset_monitor/outputs'
WORDLISTS_PATH = 'asset_monitor/wordlists'



def clear_subdomains_labels(watcher):
    DiscoverSubdomain.objects.filter(wildcard=watcher).update(label="available")

def clear_httpx_labels():
    SubdomainHttpx.objects.filter(is_active = True).update(label='available')

def clear_services_labels():
    DiscoverdServices.objects.filter(is_active = True).update(label = 'available')
    DiscoverdServicesAlive.objects.filter(is_active = True).update(label = 'available')

def run_subfinder(domain):
    try:
        sendmessage(f"[Asset-Watcher] ℹ️ Starting Subfinder for '{domain}'..." , telegram=False)
        output = os.popen(f"subfinder -d {domain} -all -silent -timeout 60 -max-time 60 | dnsx -silent").read()
        subdomains = [line.strip() for line in output.splitlines() if line.strip()]
        sendmessage(f"  ℹ️ {len(subdomains)} subs found for {domain}", colour='GREEN' ,  telegram = False)
        return subdomains
    except Exception as e:
        sendmessage(f"  [Asset-Watcher] ❌ Error running Subfinder on {domain}: {e}", colour='RED')
        return []


def run_crtsh(domain, retries=1, timeout=15):  
    for attempt in range(1, retries + 1):
        try:
            sendmessage(f"[Asset-Watcher] ℹ️ Attempt {attempt}: Starting CRT.sh for '{domain}'...", telegram = False)

            command = f"curl -s 'https://crt.sh/?q={domain}&output=json | jq -r '.[].name_value' | sort -u | dnsx -silent"

            output = subprocess.run(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                text=True
            )

            subdomains = [line.strip() for line in output.stdout.splitlines() if line.strip()]
            
            if subdomains:
                sendmessage(f"  [Asset-Watcher] ℹ️ {len(subdomains)} subs found for {domain}", colour='GREEN' , telegram = False)
                return subdomains
            else:
                sendmessage(f"  [Asset-Watcher] ⚠️ No subdomains found for {domain} in Crt.sh (Attempt {attempt})", colour='YELLOW' , telegram = False)

        except subprocess.TimeoutExpired:
            sendmessage(f"  [Asset-Watcher] [TIMEOUT] Crt.sh took longer than {timeout}s for {domain} (Attempt {attempt})", colour='YELLOW' , telegram = False)

        except Exception as e:
            sendmessage(f"  [Asset-Watcher] ❌ Crt.sh error on attempt {attempt} for {domain}: {e}", colour='RED')

    sendmessage(f"  [Asset-Watcher] ❌ Failed to get subdomains from Crt.sh for {domain} after {retries}/2 attempts.", colour='RED')
    return []


def run_wabackurls(domain, retries=1):
    for attempt in range(1, retries + 1):
        try:
            sendmessage(f"[Asset-Watcher] ℹ️ Attempt {attempt}: Starting Waybackurls for '{domain}'...", telegram = False)
            
            output = os.popen(f"echo {domain} | waybackurls | unfurl domains | awk '!seen[$0]++' | dnsx -silent").read()
            subdomains = [line.strip() for line in output.splitlines() if line.strip()]
            
            if subdomains:
                sendmessage(f"  [Asset-Watcher] ℹ️ {len(subdomains)} subs found for {domain}", colour="GREEN" , telegram = False)
                return subdomains
            else:
                sendmessage(f"  [Asset-Watcher] ⚠️ No subdomains found in attempt {attempt} for {domain}", colour='YELLOW' , telegram = False)

        except Exception as e:
            sendmessage(f"[Asset-Watcher] ❌ Waybackurls error on attempt {attempt} for {domain}: {e}", colour='RED')

    sendmessage(f"  [Asset-Watcher] ❌ Failed to get subdomains from Waybackurls for {domain} after {retries} attempts.", colour='RED')
    return []



def run_httpx(watcher_wildcard, input_file_path):
    
    try:
        sendmessage(f"  [Asset-Watcher] ℹ️ Starting HTTPx on '{watcher_wildcard}'...", telegram = False)
            
        output_file_path = f"{input_file_path}_output.jsonl"

        command = [
            'httpx',
            '-l', input_file_path,
            '-title',
            '-status-code',
            '-hash', 'md5',
            '-tech-detect',
            '-server',
            '-websocket',
            '-ip',
            '-cdn',
            '-cname',
            '-content-type',
            '-no-color',
            # '-http-proxy',PROXIES['http'],
            '-json',
            '-silent',
            '-threads', '10',
            '-timeout', '4',
            
        ]
        with open(output_file_path, 'w') as outfile, open(os.devnull, 'w') as devnull:
            subprocess.run(command, check=True, stdout=outfile, stderr=devnull)
            
        return output_file_path

    except subprocess.CalledProcessError as e:
        sendmessage(f"[Asset-Watcher] ❌ HTTPx failed: {e}", colour='RED')
        return None


def parse_httpx_jsonl(file_path):
    sendmessage(f"  [Asset-Watcher] ℹ️ Starting Parsing Data ..." , telegram=False)
    results = []
    with open(file_path, 'r') as f:
        for line in f:
            try:
                data = json.loads(line.strip())
                results.append(data)
            except json.JSONDecodeError:
                continue
    return results


def save_httpx_results(results):

    for item in results:
        domain = item.get("input")
        try:
            discovered = DiscoverSubdomain.objects.get(subdomain=domain)
        except DiscoverSubdomain.DoesNotExist:
            continue

        hash_info = item.get("hash", {})

        new_data = {
            "httpx_result": item.get("url") or "",
            "status_code": item.get("status_code") or "",
            "title": item.get("title") or "",
            "server": item.get("webserver") or "",
            "technologies": item.get("tech") or "",

            "ip_address": item.get("host") or "",
            "port": item.get("port") or "",

            "content_type": item.get("content_type") or "",
            "line_count": item.get("lines") or "",
            "a_records": item.get("a") or "",

            "body_hash": hash_info.get("body_md5", ""),
            "header_hash": hash_info.get("header_md5", ""),

            "has_cdn": item.get("cdn") or ""
        }

        change_data = {}
        actual_changes = {}
        try:
            existing = SubdomainHttpx.objects.get(discovered_subdomain=discovered)


            for field, new_value in new_data.items():
                old_value = getattr(existing, field)
                
                if str(old_value) != str(new_value):
                    change_data[f"{field}_change"] = f"{old_value} -> {new_value}"
                    
                    if field not in ['ip_address', 'a_records', 'body_hash' , 'header_hash']:
                        actual_changes[f"{field}_change"] = f"{old_value} -> {new_value}"
                else:
                    change_data[f"{field}_change"] = str(new_value)

                    

        except SubdomainHttpx.DoesNotExist:
            existing = None

        obj, created = SubdomainHttpx.objects.update_or_create(
            discovered_subdomain=discovered,
            defaults={**new_data}
        )

        if created:
            if discovered.wildcard.watcher.notify :
                asyncio.run(send_new_httpx('httpx',item.get("url"), item.get("status_code"), item.get("webserver"), item.get("tech"), f"{item.get('host')}:{item.get('port')}", item.get("cdn"), item.get("title") , item.get("header_md5") , item.get ("body_md5"), obj.updated_at.strftime("%Y-%m-%d | %H:%M:%S")))
            obj.label = 'new'
            obj.save()


        if actual_changes: 
            changes_obj, changes_created = SubdomainHttpxChanges.objects.update_or_create(
                discovered_subdomain=discovered,
                defaults={**change_data, "label": "new"}
            )
            if changes_created:
                if discovered.wildcard.watcher.notify :
                    print(changes_created)
                    asyncio.run(send_new_httpx(
                        'httpx changes',
                        change_data.get("httpx_result_change", ""),
                        change_data.get("status_code_change", ""),
                        change_data.get("server_change", ""),
                        change_data.get("technologies_change", ""),
                        change_data.get("ip_address_change", ""),
                        change_data.get("has_cdn_change", ""),
                        change_data.get("title_change", ""),
                        change_data.get("header_hash_change", ""),
                        change_data.get("body_hash_change", ""),
                        changes_obj.updated_at.strftime("%Y-%m-%d | %H:%M:%S")
                    ))
                changes_obj.label = 'new'
                changes_obj.save()



def parse_datetime(date_str):
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except ValueError:
        return None



def export_for_httpx(subdomains , file):
    try :
        with open (file , 'w') as file:
            file.writelines([f"{s}\n" for s in subdomains])
   
    except Exception as e :
        sendmessage(f"[Asset-Watcher] ❌ Error Export domains for Httpx {e}" , colour='RED')



def process_subfinder(domains):
    try:
        tool = Tool.objects.get(tool_name='subfinder')
        for domain in domains:
            wildcards = WatchedWildcard.objects.filter(is_active=True, tools__tool_name='subfinder', wildcard=domain)

            wildcards.update(status='running')
            subdomains = run_subfinder(domain)

            for wildcard in wildcards:
                wildcard.status = 'running'
                wildcard.save()
                clear_subdomains_labels(wildcard)
                for sub in subdomains:
                    obj, created = DiscoverSubdomain.objects.get_or_create(
                        wildcard=wildcard, subdomain=sub, defaults={'tool': tool}
                    )
                    if created:
                        if wildcard.watcher.notify :
                            asyncio.run(startbot(domain, sub, tool.tool_name , wildcard.updated_at.strftime("%Y-%m-%d | %H:%M:%S")))
                        obj.label = "new"
                        obj.save()
                wildcard.status = 'completed'
                wildcard.save()
    except Exception as e:
        sendmessage(f"[Asset-Watcher] ❌ Process Subfinder error: {e}", colour='RED')



def process_crtsh(domains):
    try : 
        tool = Tool.objects.get(tool_name='crt.sh')
        for domain in domains :
            wildcards = WatchedWildcard.objects.filter(is_active=True , tools__tool_name='crt.sh' , wildcard=domain)
            wildcards.update(status='running')
            subdomains = run_crtsh(domain)
            for wildcard in wildcards:
                wildcard.status = 'running'
                wildcard.save()
                for sub in subdomains:
                    obj, created = DiscoverSubdomain.objects.get_or_create(
                        wildcard=wildcard, subdomain=sub, defaults={'tool': tool}
                    )
                    
                    if created:
                        if wildcard.watcher.notify :
                            asyncio.run(startbot(domain, sub, tool.tool_name , wildcard.updated_at.strftime("%Y-%m-%d | %H:%M:%S")))
                        obj.label = "new"
                        obj.save()
                wildcard.status = 'completed'
                wildcard.save()
    except Exception as e:
        sendmessage(f"[Asset-Watcher] ❌ Process Crt.sh error: {e}" , colour='RED')



def run_findomain(domain, retries=1, timeout=15):  
    try:
        sendmessage(f"[Asset-Watcher] ℹ️ Starting Findomain for '{domain}'..." , telegram = False)
        output = os.popen(f"findomain -t {domain} -q").read()
        subdomains = [line.strip() for line in output.splitlines() if line.strip()]
        sendmessage(f"  ℹ️ {len(subdomains)} subs found for {domain}", colour='GREEN' ,  telegram = False)
        return subdomains
    except Exception as e:
        sendmessage(f"  [Asset-Watcher] ❌ Error running Findomain on {domain}: {e}", colour='RED')
        return []



def process_findomain(domains):
    try : 
        tool = Tool.objects.get(tool_name='findomain')
        for domain in domains :
            wildcards = WatchedWildcard.objects.filter(is_active=True , tools__tool_name='findomain' , wildcard=domain)
            wildcards.update(status='running')
            subdomains = run_findomain(domain)
            for wildcard in wildcards:
                wildcard.status = 'running'
                wildcard.save()
                for sub in subdomains:
                    obj, created = DiscoverSubdomain.objects.get_or_create(
                        wildcard=wildcard, subdomain=sub, defaults={'tool': tool}
                    )
                    
                    if created:
                        if wildcard.watcher.notify :
                            asyncio.run(startbot(domain, sub, tool.tool_name , wildcard.updated_at.strftime("%Y-%m-%d | %H:%M:%S")))
                        obj.label = "new"
                        obj.save()
                wildcard.status = 'completed'
                wildcard.save()
    except Exception as e:
        sendmessage(f"[Asset-Watcher] ❌ Process Findomain error: {e}" , colour='RED')



def process_wabackurls(domains):
    try:
        tool = Tool.objects.get(tool_name='wabackurls')
        for domain in domains:
            wildcards = WatchedWildcard.objects.filter(is_active=True, tools__tool_name='wabackurls', wildcard=domain)
            wildcards.update(status='running')
            subdomains = run_wabackurls(domain)
            for wildcard in wildcards:
                wildcard.status = 'running'
                wildcard.save()
                for sub in subdomains:
                    obj, created = DiscoverSubdomain.objects.get_or_create(
                        wildcard=wildcard, subdomain=sub, defaults={'tool': tool}
                    )
                    if wildcard.watcher.notify :
                        asyncio.run(startbot(domain, sub, tool.tool_name , wildcard.updated_at.strftime("%Y-%m-%d | %H:%M:%S")))
                    if created:
                        obj.label = "new"
                        obj.save()
                wildcard.status = 'completed'
                wildcard.save()
    except Exception as e:
        sendmessage(f"[Asset-Watcher] ❌ Process wabackurls error: {e}", colour='RED')


def proccess_user_subdomains(assets):
    def read_own_subdomains(fieldfile):
        if fieldfile and fieldfile.name:
            try:
                with fieldfile.open('r') as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                sendmessage(f"[Asset-Watcher] ❌ Cannot read file: {e}", colour='RED')
                return []
        return []

    try :
        sendmessage("[Asset-Watcher] ℹ️ Starting Insert user's subdomains" , telegram = False)
        tool = Tool.objects.get(tool_name='owned')
        for asset in assets :
            watched_wildcards = WatchedWildcard.objects.filter(watcher=asset)
            for watched_wildcard in watched_wildcards :
                subdomains = read_own_subdomains(watched_wildcard.own_subdomains)
                if not subdomains:
                    sendmessage(f"  [Asset-Watcher] ⚠️ No own subdomains found for {watched_wildcard.wildcard}", colour='YELLOW' , telegram = False)
                    continue          
                watched_wildcard.status = 'running'
                watched_wildcard.save()
                for sub in subdomains:
                    obj, created = DiscoverSubdomain.objects.get_or_create(
                        wildcard=watched_wildcard, subdomain=sub, defaults={'tool': tool}
                    )
                    if created:
                        
                        obj.label = "new"
                        obj.save()
                watched_wildcard.status = 'completed'
                watched_wildcard.save()

    except Exception as e:
        sendmessage(f"[Asset-Watcher] ❌ Process User Subdomains error: {e}", colour='RED')



def process_dns_bruteforce(watcher_assets):

    def check_a_record(domain: str) -> bool:
        try:
            fake_domain = f"nonexistent1234.{domain}"
            result = pydig.query(fake_domain, 'A')
            if result:
                sendmessage(f"  [Asset-Watcher] ❌ A record verification failed for {domain}", colour='RED')


                return True
            sendmessage(f"  [Asset-Watcher] ℹ️ A record check passed for {domain}", colour='GREEN')
            return True
        except Exception as e:
            sendmessage(f"  [Asset-Watcher] ❌ DNS A record check error: {e}", colour='RED')
            return False


    def generate_dns_wordlist(asset, wildcard , discoverd_subs, discoverd_dynamic, discoverd_static, final_dns_wordlist):

        os.makedirs(os.path.dirname(discoverd_subs), exist_ok=True)

        try:
            subdomains = list(wildcard.subdomains.all().values_list('subdomain', flat=True))
            with open(discoverd_subs, 'w') as f:
                for sub in subdomains:
                    f.write(f"{sub}\n")

            sendmessage(f"  [Asset-Watcher] ℹ️ {len(subdomains)} subdomains collected for DNS bruteforce", colour='GREEN')

            with open(discoverd_subs, 'r') as infile, open(discoverd_dynamic, 'w') as outfile:
                subprocess.run(
                    ['dnsgen', '--wordlist', asset.dns_bruteforce_dynamic_wordlist.path, '-'],
                    stdin=infile,
                    stdout=outfile,
                    check=True
                )

            with open(discoverd_static, 'w') as outfile:
                subprocess.run(
                    ['awk', f'{{print $0".{wildcard.wildcard}"}}', asset.dns_bruteforce_static_wordlist.path],
                    stdout=outfile,
                    check=True
                )

            with open(final_dns_wordlist, 'w') as outfile:
                subprocess.run(
                    ['sort', '-u', discoverd_static, discoverd_dynamic],
                    stdout=outfile,
                    check=True
                )
            sendmessage(f"  [Asset-Watcher] ℹ️ Merged and sorted DNS wordlists into {final_dns_wordlist}", colour='YELLOW')
            
            return subdomains

        except subprocess.CalledProcessError as e:
            sendmessage(f"[Asset-Watcher] ❌ Command failed: {e}", colour='RED')
        except Exception as e:
            sendmessage(f"[Asset-Watcher] ❌ Unexpected error: {e}", colour='RED')

        return []


    tool = Tool.objects.get(tool_name='dns_bruteforce')

    for asset in watcher_assets:
        
        for wildcard in asset.wildcards.all():

            username = asset.user.username
            domain = wildcard.wildcard

            root_path = f"{OUTPUT_PATH}/{username}/{domain}"
            discoverd_subs = f"{root_path}/{domain}.subs"
            discoverd_dynamic = f"{root_path}/{domain}.dynamic"
            discoverd_static = f"{root_path}/{domain}.statics"
            final_dns_wordlist = f"{root_path}/{domain}.final"


            if not wildcard.tools.filter(tool_name='dns_bruteforce').exists():
                continue

            if not check_a_record(domain):
                wildcard.status = 'failed'
                wildcard.save()
                continue

            
            generate_dns_wordlist(asset, wildcard , discoverd_subs , discoverd_dynamic , discoverd_static , final_dns_wordlist)
            sendmessage(f"[Asset-Watcher] ℹ️ Starting DNS Bruteforce for {domain}", telegram = False)

            with open(f'{root_path}/{domain}.resolved', 'w') as outfile:
                puredns = subprocess.Popen(
                    [
                        'puredns', 'resolve',
                        final_dns_wordlist,
                        domain,
                        '-t', '400',
                        '-l', '1000',
                        '-r', f'{OUTPUT_PATH}/resolvers.txt'
                    ],
                    stdout=subprocess.PIPE,
                )

                dnsx = subprocess.Popen(
                    ['dnsx', '-silent'],
                    stdin=puredns.stdout,
                    stdout=outfile,
                )

                puredns.stdout.close()
                dnsx.communicate()
                puredns.wait()


            with open (f'{root_path}/{domain}.resolved' , 'r') as file:
                subdomains = [line.strip() for line in file if line.strip()]

            if not subdomains:
                sendmessage(f"[Asset-Watcher] ℹ️ No subdomains resolved for {domain}", colour='YELLOW')
                wildcard.status = 'failed'
                wildcard.save()
                continue

            for sub in subdomains:
                obj, created = DiscoverSubdomain.objects.get_or_create(
                    wildcard=wildcard, subdomain=sub, defaults={'tool': tool}
                )
                
                if created:
                    if wildcard.watcher.notify :
                        asyncio.run(startbot(domain, sub, tool.tool_name , wildcard.updated_at.strftime("%Y-%m-%d | %H:%M:%S")))
                    obj.label = "new"
                    obj.save()
                wildcard.status = 'completed'
                wildcard.save()
            sendmessage(f"  [Asset-Watcher] ℹ️ DNS Bruteforce completed for {domain}", colour='YELLOW')


def process_cidrs_scanning(watcher_cidrs):
    clear_services_labels()
    def run_naabu(watcher_cidr):
        cidr = watcher_cidr.cidr
        ports_query = watcher_cidr.ports.values_list('port', flat=True)
        ports = ",".join(port for port in ports_query if port)
        if not ports:
            return []

        try:
            result = subprocess.run(
                ['naabu', '-host', cidr, '-p', ports,'-silent'],
                capture_output=True, text=True, check=True
            )
        except subprocess.CalledProcessError as e:
            sendmessage(f"    [Asset-Watcher] ❌ Error running naabu on {cidr}: {e}" ,colour='RED' )
            return []

        for line in result.stdout.strip().split('\n'):
            if ':' in line:
                ip, port = line.strip().split(':')
                
                obj, created = DiscoverdServices.objects.get_or_create(
                    watcher=watcher_cidr,
                    ip=ip,
                    port=port,
                )
                if created:
                    if watcher_cidr.watcher.notify :
                        asyncio.run(send_new_cidr('ip' , ip , f":{port}" , obj.updated_at.strftime("%Y-%m-%d | %H:%M:%S") , ''))
                    obj.label = "new"
                    obj.save()
        

        watcher_cidr.status = 'completed'
        watcher_cidr.save()


    def run_httpx(watcher_cidr):
        sendmessage(f"  [Asset-Watcher] ℹ️ Starting HTTPx on {watcher_cidr.cidr} Assets", telegram = False)

        services = watcher_cidr.discoverd_services.all()
        if not services.exists():
            return

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            for service in services:
                if service.ip:
                    f.write(f"{service.ip}\n")
            f.flush()

        try:
            result = subprocess.run(
                ['httpx', '-l', f.name, '-sc', '-threads', '10', '-timeout','7', '-no-color','-http-proxy' , '-silent'],
                capture_output=True, text=True, check=True
            )
            print(result)
        except subprocess.CalledProcessError as e:
            sendmessage(f"[Asset-Watcher] ❌ Error running httpx: {e}", colour="RED")
            return

        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue

            try:
                main_part, status_code = line.strip().rsplit(' ', 1)
                status_code = status_code.strip('[]')
                service_url = main_part.strip()

                obj, created = DiscoverdServicesAlive.objects.get_or_create(
                    watcher=watcher_cidr,
                    service=service_url,
                    defaults={
                        'status_code': status_code,
                        'label': 'new'
                    }
                )

                if not created:
                    if watcher_cidr.watcher.notify : 
                        asyncio.run(send_new_cidr('ip httpx' , service_url , '' , obj.updated_at.strftime("%Y-%m-%d | %H:%M:%S") , status_code))
                    if obj.status_code != status_code:
                        obj.status_code = status_code
                        obj.label = "new"
                        obj.save()

            except Exception as e:
                sendmessage(f"[Asset-Watcher] ❌ Error parsing line '{line}': {str(e)}", colour="RED")





    for watcher_cidr in watcher_cidrs :
        try : 
            sendmessage(f"[Asset-Watcher] ℹ️ Scanning CIDR: {watcher_cidr.cidr}" , telegram = False)
            run_naabu(watcher_cidr)
            run_httpx(watcher_cidr)

        except Exception as e : 
            sendmessage(f"[Asset-Watcher] ❌ process cidr scanning failed {e}" , colour="RED")



def process_httpx(assets_watchers):
    clear_httpx_labels()
    subdomains_httpx = f"{OUTPUT_PATH}/subdomains_httpx.txt"
    for assets_watcher in assets_watchers:
        for watcher_wildcard in assets_watcher.wildcards.all():
            for tool in watcher_wildcard.tools.all():
                if tool.tool_name == 'httpx':
                    subdomains = DiscoverSubdomain.objects.filter(wildcard=watcher_wildcard).values_list('subdomain', flat=True)
                    export_for_httpx(subdomains, subdomains_httpx)
                    output_file = run_httpx(watcher_wildcard,subdomains_httpx)
                    if output_file:
                        results = parse_httpx_jsonl(output_file)
                        save_httpx_results(results)

  

@shared_task(bind=True, acks_late=True)
def check_assets(self):
    assets = AssetWatcher.objects.filter(is_active=True)
    watcher_cidrs = WatcherCIDR.objects.filter(is_active=True)
    AssetWatcher.objects.filter(is_active=True).update(status='pending')

    subfinder_domains = set()
    httpx_domains = set()
    crtsh_domains = set()
    wabackurls_domains = set()
    findomain_domains = set()
    for asset in assets:
        try:
            for wildcard in asset.wildcards.all():
                wildcard.status = 'pending'
                wildcard.save()

                for tool in wildcard.tools.all():
                    if tool.tool_name == 'subfinder':
                        subfinder_domains.add(wildcard.wildcard)
                    if tool.tool_name == 'httpx':
                        httpx_domains.add(wildcard.wildcard)
                    if tool.tool_name == 'crt.sh':
                        crtsh_domains.add(wildcard.wildcard)
                    if tool.tool_name == 'wabackurls':
                        wabackurls_domains.add(wildcard.wildcard)
                    if tool.tool_name == 'findomain':
                        findomain_domains.add(wildcard.wildcard)

        except Exception as e:
            asset.status = 'failed'
            asset.save()
            sendmessage(f"[Asset-Watcher] ❌ Failed to process {asset}: {e}", colour='RED',telegram=True)

    steps = [
        ("subfinder", lambda: process_subfinder(subfinder_domains)),
        ("crt.sh", lambda: process_crtsh(crtsh_domains)),
        ("findomain", lambda: process_findomain(findomain_domains)),
        ("user subdomains", lambda: proccess_user_subdomains(assets)),
        ("httpx", lambda: process_httpx(assets)),
        ("cidrs scanning", lambda: process_cidrs_scanning(watcher_cidrs)),
        # ("wayback urls" , lambda: process_wabackurls(wabackurls_domains))
        # ("dns bruteforce", lambda: process_dns_bruteforce(assets)),
    ]

    for step_name, func in steps:
        try:
            sendmessage(f"[Asset-Watcher] ℹ️ Starting {step_name}", colour='BLUE',telegram=True)
            func()
            sendmessage(f"[Asset-Watcher] ✅ Finished {step_name}", colour='GREEN',telegram=True)
        except Exception as e:
            sendmessage(f"[Asset-Watcher] ❌ {step_name} failed: {e}", colour='RED',telegram=True)
    
    sendmessage(f"[Asset-Watcher] ✅ Asset Monitoring Successfully Done" , colour="CYAN", telegram=True)

    AssetWatcher.objects.filter(is_active=True).update(status='completed')
