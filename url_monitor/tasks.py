from celery import shared_task
from .models import *
from asset_monitor.models import *
import subprocess , time , hashlib , requests , json
from urllib.parse import urlparse 
from django.db.models import Case, When, Value, IntegerField
from vulnerability_monitor.tasks import read_write_list
from programs_monitor.tasks import sendmessage , PROXIES
from vulnerability_monitor.tasks import *


OUTPUT_PATH = 'url_monitor/outputs'

EXTS = ['js']

def clear_labels(self):
    Url.objects.all().update(label="available")
    UrlChanges.objects.all().update(label="available")
    SubdomainParameter.objects.all().update(label='available')
    Parameter.objects.all().update(label = 'available')

def run_fallparams(input : str , headers : list) -> list:
    try : 
        command = [
            "fallparams",
            "-u", input,
            "-proxy","socks5://127.0.0.1:1080",
            "-X", "GET",
            "-X", "POST",
            "-silent",
            "-duc",
        ]
        if headers:
            for h in headers:
                if h:
                    command.extend(["-H", h])
        result = subprocess.run(
            command,
            shell=False,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        parameters = result.stdout.splitlines()
        return parameters
    
    except Exception as e:
        sendmessage(f"  [Url-Watcher] ❌ Error Fallparams {input} : {str(e)}", colour="RED")
        return None

def run_waybackurls (subdomain : str) -> list :
    sendmessage(f"  [INFO] Starting Waybackurls for '{subdomain}'...", telegram=False)
    command = f"proxychains waybackurls {subdomain} | uro | sort -u"
    output = subprocess.run(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        text=True
    )
    return(output.stdout.splitlines())

def run_katana(subdomain : str) -> list :
    sendmessage(f"  [INFO] Starting Katana for '{subdomain}'...", telegram=False)
    command = f"nice-katana {subdomain} | uro | sort -u"
    output = subprocess.run(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=600,
        text=True
    )
    return(output.stdout.splitlines())


def generate_body_hash(url: str) -> str:
    try:
        response = requests.get(url, timeout=30, verify=True, headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.90 Safari/537.36",
        "Cache-Control": "no-cache","Pragma": "no-cache"},
        proxies=PROXIES
    )
        body_bytes = response.content 
        return hashlib.sha256(body_bytes).hexdigest()
    except Exception as e:
        return None


def discover_urls(self, label):

    def insert_subdomains(subdomain_obj, urls):
        for url in urls:
            clean_url = urlparse(url)
            matched_ext = 'none'
            for ext in EXTENSION:
                if clean_url.path.endswith(ext[1]):
                    matched_ext = ext[0]
                    break  

            if matched_ext in EXTS:
                new_body_hash = generate_body_hash(url)
            else :
                new_body_hash = ''

            try:
                resp = requests.get(url, timeout=10)
                status = resp.status_code
            except requests.RequestException:
                status = None

            obj, created = Url.objects.get_or_create(
                subdomain=subdomain_obj.discovered_subdomain,
                path=clean_url.path,
                defaults={
                    'query': clean_url.query,
                    'ext': matched_ext,
                    'url': url,
                    'body_hash' : new_body_hash,
                    'status': status
                }
            )
            if created:
                obj.label = "new"   
                obj.save()

    sendmessage(f"[Url-Watcher] ℹ️ Starting Url Discovery on All Assets (label : {label})" , colour='CYAN')
    subdomains = SubdomainHttpx.objects.filter(label=label)
    
    for subdomain in subdomains :
        print(subdomain)
        urls = run_katana(subdomain.httpx_result) + run_waybackurls(subdomain.httpx_result)
        insert_subdomains(subdomain , urls)



def detect_urls_changes(self):
    sendmessage(f"[Urls-Watcher] ℹ️ Starting Detect URLs Changes (Body-Hash , Query-Changes , Status-Changes)", telegram=True , colour="CYAN")

    urls = Url.objects.all()
    
    for url in urls:
        changes = {}

        try:
            response = requests.get(
                url.url, 
                timeout=30,
                verify=True, 
                headers={
                    "Cache-Control": "no-cache",
                    "Pragma": "no-cache",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36"
                }
            )
            if url.ext in EXTS : 
                new_body_hash = hashlib.sha256(response.content).hexdigest()
            else : 
                new_body_hash = ''
            new_status = str(response.status_code)
            new_query = url.query 
        except requests.RequestException:
            continue
        

        if url.body_hash != new_body_hash:
            changes['body_hash_change'] = f"{url.body_hash} -> {new_body_hash}"
            url.body_hash = new_body_hash

        if url.status != new_status:
            changes['status_change'] = f"{url.status} -> {new_status}"
            url.status = new_status

        if url.query != new_query:
            changes['query_change'] = f"{url.query} -> {new_query}"
            url.query = new_query

        if changes:
            UrlChanges.objects.create(
                url=url,
                query_change=changes.get('query_change', ''),
                body_hash_change=changes.get('body_hash_change', ''),
                status_change=changes.get('status_change', ''),
                label="new",
                ext=url.ext
            )
            url.label = 'new'
            url.save(update_fields=['body_hash', 'status', 'query', 'label'])



def discover_parameter(self , label):
    sendmessage(f"[Urls-Watcher] ℹ️ Starting Discover Parameters on Assets (label: {label})", telegram=True , colour="CYAN")
    
    def parameters_insert_database(subdomain , parameters):
        for parameter in parameters :
            obj, created = SubdomainParameter.objects.get_or_create(
                wildcard = subdomain.wildcard,
                parameter = parameter
            )
            if created:
                obj.label = "new"   
                obj.save()
    
    subdomains = DiscoverSubdomain.objects.filter(label=label)
    
    for subdomain in subdomains :
        print(subdomain)
        headers = list(RequestHeaders.objects.filter(asset_watcher=subdomain).values_list('header', flat=True))
        read_write_list(list(subdomain.url_set.values_list('url', flat=True)) , f"{OUTPUT_PATH}/urls.txt" , 'w')
        parameters = run_fallparams(f"{OUTPUT_PATH}/urls.txt" , headers)
        parameters_insert_database (subdomain , parameters)




def fuzz_parameters_on_urls(self , label):

    def save_x8_output_from_file(url_instance , json_file_path, url):

        try:
            with open(json_file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            for item in data:
                method = item.get("method")
                injection_place = item.get("injection_place")
                for param in item.get("found_params", []):
                    obj, created = Parameter.objects.get_or_create(
                        url=url_instance,
                        method=method,
                        parameter=param.get("name"),
                        defaults={
                            "status": str(param.get("status")),
                            "reason_kind": param.get("reason_kind"),
                            "injection_place": injection_place
                        }
                    )
                    if created :
                        obj.label = 'new'
                        obj.save()

        except json.JSONDecodeError as e:
            sendmessage(f"[Url-Watcher] ❌ Failed to decode JSON for {url_instance}: {str(e)}", colour="RED")
        except FileNotFoundError:
            sendmessage(f"[Url-Watcher] ❌ JSON file not found: {json_file_path}", colour="RED")
        except Exception as e:
            sendmessage(f"[Url-Watcher] ❌ Failed to save parameters for {url_instance}: {str(e)}", colour="RED")

    def run_x8(url_instance , url, parameters_path, headers):
        for method in ["GET", "POST"]:
            output_file = f"{OUTPUT_PATH}/x8_output_{method}.json"
            try:
                command = [
                    "x8",
                    "-u", url,
                    "-w", parameters_path,
                    "--output-format", "json",
                    "-o",output_file,
                    "-X", method,
                ]

                if headers:
                    valid_headers = [h.strip() for h in headers if h and ":" in h]
                    if valid_headers:
                        command.append("-H")
                        command.extend(valid_headers)
                
                result = subprocess.run(
                    command,
                    shell=False,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                save_x8_output_from_file(url_instance , output_file, url)

            except subprocess.CalledProcessError as e:
                sendmessage(f"[Url-Watcher] ❌ X8 failed on {url} with {method}: {e.stderr}", colour="RED")
            except Exception as e:
                sendmessage(f"[Url-Watcher] ❌ Unexpected error X8 {url} with {method}: {str(e)}", colour="RED")

    wildcards = WatchedWildcard.objects.all()
    sendmessage(f"[Urls-Watcher] ℹ️ Starting Fuzz Parameters on URLs (label: {label})", telegram=True , colour="CYAN")

    for wildcard in wildcards:
        parameters = wildcard.subdomainparameter_set.values_list('parameter', flat=True)
        read_write_list(list(parameters), f"{OUTPUT_PATH}/parameters.txt", 'w')
        subdomains = DiscoverSubdomain.objects.filter(wildcard=wildcard , label=label)
        
        for subdomain in subdomains:
            headers = list(RequestHeaders.objects.filter(asset_watcher=subdomain).values_list('header', flat=True))
            urls = Url.objects.filter(subdomain=subdomain).order_by(
            Case(
                When(label="new", then=Value(0)),
                default=Value(1),
                output_field=IntegerField()),)

            for url in urls:
                run_x8(url, url.url, f"{OUTPUT_PATH}/parameters.txt", headers)



@shared_task(bind=True, acks_late=True)
def url_monitor(self):
    clear_labels(self)
    sendmessage(f"[Url-Monitoring] ⚠️ Url Monitoring Will be Started Please add Valid Headers ⚠️")

    discover_urls(self , 'new')
    discover_parameter(self , 'new')
    fuzz_parameters_on_urls(self , 'new')
    vulnerability_monitor('new')

    fuzz_parameters_on_urls(self , 'available')
    discover_urls(self , 'available')
    discover_parameter(self , 'available')
    vulnerability_monitor(self , 'available')
    
    detect_urls_changes(self)

    