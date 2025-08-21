from celery import shared_task
from .models import *
from asset_monitor.models import *
import subprocess , time , hashlib , requests
from asset_monitor.tasks import sendmessage
from urllib.parse import urlparse
import json
from django.db.models import Case, When, Value, IntegerField
from vulnerability_monitor.tasks import read_write_list


OUTPUT_PATH = 'url_monitor/outputs'


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
        sendmessage(f"  [ERROR] Error Fallparams {input} : {str(e)}", colour="RED")
        return None

def run_waybackurls (subdomain : str) -> list :
    sendmessage(f"  [INFO] Starting Waybackurls for '{subdomain}'...", telegram=False)
    command = f"waybackurls {subdomain}"
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
    command = f"nice-katana {subdomain}"
    output = subprocess.run(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        text=True
    )
    return(output.stdout.splitlines())


def generate_body_hash(url: str) -> str:
    try:
        response = requests.get(url, timeout=30, verify=True, headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.90 Safari/537.36",
        "Cache-Control": "no-cache","Pragma": "no-cache"}
    )
        body_bytes = response.content 
        return hashlib.sha256(body_bytes).hexdigest()
    except Exception as e:
        return None


def discover_urls(self):
    subdomains = DiscoverSubdomain.objects.order_by(
    Case(
        When(label='new', then=Value(0)),
        default=Value(1),
        output_field=IntegerField(),
    ),
    )
    sendmessage(f"[INFO] Starting Discover URLs on All Assets (order by NEW) for Discover New URLs", telegram=True , colour="CYAN")

    def insert_subdomains(subdomain_obj, urls):
        for url in urls:
            clean_url = urlparse(url)
            matched_ext = 'none'
            for ext in EXTENSION:
                if clean_url.path.endswith(ext[1]):
                    matched_ext = ext[0]
                    break  

            new_body_hash = generate_body_hash(url)

            try:
                resp = requests.get(url, timeout=10)
                status = resp.status_code
            except requests.RequestException:
                status = None

            obj, created = Url.objects.get_or_create(
                subdomain=subdomain_obj,
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

    for subdomain in subdomains :
        urls = run_katana(subdomain.subdomain) + run_waybackurls(subdomain.subdomain)
        insert_subdomains(subdomain , urls)



def detect_urls_changes(self):
    sendmessage(f"[INFO] Starting Detect URLs Changes ", telegram=True , colour="CYAN")

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
            new_body_hash = hashlib.sha256(response.content).hexdigest()
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



def discover_parameter(self):
    sendmessage(f"[INFO] Starting Discover Parameters from Discovered Subdomains", telegram=True , colour="CYAN")
    
    def parameters_insert_database(subdomain , parameters):
        for parameter in parameters :
            obj, created = SubdomainParameter.objects.get_or_create(
                wildcard = subdomain.wildcard,
                parameter = parameter
            )
            if created:
                obj.label = "new"   
                obj.save()
    
    subdomains = DiscoverSubdomain.objects.all()

    for subdomain in subdomains :
        headers = list(RequestHeaders.objects.filter(asset_watcher=subdomain).values_list('header', flat=True))
        read_write_list(list(subdomain.url_set.values_list('url', flat=True)) , f"{OUTPUT_PATH}/urls.txt" , 'w')
        parameters = run_fallparams(f"{OUTPUT_PATH}/urls.txt" , headers)
        parameters_insert_database (subdomain , parameters)




def fuzz_parameters_on_urls(self):
    wildcards = WatchedWildcard.objects.all()
    sendmessage(f"[INFO] Starting Fuzz Parameters on URLs (ordery_by NEW URLs)", telegram=True , colour="CYAN")
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
            sendmessage(f"[ERROR] Failed to decode JSON for {url_instance}: {str(e)}", colour="RED")
        except FileNotFoundError:
            sendmessage(f"[ERROR] JSON file not found: {json_file_path}", colour="RED")
        except Exception as e:
            sendmessage(f"[ERROR] Failed to save parameters for {url_instance}: {str(e)}", colour="RED")

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
                sendmessage(f"[ERROR] X8 failed on {url} with {method}: {e.stderr}", colour="RED")
            except Exception as e:
                sendmessage(f"[ERROR] Unexpected error X8 {url} with {method}: {str(e)}", colour="RED")


    for wildcard in wildcards:
        parameters = wildcard.subdomainparameter_set.values_list('parameter', flat=True)
        read_write_list(list(parameters), f"{OUTPUT_PATH}/parameters.txt", 'w')
        subdomains = DiscoverSubdomain.objects.filter(wildcard=wildcard).order_by(
            Case(
                When(label="new", then=Value(0)),
                default=Value(1),
                output_field=IntegerField(),))
        
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
    discover_urls(self)
    detect_urls_changes(self)
    discover_parameter(self)
    fuzz_parameters_on_urls(self)
    