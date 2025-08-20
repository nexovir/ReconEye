from celery import shared_task
from .models import *
from asset_monitor.models import *
import subprocess , time , hashlib , requests
from asset_monitor.tasks import sendmessage
from urllib.parse import urlparse
import colorama
from django.db.models import Case, When, Value, IntegerField
from vulnerability_monitor.tasks import read_write_list


OUTPUT_PATH = 'url_monitor/outputs'


def clear_labels(self):
    Url.objects.all().update(label="available")
    UrlChanges.objects.all().update(label="available")


def run_fallparams(input : str ) -> list:
    try : 
        command = [
            'fallparams',
            '-u',input,
            '-silent',
            '-duc',
            '-X','GET',
            'POST',
            
        ]
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
    sendmessage(f"[INFO] Starting Discover Urls on All Assets (order by NEW)", telegram=True , colour="CYAN")

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
    sendmessage(f"[INFO] Starting Detect URLs Changes", telegram=True , colour="CYAN")

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



def discover_parameter_and_changes(self):
    def parameters_insert_database(subdomain , parameters):
        for parameter in parameters :
            obj, created = SubdomainParameter.objects.get_or_create(
                subdomain = subdomain,
                parameter = parameter
            )
            if created:
                obj.label = "new"   
                obj.save()
    
    subdomains = DiscoverSubdomain.objects.filter(label='new')

    for subdomain in subdomains :
        read_write_list(list(subdomain.url_set.values_list('url', flat=True)) , f"{OUTPUT_PATH}/urls.txt" , 'w')
        parameters = run_fallparams(f"{OUTPUT_PATH}/urls.txt")
        parameters_insert_database (subdomain , parameters)



def fuzz_parameters_on_urls (self):
    urls = Url.objects.filter(label ='new')
    

@shared_task(bind=True, acks_late=True)
def url_monitor(self):
    # clear_labels(self)
    # discover_urls(self)
    # detect_urls_changes(self)
    # discover_parameter_and_changes(self)
    fuzz_parameters_on_urls(self)
    