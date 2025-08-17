from celery import shared_task
from .models import *
from asset_monitor.models import *
import subprocess , time , hashlib , requests
from asset_monitor.tasks import sendmessage
from urllib.parse import urlparse

list_check_extension = ['txt' , 'js']


def clear_labels(self):
    Url.objects.all().update(label="available")
    UrlChanges.objects.all().update(label="available")


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
        response = requests.get(url, timeout=30, verify=False, headers={"Cache-Control": "no-cache", "Pragma": "no-cache"})
        body_bytes = response.content 
        return hashlib.sha256(body_bytes).hexdigest()
    except Exception as e:
        return None


def discover_urls(self):
    subdomains = DiscoverSubdomain.objects.filter(label='new')
    sendmessage(f"[INFO] Starting URL Monitoring", telegram=False , colour="CYAN")

    def insert_subdomains(subdomain_obj, urls):
        for url in urls:
            clean_url = urlparse(url)
            matched_ext = 'none'
            for ext in EXTENSION:
                if clean_url.path.endswith(ext[1]):
                    matched_ext = ext[0]
                    break  

            new_body_hash = generate_body_hash(url)
            obj, created = Url.objects.get_or_create(
                subdomain=subdomain_obj,
                path=clean_url.path,
                defaults={
                    'query': clean_url.query,
                    'ext': matched_ext,
                    'url': url,
                    'body_hash' : new_body_hash
                }
            )
            if created:
                obj.label = "new"   
                obj.save()

    for subdomain in subdomains :
        urls = run_katana(subdomain.subdomain) + run_waybackurls(subdomain.subdomain)
        insert_subdomains(subdomain , urls)


def detect_urls_change(self):
    urls = Url.objects.all()
    
    for url in urls:
        changes = {}
        
        if url.ext in list_check_extension:  
            new_body_hash = generate_body_hash(url.url)

            if not new_body_hash:  
                continue

            if url.body_hash != new_body_hash:
                changes['body_hash_change'] = f"{url.body_hash} -> {new_body_hash}"
                
                url.body_hash = new_body_hash  

            if changes:
                UrlChanges.objects.create(
                    url=url,
                    query_change=changes.get('query_change', ''),
                    body_hash_change=changes.get('body_hash_change', ''),
                    label="new",
                    ext=url.ext
                )
                url.label = 'new'
                url.save(update_fields=['body_hash'])


@shared_task(bind=True, acks_late=True)
def url_monitor(self):
    clear_labels(self)
    discover_urls(self)
    detect_urls_change(self)
    