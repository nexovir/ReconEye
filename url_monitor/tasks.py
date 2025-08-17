from celery import shared_task
from .models import *
from asset_monitor.models import *
import subprocess , time , hashlib , requests
from asset_monitor.tasks import sendmessage
from urllib.parse import urlparse


def clear_subdomains_labels(subdomain):
    Url.objects.filter(subdomain=subdomain).update(label="available")


def discover_urls(subdomains):

    sendmessage(f"[INFO] Starting URL Monitoring", telegram=False , colour="CYAN")

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
            response = requests.get(url, timeout=10, verify=False)
            body_bytes = response.content 
            return hashlib.sha256(body_bytes).hexdigest()
        except Exception as e:
            return None

    def insert_subdomains(subdomain_obj, urls):
        for url in urls:
            clean_url = urlparse(url)
            matched_ext = 'none'
            for ext in EXTENSION:
                if clean_url.path.endswith(ext[1]):
                    matched_ext = ext[0]
                    break  

            obj, created = Url.objects.get_or_create(
                subdomain=subdomain_obj,
                path=clean_url.path,
                defaults={
                    'query': clean_url.query,
                    'ext': matched_ext,
                    'url': url,
                    'body_hash' : generate_body_hash(url)
                }
            )
            if created:
                obj.label = "new"
                obj.save()

    for subdomain in subdomains :
        clear_subdomains_labels(subdomain)
        urls = run_katana(subdomain.subdomain) + run_waybackurls(subdomain.subdomain)
        insert_subdomains(subdomain , urls)


@shared_task(bind=True, acks_late=True)
def url_monitor(self):
    subdomains = DiscoverSubdomain.objects.filter(label='new')
    discover_urls(subdomains)