from celery import shared_task
from .models import *
from asset_monitor.models import *
import subprocess , time
from asset_monitor.tasks import sendmessage
from urllib.parse import urlparse

@shared_task(bind=True, acks_late=True)
def url_monitor(self):

    sendmessage(f"[INFO] Starting URL Monitoring", telegram=False , colour="CYAN")
    subdomains = DiscoverSubdomain.objects.filter(label='new')

    def run_waybackurls (subdomain : str) -> list:
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

    def run_katana(subdomain : str) -> list:
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
    
    def insert_subdomains (subdomain_obj , urls):
        print(type(subdomain_obj))
        for url in urls :
            for ext in EXTENSION :
                if urlparse(url).path.endswith(ext[1]):
                    obj , created = Url.objects.get_or_create(
                        url = url , ext = ext[0] , defaults={'subdomain' : subdomain_obj}
                    )
                    if created :
                        obj.label = "new"
                        obj.save()

    for subdomain in subdomains :
        urls = run_katana(subdomain.subdomain) + run_waybackurls(subdomain.subdomain)
        insert_subdomains(subdomain , urls)