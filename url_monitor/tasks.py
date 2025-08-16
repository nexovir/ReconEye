from celery import shared_task
from .models import *

@shared_task(bind=True, acks_late=True)
def url_monitor(self):
    urls = Url.objects.all()
    
    print(urls)