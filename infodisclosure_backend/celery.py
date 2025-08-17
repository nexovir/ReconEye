# infodisclosure_backend/celery.py
import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'infodisclosure_backend.settings')

app = Celery('infodisclosure_backend')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks(['programs_monitor', 'asset_monitor' , 'url_monitor' , 'vulnerability_monitor'])

app.conf.update(
    task_time_limit=86400,
    task_soft_time_limit=86000,
    task_acks_late=True,
    worker_prefetch_multiplier=1
)

broker_transport_options = {
    'visibility_timeout': 86400 
}
