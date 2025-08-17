from django.db import models
from core.models import BaseModel
from django.contrib.auth.models import User
from asset_monitor.models import *


EXTENSION = [
    ('none', 'none'),
    ('html', '.html'), ('htm', '.htm'), ('xhtml', '.xhtml'), ('php', '.php'),
    ('asp', '.asp'), ('aspx', '.aspx'), ('jsp', '.jsp'), ('cgi', '.cgi'), ('pl', '.pl'),
    ('js', '.js'), ('ts', '.ts'), ('jsx', '.jsx'), ('tsx', '.tsx'),
    ('css', '.css'), ('scss', '.scss'), ('sass', '.sass'), ('less', '.less'),
    ('json', '.json'), ('xml', '.xml'), ('yaml', '.yaml'), ('yml', '.yml'), ('csv', '.csv'), ('txt', '.txt'),
    ('jpg', '.jpg'), ('jpeg', '.jpeg'), ('png', '.png'), ('gif', '.gif'), ('svg', '.svg'),
    ('webp', '.webp'), ('ico', '.ico'), ('bmp', '.bmp'), ('tiff', '.tiff'), ('heic', '.heic'),
    ('pdf', '.pdf'), ('doc', '.doc'), ('docx', '.docx'), ('xls', '.xls'), ('xlsx', '.xlsx'),
    ('ppt', '.ppt'), ('pptx', '.pptx'), ('odt', '.odt'), ('ods', '.ods'), ('odp', '.odp'),
    ('zip', '.zip'), ('rar', '.rar'), ('7z', '.7z'), ('tar', '.tar'), ('gz', '.gz'), ('bz2', '.bz2'),
    ('mp3', '.mp3'), ('wav', '.wav'), ('flac', '.flac'), ('ogg', '.ogg'),
    ('mp4', '.mp4'), ('mov', '.mov'), ('avi', '.avi'), ('mkv', '.mkv'), ('webm', '.webm'),
    ('exe', '.exe'), ('apk', '.apk'), ('bin', '.bin'), ('jar', '.jar'), ('sh', '.sh'), ('bat', '.bat'),
    ('sql', '.sql'), ('db', '.db'), ('sqlite', '.sqlite'), ('mdb', '.mdb'),
    ('conf', '.conf'), ('ini', '.ini'), ('env', '.env'), ('log', '.log'), ('cfg', '.cfg'), 
    ('toml', '.toml'), ('lock', '.lock'), ('crt', '.crt'), ('key', '.key'),
]


class Url(BaseModel):
    subdomain = models.ForeignKey(DiscoverSubdomain , on_delete=models.CASCADE)
    url = models.CharField(max_length=600, null=False , blank=False)
    path = models.CharField(max_length=300 , null=False , blank=False)
    query = models.CharField(max_length=300 , null=False , blank=False)
    label = models.CharField(max_length=150 , choices=LABELS , default='new')
    ext = models.CharField(max_length=150 , choices=EXTENSION , default='none')
    body_hash = models.CharField(max_length=300 , null=True , blank=True)
    
    def __str__(self):
        return f"{self.subdomain} - {self.ext}"

    class Meta:
        verbose_name = 'URL'
        verbose_name_plural = 'URLs'


class UrlChanges(BaseModel):
    path = models.ForeignKey(Url , on_delete=models.CASCADE)
    label = models.CharField(max_length=150 , choices=LABELS , default='new')
    old_body_hash = models.CharField(max_length=300 , null=False , blank=True)
    new_body_hash = models.CharField(max_length=300 , null=False , blank=True)

    def __str__(self):
        return f"{self.old_body_hash} -> {self.new_body_hash}"
    
    class Meta:
        verbose_name = 'URL Change'
        verbose_name_plural = 'URL Changes'