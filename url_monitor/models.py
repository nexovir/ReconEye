from django.db import models
from core.models import BaseModel
from django.contrib.auth.models import User
from asset_monitor.models import *

def user_urls_upload_path(instance, filename):
    username = instance.watcher.user.username if instance.watcher.user else 'anonymous'
    ext = os.path.splitext(filename)[1]
    return f"url_monitor/urls/{username}/{instance.wildcard}_urls.txt"



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
    url = models.CharField(null=False , blank=False)
    path = models.CharField(null=False , blank=True)
    query = models.CharField(null=False , blank=True)
    status = models.CharField(blank=True , null=True)
    ext = models.CharField(choices=EXTENSION , default='none')
    body_hash = models.CharField(null=True , blank=True)
    tool = models.CharField(blank=True , null=True)
    
    own_urls = models.FileField(
        upload_to=user_urls_upload_path,
        validators=[validate_wordlist_file],
        null=True,
        blank=True,
    )
    
    label = models.CharField(choices=LABELS , default='new')

    def __str__(self):
        return f"{self.subdomain} - {self.ext}"

    class Meta:
        verbose_name = 'URL'
        verbose_name_plural = 'All URLs'



class NewUrl(BaseModel):
    subdomain = models.ForeignKey(DiscoverSubdomain , on_delete=models.CASCADE)
    url = models.CharField(null=False , blank=False)
    path = models.CharField(null=False , blank=True)
    query = models.CharField(null=False , blank=True)
    status = models.CharField(blank=True , null=True)
    ext = models.CharField(choices=EXTENSION , default='none')
    body_hash = models.CharField(null=True , blank=True)
    tool = models.CharField(blank=True , null=True)

    own_urls = models.FileField(
        upload_to=user_urls_upload_path,
        validators=[validate_wordlist_file],
        null=True,
        blank=True,
    )

    label = models.CharField(choices=LABELS , default='new')

    def __str__(self):
        return f"{self.subdomain} - {self.ext}"

    class Meta:
        verbose_name = 'New URL'
        verbose_name_plural = 'New URLs'



class UrlChanges(BaseModel):
    url = models.ForeignKey(Url , on_delete=models.CASCADE)
    query_change = models.CharField(null=True , blank=True)
    body_hash_change = models.CharField(null=True , blank=True)
    status_change = models.CharField(null=True , blank=True)
    label = models.CharField(choices=LABELS , default='new')
    ext = models.CharField(choices=EXTENSION , default='none')

    def __str__(self):
        return f"{self.url} -> {self.ext}"
    
    class Meta:
        verbose_name = 'URL Change'
        verbose_name_plural = 'URL Changes'


class Parameter(BaseModel) :
    url = models.ForeignKey(Url , on_delete=models.CASCADE)
    method = models.CharField(null=True , blank=True)
    status = models.CharField(blank=True , null=True)
    parameter = models.CharField(blank=True , null=True)
    reason_kind = models.CharField(blank=True , null=True)
    injection_place = models.CharField(blank=True , null=True)
    label = models.CharField(choices=LABELS , default='new')
    
    def __str__(self):
        return f"{self.url} : {self.method} - {self.parameter}"

    class Meta:
        verbose_name = 'Parameter'
        verbose_name_plural = 'Parameters'


class SubdomainParameter(BaseModel):
    subdomain = models.ForeignKey(DiscoverSubdomain , on_delete=models.CASCADE , null=True , blank=True)
    parameter = models.CharField(null=False , blank=False)
    label = models.CharField(choices=LABELS , default='new')
    
    def __str__(self):
        return f"{self.parameter} - {self.subdomain}"
    
    class Meta :
        unique_together = ['subdomain' , 'parameter']
        verbose_name = 'Subdomain Parameter'
        verbose_name_plural = 'Subdomain Parameters'