from django.db import models
from core.models import BaseModel
from django.contrib.auth.models import User
from private_watchers.models import *

LABELS = [
        ('new', 'NEW'),
        ('available' , 'AVAILABLE')
    ]

EXTENSION = [('none', 'none'),('html', 'html'),('htm', 'htm'),('js', 'js'),
             ('css', 'css'),('json', 'json'),('xml', 'xml'),('jpg', 'jpg'),
             ('jpeg', 'jpeg'),('png', 'png'),('gif', 'gif'),('svg', 'svg'),
             ('ico', 'ico'),('pdf', 'pdf'),('doc', 'doc'),('docx', 'docx'),
             ('xls', 'xls'),('xlsx', 'xlsx'),('ppt', 'ppt'),('pptx', 'pptx'),
             ('txt', 'txt'),('csv', 'csv'),('zip', 'zip'),('rar', 'rar'),
             ('7z', '7z'),('tar', 'tar'),('gz', 'gz'),('exe', 'exe'),('apk', 'apk'),
             ('mp3', 'mp3'),('mp4', 'mp4'),('mov', 'mov'),('avi', 'avi'),
             ('mkv', 'mkv'),('webm', 'webm'),('wav', 'wav'),('flac', 'flac'),
             ('ogg', 'ogg'),('log', 'log'),('sql', 'sql'),('db', 'db'),
             ('conf', 'conf'),('ini', 'ini'),('yml', 'yml'),('yaml', 'yaml'),
             ('env', 'env'),
]

class UrL(BaseModel):
    subdomain = models.ForeignKey(DiscoverSubdomain , on_delete=models.CASCADE)
    url = models.CharField(max_length=300 , null=False , blank=False)
    label = models.CharField(max_length=150 , choices=STATUSES , default='new')
    ext = models.CharField(max_length=150 , choices=EXTENSION , default='none')
    body_hash = models.CharField(max_length=300 , null=False , blank=True)
    
    def __str__(self):
        return f"{self.subdomain} - {self.ext}"

    class Meta:
        verbose_name = 'Discovered URL'
        verbose_name_plural = 'Discovered URLs'
