from django.db import models
from core.models import BaseModel
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
import os




STATUSES = [
    ('pending', 'Pending'),         
    ('running', 'Running'),      
    ('completed', 'Completed'),    
    ('failed', 'Failed'),           
    ('cancelled', 'Cancelled'),     
]


LABELS = [
        ('new', 'NEW'),
        ('available' , 'AVAILABLE')
    ]

TOOLS_NAME = [
    ('owned', 'Owned'),
    ('amass', 'Amass'),
    ('subfinder' , 'Subfinder'),
    ('dns_bruteforce', 'DNS Bruteforce'),
    ('httpx', 'HTTPX'),
    ('wabackurls', 'Wabackurls'),
    ('crt.sh', 'CRT.sh'),
]

PORTS = [
    ('80','80'),
    ('8080','8080'),
    ('8081','8081'),
    ('8880','8880'),
    ('2052','2052'),
    ('2082','2082'),
    ('2086','2086'),
    ('2095','2095'),
    ('443','443'),
    ('2053','2053'),
    ('2087','2087'),
    ('2096','2096'),
    ('8443','8443'),
    ('10443' , '10443')
    ]

def validate_wordlist_file(file):
    ext = os.path.splitext(file.name)[1]


    max_size = 300 * 1024 * 1024  # 300 MB
    if file.size > max_size:
        raise ValidationError('File size must be under 300 MB.')
    
    if ext.lower() != '.txt':
        raise ValidationError('Only .txt files are allowed.')



def default_wordlist_path():
    return 'asset_monitor/wordlists/2m-subdomains.txt'



def user_static_wordlist_upload_path(instance, filename):
    username = instance.user.username if instance.user else 'anonymous'
    ext = os.path.splitext(filename)[1]
    return f"asset_monitor/wordlists/{username}/static_dns_wordlist.txt"

def user_dynamic_wordlist_upload_path(instance, filename):
    username = instance.user.username if instance.user else 'anonymous'
    ext = os.path.splitext(filename)[1]
    return f"asset_monitor/wordlists/{username}/dynamic_dns_wordlist.txt"


def user_subdomains_upload_path(instance, filename):
    username = instance.watcher.user.username if instance.watcher.user else 'anonymous'
    ext = os.path.splitext(filename)[1]
    return f"asset_monitor/subdomains/{username}/{instance.wildcard}_subdomains.txt"



class AssetWatcher(BaseModel):
    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True, blank=True)
    notify = models.BooleanField(default=False)
    status = models.CharField(max_length=150, choices=STATUSES, default='pending')
    

    def import_wildcards_from_file(self, file_path):
        tool_names = ['subfinder', 'httpx', 'crt.sh', 'wabackurls']
        tools = Tool.objects.filter(tool_name__in=tool_names)
        tools_dict = {tool.tool_name: tool for tool in tools}

        missing_tools = set(tool_names) - set(tools_dict.keys())
        if missing_tools:
            print(f"These tools do not exist in DB: {', '.join(missing_tools)}")
            return

        with open(file_path, 'r') as f:
            lines = f.readlines()

        for line in lines:
            wildcard = line.strip()
            if wildcard:
                wildcard_obj, created = WatchedWildcard.objects.get_or_create(
                    watcher=self,
                    wildcard=wildcard,
                )

                for tool_name in tool_names:
                    tool = tools_dict[tool_name]
                    if not wildcard_obj.tools.filter(pk=tool.pk).exists():
                        wildcard_obj.tools.add(tool)
                        print(f"Added {tool_name} tool to wildcard: {wildcard}")
                    else:
                        print(f"{tool_name} tool already exists for wildcard: {wildcard}")



    dns_bruteforce_static_wordlist = models.FileField(
        upload_to=user_static_wordlist_upload_path,
        validators=[validate_wordlist_file],
        null=True,
        blank=True,
        default=default_wordlist_path,  
    )

    dns_bruteforce_dynamic_wordlist = models.FileField(
        upload_to=user_dynamic_wordlist_upload_path,
        validators=[validate_wordlist_file],
        null=True,
        blank=True,
        default=default_wordlist_path,
    )
    
    def __str__(self):
        wildcards = ", ".join([w.wildcard for w in self.wildcards.all()])
        return f"{self.user.username} - {wildcards}"


    def save(self, *args, **kwargs):
        try:
            old = AssetWatcher.objects.get(pk=self.pk)
            if old.dns_bruteforce_static_wordlist and old.dns_bruteforce_static_wordlist != self.dns_bruteforce_static_wordlist:
                if os.path.isfile(old.dns_bruteforce_static_wordlist.path):
                    os.remove(old.dns_bruteforce_static_wordlist.path)
        except AssetWatcher.DoesNotExist:
            pass
        super().save(*args, **kwargs)

    class Meta:
        verbose_name = 'Asset Watcher'
        verbose_name_plural = 'Asset Watchers'



class Tool(models.Model):

    tool_name = models.CharField(max_length=120, choices=TOOLS_NAME , default='subfinder')

    def __str__(self):
        return self.tool_name

    class Meta:
        verbose_name = 'Tool'
        verbose_name_plural = 'Tools'



class WatchedWildcard(BaseModel):
    watcher = models.ForeignKey(AssetWatcher , on_delete=models.CASCADE , related_name= 'wildcards')
    wildcard = models.CharField(max_length=300 , blank=True , null=True , unique=True)
    tools = models.ManyToManyField(Tool)
    own_subdomains = models.FileField(
        upload_to=user_subdomains_upload_path,
        validators=[validate_wordlist_file],
        null=True,
        blank=True,
    )
    status = models.CharField(max_length=150, choices=STATUSES, default='pending') 

    def __str__(self):
        return f"{self.wildcard} - {self.watcher.user.username}"
    
    class Meta:
        verbose_name = 'Watcher Wildcard'
        verbose_name_plural = 'Watcher Wildcards'


class DiscoverSubdomain(BaseModel):
    wildcard = models.ForeignKey(WatchedWildcard, on_delete=models.CASCADE, related_name='subdomains')
    subdomain = models.CharField(max_length=300, blank=True, null=True , unique= True)
    tool = models.ForeignKey(Tool, on_delete=models.SET_NULL, null=True, blank=True)

    label = models.CharField(choices=LABELS, max_length=50, default='new')

    def __str__(self):
        return f"{self.subdomain} - {self.wildcard.watcher.user.username}"

    class Meta:
        ordering = ['label']
        verbose_name = 'Discovered Subdomain'
        verbose_name_plural = 'Discovered Subdomains'


class RequestHeaders (BaseModel):
    asset_watcher = models.ForeignKey(DiscoverSubdomain , on_delete=models.CASCADE , blank=False , null=False)
    header = models.CharField(max_length=5000 , null=True , blank=True)

    def __str__(self):
        return f"{self.asset_watcher.subdomain} -> {self.asset_watcher.wildcard.wildcard}"

    class Meta:
        verbose_name = 'Request Header'
        verbose_name_plural = 'Request Headers'


class SubdomainHttpx(BaseModel):

    discovered_subdomain = models.OneToOneField(DiscoverSubdomain , on_delete=models.CASCADE)
    
    httpx_result = models.URLField(max_length=300 , blank=True , null=True)
    status_code = models.CharField(null=True, blank=True)
    title = models.CharField(null=True , blank=True , max_length=500)
    server = models.CharField(max_length=300 , null=True , blank=True)
    technologies = models.CharField(max_length=900, blank=True)

    ip_address = models.CharField(max_length=120 , null=True , blank=True)
    port = models.CharField(null=True, blank=True)


    content_type = models.CharField(max_length=300, null=True, blank=True)
    line_count = models.CharField(null=True, blank=True)
    a_records = models.CharField(blank=True)

    body_hash = models.CharField(blank=True , null=True , max_length=200)
    header_hash = models.CharField(blank=True , null=True , max_length=200)
    has_cdn = models.CharField(default='False' , null=True , blank=True , max_length=10)

    label = models.CharField(choices=LABELS , default='new')

    def __str__(self):
        return f"{self.discovered_subdomain.subdomain} - {self.status_code}"

    class Meta:
        verbose_name = 'Subdomain HTTPX'
        verbose_name_plural = 'Subdomains HTTPX'




class SubdomainHttpxChanges(BaseModel):
    discovered_subdomain = models.OneToOneField(DiscoverSubdomain , on_delete=models.CASCADE)

    httpx_result_change = models.CharField(blank=True , null=True)
    status_code_change = models.CharField(null=True, blank=True)
    title_change = models.CharField(null=True , blank=True , max_length=500)
    server_change = models.CharField(null=True , blank=True)
    technologies_change = models.CharField(blank=True)

    ip_address_change = models.CharField(null=True , blank=True)
    port_change = models.CharField(null=True, blank=True)


    content_type_change = models.CharField(null=True, blank=True)
    line_count_change = models.CharField(null=True, blank=True)
    a_records_change = models.CharField(blank=True)
    
    body_hash_change = models.CharField(blank=True , null=True)
    header_hash_change = models.CharField(blank=True , null=True)
    has_cdn_change = models.CharField(blank=True , null=True)

    label = models.CharField(choices=LABELS , default='new')

    def __str__(self):
        return f"{self.discovered_subdomain.subdomain} - {self.label}"

    class Meta:
        verbose_name = 'Subdomain HTTPX Changes'
        verbose_name_plural = 'Subdomains HTTPX Changes'




class Ports (models.Model):
    port = models.CharField(choices=PORTS, max_length=10, blank=True, null=True)


    def __str__ (self):
        return self.port
    
    class Meta : 
        verbose_name = 'Port'
        verbose_name_plural = 'Ports'



class WatcherCIDR(BaseModel):
    watcher = models.ForeignKey(AssetWatcher, on_delete=models.CASCADE, related_name='cidrs' , null=True , blank=True)
    cidr = models.CharField(max_length=50, blank=True, null=True , unique=True)
    status = models.CharField(choices=STATUSES, max_length=50, default='new')
    ports = models.ManyToManyField(Ports)
    
    def __str__(self):
        return f"{self.watcher.user.username} - {self.cidr}"

    def import_cidrs_from_file(self, file_path):
        all_ports = Ports.objects.all()
        with open(file_path, 'r') as f:
            lines = f.readlines()

        for line in lines:
            cidr_line = line.strip()
            if cidr_line:
                cidr_obj, created = WatcherCIDR.objects.get_or_create(
                    watcher=self.watcher,
                    cidr=cidr_line
                )
                cidr_obj.ports.set(all_ports) 
                cidr_obj.save()

    class Meta:
        verbose_name = 'Watcher CIDR'
        verbose_name_plural = 'Watcher CIDRs'


class DiscoverdServices(BaseModel):
    watcher = models.ForeignKey(WatcherCIDR , on_delete=models.CASCADE , related_name='discoverd_services')
    ip = models.CharField (max_length=20 , blank=True , null=True)
    port = models.CharField (max_length=10 , blank=True , null=True)

    label = models.CharField(choices=LABELS , default='available')

    has_change = models.BooleanField(default=False)
    
    def __str__ (self): 
        return f"{self.ip}:{self.port} -> {self.watcher} - "
    

    class Meta:
        verbose_name = 'Discoverd Service'
        verbose_name_plural = 'Discovered Services'


class DiscoverdServicesAlive(BaseModel):
    watcher = models.ForeignKey(WatcherCIDR , on_delete=models.CASCADE , related_name='discoverd_services_alive')
    service = models.CharField(max_length=100 , blank=True , null=True) 
    status_code = models.CharField(max_length=100 , null=True , blank=True)

    label = models.CharField(choices=LABELS , default='available')

    def __str__(self):
        return f"{self.service} - {self.status_code}"


    class Meta:
        db_table = ''
        managed = True
        verbose_name = 'Discovered Service Alive' 
        verbose_name_plural = 'Discovered Services Alive'