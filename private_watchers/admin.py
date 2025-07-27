from django.contrib import admin
from .models import *


class WatchedWildcardInline(admin.TabularInline):
    model = WatchedWildcard
    extra = 0
    show_change_link = True



class JSFileWatchListInline(admin.TabularInline):
    model = JSFileWatchList
    extra = 0
    show_change_link = True



class WatchedJSFileInline(admin.TabularInline):
    model = WatchedJSFile
    extra = 0



class WatchedJSFileChangedInline(admin.TabularInline):
    model = WatchedJSFileChanged
    extra = 0


class JSFileWatcherInline(admin.TabularInline):
    model = JSFileWatcher
    extra = 0
    show_change_link = True


class WatcherCIDRInline(admin.TabularInline):
    model = WatcherCIDR
    extra = 0
    show_change_link = True



@admin.register(Tool)
class ToolAdmin(admin.ModelAdmin):
    list_display = ('id', 'tool_name')
    search_fields = ('tool_name',)



@admin.register(AssetWatcher)
class AssetWatcherAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'status','updated_at', 'notify')
    list_filter = ('status', 'notify')
    search_fields = ('user__username',)
    ordering = ('-updated_at',)
    inlines = [WatchedWildcardInline , JSFileWatcherInline , WatcherCIDRInline]



@admin.register(WatchedWildcard)
class WatchedWildcardAdmin(admin.ModelAdmin):
    list_display = ('id', 'watcher', 'wildcard', 'status' ,'get_all_tools', 'updated_at')
    search_fields = ('wildcard',)
    
    list_filter = ['watcher' , 'status' , 'tools']
    def get_all_tools(self, obj):
        return ", ".join([tool.tool_name for tool in obj.tools.all()])
    get_all_tools.short_description = "Tools"



@admin.register(DiscoverSubdomain)
class DiscoverSubdomainAdmin(admin.ModelAdmin):
    list_display = ('id', 'subdomain', 'label', 'wildcard', 'tool' , 'created_at' , 'updated_at')
    search_fields = ('subdomain',)
    ordering = ('-updated_at',)
    list_filter = ('tool','wildcard__watcher__user__username' , 'label')



@admin.register(SubdomainHttpx)
class SubdomainHttpxAdmin(admin.ModelAdmin):
    list_display = ('id','httpx_result','label', 'status_code','server' ,'title', 'ip_address', 'port')
    list_filter = ('status_code', 'port' , 'label')
    search_fields = ('discovered_subdomain__subdomain', 'ip_address', 'title')
    ordering = ['label']


@admin.register(SubdomainHttpxChanges)
class SubdomainHttpxChangesAdmin(admin.ModelAdmin):
    list_display = ['id' , 'discovered_subdomain' , 'label' , 'status_code_change' , 'title_change' , 'server_change'  , 'technologies_change' , 'ip_address_change' , 'port_change' , 'content_type_change',
                    'line_count_change', 
                    'a_records_change',
                    'body_hash_change', 
                    'header_hash_change' , 
                    'has_cdn_change']
    list_filter = ['label']
    search_fields = ['discovered_subdomain__subdomain' , 'ip_address_change','status_code_change' , 'title_change' , 'server_change'  , 'technologies_change' , 'ip_address_change' , 'port_change' , 'content_type_change',
                    'line_count_change', 
                    'a_records_change',
                    'body_hash_change', 
                    'header_hash_change' , 
                    'has_cdn_change']
    ordering = ['label']


    
@admin.register(JSFileWatcher)
class JSFileWatcherAdmin(admin.ModelAdmin):
    list_display = ('id', 'watcher__user__username', 'status', 'last_checked', 'notify')
    list_filter = ('status', 'notify')
    search_fields = ('user__username',)
    inlines = [JSFileWatchListInline]



@admin.register(JSFileWatchList)
class JSFileWatchListAdmin(admin.ModelAdmin):
    list_display = ('id', 'jsfilewatcher', 'name')
    search_fields = ('name',)
    inlines = [WatchedJSFileInline]



@admin.register(WatchedJSFile)
class WatchedJSFileAdmin(admin.ModelAdmin):
    list_display = ('id', 'jsfilewatchlist', 'file_url', 'has_changed', 'last_checked')
    search_fields = ('file_url',)
    list_filter = ('has_changed',)
    inlines = [WatchedJSFileChangedInline]



@admin.register(WatchedJSFileChanged)
class WatchedJSFileChangedAdmin(admin.ModelAdmin):
    list_display = ('id', 'watchedjsfile', 'changed_at')
    search_fields = ('watchedjsfile__file_url',)
    readonly_fields = ('old_hash', 'new_hash', 'diff_snipped', 'changed_at')



@admin.register(Ports)
class PortsAdmin(admin.ModelAdmin):
    list_display = ('port' ,)
    search_fields = ('port' ,)


@admin.register(DiscoverdServices)
class DiscoverdServicesAdmin(admin.ModelAdmin):
    list_display = ['ip' , 'port'  , 'label' ]
    search_fields = ['ip'  , 'label']
    ordering = ['-label']
    list_filter = ['watcher' , 'label' , 'port']


@admin.register(DiscoverdServicesAlive)
class DiscoverdServicesAliveAdmin(admin.ModelAdmin):
    list_display = ['service' , 'status_code' , 'label']
    search_fields = ['service' , 'status_code']
    ordering = ['-label']
    list_filter = ['status_code' , 'label']



@admin.register(WatcherCIDR)
class WatcherCIDRAdmin(admin.ModelAdmin):
    list_display = ('id', 'watcher', 'cidr', 'status')
    search_fields = ('cidr',)
    list_filter = ('status',)
    readonly_fields = ('created_at', 'updated_at')
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('watcher')