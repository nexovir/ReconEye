from django.contrib import admin
from .models import *
from nested_admin import NestedTabularInline, NestedModelAdmin


@admin.action(description="Set label to 'New'")
def make_label_new(modeladmin, request, queryset):
    queryset.update(label="new")

@admin.action(description="Set label to 'Available'")
def make_label_available(modeladmin, request, queryset):
    queryset.update(label="available")



class RequestHeadersInline(admin.TabularInline):
    model = RequestHeaders
    extra = 0
    show_change_link = True

class WatchedWildcardInline(NestedTabularInline):
    model = WatchedWildcard
    extra = 0
    show_change_link = True


class WatcherCIDRInline(NestedTabularInline):
    model = WatcherCIDR
    extra = 0
    show_change_link = True



@admin.register(Tool)
class ToolAdmin(admin.ModelAdmin):
    list_display = ('id', 'tool_name')
    search_fields = ('tool_name',)



@admin.register(AssetWatcher)
class AssetWatcherAdmin(NestedModelAdmin):
    list_display = ('id', 'user', 'status','updated_at', 'notify')
    list_filter = ('status', 'notify')
    search_fields = ('user__username',)
    ordering = ('-updated_at',)
    inlines = [WatchedWildcardInline , WatcherCIDRInline]


@admin.register(WatchedWildcard)
class WatchedWildcardAdmin(NestedModelAdmin):
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
    ordering = ('-label',)
    list_filter = ('tool','wildcard__watcher__user__username' , 'label')
    inlines = [RequestHeadersInline]
    actions = [make_label_new , make_label_available]
    

@admin.register(SubdomainHttpx)
class SubdomainHttpxAdmin(admin.ModelAdmin):
    list_display = ('id','httpx_result','label', 'status_code','server' ,'title', 'ip_address', 'port')
    list_filter = ('status_code', 'port' , 'label')
    search_fields = ('discovered_subdomain__subdomain', 'ip_address', 'title' , 'technologies','httpx_result')
    ordering = ['-label']
    actions = [make_label_new , make_label_available]


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
    ordering = ['-updated_at']
    actions = [make_label_new , make_label_available]



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



# @admin.register(WatcherCIDR)
# class WatcherCIDRAdmin(admin.ModelAdmin):
#     list_display = ('id', 'watcher', 'cidr', 'status')
#     search_fields = ('cidr',)
#     list_filter = ('status',)
#     readonly_fields = ('created_at', 'updated_at')
    
#     def get_queryset(self, request):
#         return super().get_queryset(request).select_related('watcher')