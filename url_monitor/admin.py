from django.contrib import admin
from django.contrib.admin import register
from .models import *
from django.utils.html import format_html

@admin.action(description="Set label to 'New'")
def make_label_new(modeladmin, request, queryset):
    queryset.update(label="new")

@admin.action(description="Set label to 'Available'")
def make_label_available(modeladmin, request, queryset):
    queryset.update(label="available")




@register(Url)
class UrlAdmin(admin.ModelAdmin):
    list_display = ['subdomain' , 'path' , 'query' , 'status' ,'label', 'ext' , 'short_url']
    search_fields = ['subdomain__subdomain' , 'path' ]
    list_filter = ['label' , 'ext' , 'status']
    ordering = ['-label']
    actions = [make_label_new , make_label_available]

    def short_url(self, obj):
        return format_html('<a href="{}" target="_blank">Click here</a>', obj.url)
    short_url.short_description = 'URL'

@register(UrlChanges)
class UrlChangesAdmin(admin.ModelAdmin):
    list_display = ['url' , 'body_hash_change' , 'status_change', 'query_change' ,'ext', 'label' ,'short_url']
    search_fields = ['path_change']
    list_filter = ['label' , 'ext']
    ordering = ['-label']
    
    def short_url(self, obj):
        return format_html('<a href="{}" target="_blank">Click here</a>', obj.url.url)
    short_url.short_description = 'URL'


@register(Parameter)
class ParameterAdmin(admin.ModelAdmin):
    list_display = ['url' , 'method' , 'status' , 'parameter' , 'reason_kind' , 'injection_place' , 'label' , 'short_url']
    list_filter = ['label' , 'injection_place' , 'method' , 'status' , 'reason_kind']
    ordering = ['-label']
    
    def short_url(self, obj):
        return format_html('<a href="{}" target="_blank">Click here</a>', obj.url.url)
    short_url.short_description = 'URL'
    

@register(SubdomainParameter)
class SubdomainParameterAdmin(admin.ModelAdmin):
    list_display = ['wildcard' , 'parameter' , 'label']
    search_fields = ['wildcard' , 'path' ]
    list_filter = ['label']
    list_per_page = 100

    ordering = ['-label']