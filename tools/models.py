from django.db import models
from core.models import *


class ToolCategory(BaseModel):
    title = models.CharField(max_length=100)
    slug = models.SlugField(max_length=100, unique=True)
    parent = models.ForeignKey('self' ,null=True , blank=True , on_delete=models.CASCADE, related_name='subcategories')


    def __str__(self):
        return self.title
    

    class Meta:
        verbose_name = 'Tool Category'
        verbose_name_plural = 'Tool Categories'
        ordering = ['title']





class Tool(AttributesBaseModel):
    
    category = models.ForeignKey(ToolCategory, on_delete=models.SET_NULL, null=True, blank=True, related_name='tools')

    upload_file = models.FileField(upload_to='tools/tool/files/', blank=True, null=True)

    demo_video_file = models.FileField(upload_to='tools/tool/demo/videos/', blank=True, null=True)
    demo_video_url = models.URLField(blank=True, null=True)

    impact = models.TextField(blank=True, null=True)

    github_repo_url = models.URLField(blank=False, null=False)
    access_token = models.CharField(max_length=255, blank=True, null=True)
    

    def __str__(self):
        return self.title

    def like_count(self):
        return self.likes.count()

    def comment_count(self):
        return self.comments.count()

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = self.title.replace(" ", "-").lower()
        
        if self.price < 1 :
            self.is_free = True
            self.price = 0
        elif self.price >= 1:
            self.is_free = False

        super().save(*args, **kwargs)
        
    class Meta:
        verbose_name = 'Tool'
        verbose_name_plural = 'Tools'
        ordering = ['-created_at']





class ToolImage(BaseModel):
    tool = models.ForeignKey(Tool, on_delete=models.CASCADE, related_name='images')
    image = models.ImageField(upload_to='tool/toolimage/images/' , blank=True , null=False)

    def __str__(self):
        return f"Image for {self.tool.title}"

    class Meta:
        verbose_name = 'Tool Image'
        verbose_name_plural = 'Tool Images'
        ordering = ['-created_at']