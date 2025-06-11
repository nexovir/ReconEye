from django.db import models
from core.models import *
from techniques.models import *
from tools.models import *


class WriteupCategory(BaseModel):
    title = models.CharField(max_length=100)
    slug = models.SlugField(unique=True)
    parent = models.ForeignKey('self', on_delete=models.CASCADE, related_name="subcategories" , null = True , blank=True)

    def __str__(self):
        return self.title
    
    class Meta:
        verbose_name = "Category"
        verbose_name_plural = "Categories"




class WriteUp(AttributesBaseModel):

    category = models.ForeignKey(WriteupCategory , on_delete=models.CASCADE , related_name='writeup' , blank=False, null=True , default=None)

    vulnerability_type = models.CharField(max_length=50)
    target_type = models.CharField(max_length=100)  
    tools_used = models.ManyToManyField(Tool , related_name='writeup_tools', blank=True)
    techniques = models.ManyToManyField(Techniques, related_name='writeup_techniques', blank=True)
    read_time = models.PositiveIntegerField(default=3)  # بر حسب دقیقه


    def __str__(self):
        return self.title
    
    def like_count(self):
        return self.likes.count()

    def comment_count(self):
        return self.comments.count()
    
    class Meta :
        verbose_name = 'WriteUp'
        verbose_name_plural = 'WriteUps'


class WriteUpAttachment(models.Model):
    writeup = models.ForeignKey("WriteUp", on_delete=models.CASCADE, related_name="attachments")
    file = models.FileField(upload_to="writeups/attachments/")
    uploaded_at = models.DateTimeField(auto_now_add=True)
