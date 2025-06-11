from django.db import models
from core.models import BaseModel
from tools.models import Tool
from core.models import *

class TechniquesCategory(BaseModel):
    title = models.CharField(max_length=100)
    slug = models.SlugField(unique=True)
    parent = models.ForeignKey('self', on_delete=models.CASCADE, related_name="subcategories" , null = True , blank=True)

    def __str__(self):
        return self.title
    
    class Meta:
        verbose_name = "Technique Category"
        verbose_name_plural = "Technique Categories"




class Techniques(AttributesBaseModel):
    category = models.ForeignKey(TechniquesCategory , blank=True , null=True , on_delete=models.CASCADE)
    difficulty = models.CharField(max_length=50, choices=[('Easy', 'Easy'), ('Medium', 'Medium'), ('Hard', 'Hard')], help_text="The difficulty level of the technique.")
    related_tools = models.ManyToManyField(Tool , blank=True, related_name='techniques', help_text="Tools commonly used with this technique.")
    proof_of_concept = models.TextField(blank=True, null=True, help_text="Proof of concept or example of the technique in action.")


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
        verbose_name = 'Technique'
        verbose_name_plural = 'Techniques'


