import graphene
from graphene_django.types import DjangoObjectType
from .models import *


class TechniquesCategoryType(DjangoObjectType):
    class Meta:
        model = TechniquesCategory
        fields = '__all__'


class TechniquesType(DjangoObjectType):
    class Meta:
        model = Techniques
        fields = '__all__'

        
class CreateTechnique(graphene.Mutation):
    class Arguments:
        title = graphene.String(required=True)
        content = graphene.String(required=True)
        preview_text = graphene.String(required=True)
        category_id = graphene.Int(required=True)
        difficulty = graphene.String(required=False)
        related_tools = graphene.List(graphene.Int)
        proof_of_concept = graphene.String(required=False)
        price = graphene.Decimal(required=False)
        is_public = graphene.Boolean(required=False, default_value=True)

    technique = graphene.Field(TechniquesType)
    success = graphene.Boolean()
    message = graphene.String()

    def mutate(self, info, title, content, category_id, preview_text , difficulty=None, related_tools=None, proof_of_concept=None, price=None, is_public=True):
        user = info.context.user
        if user.is_anonymous:
            return CreateTechnique(success=False, message="authentication required")

        try:
            category = TechniquesCategory.objects.get(id=category_id)
        except TechniquesCategory.DoesNotExist:
            return CreateTechnique(success=False, message="category not found")

        valid_difficulties = ['Easy', 'Medium', 'Hard']
        if difficulty and difficulty not in valid_difficulties:
            return CreateTechnique(success=False, message="invalid difficulty value")

        technique = Techniques.objects.create(
            author=user,
            title=title,
            preview_text=preview_text,
            content=content,
            category=category,
            difficulty=difficulty,
            proof_of_concept=proof_of_concept,
            price=price,
            is_public=is_public,
        )

        if related_tools:
            tools = Tool.objects.filter(id__in=related_tools)
            technique.related_tools.set(tools)

        return CreateTechnique(success=True, message="technique created successfully", technique=technique)



class UpdateTechnique(graphene.Mutation):
    class Arguments:
        id = graphene.ID(required=True)
        title = graphene.String()
        content = graphene.String()
        preview_text = graphene.String()
        category_id = graphene.Int()
        difficulty = graphene.String()
        related_tools = graphene.List(graphene.Int)
        proof_of_concept = graphene.String()
        price = graphene.Decimal()
        is_public = graphene.Boolean()

    technique = graphene.Field(TechniquesType)
    success = graphene.Boolean()
    message = graphene.String()

    def mutate(self, info, id, title=None, content=None, preview_text=None, category_id=None,
               difficulty=None, related_tools=None, proof_of_concept=None, price=None, is_public=None):
        user = info.context.user
        if user.is_anonymous:
            return UpdateTechnique(success=False, message="authentication required")

        try:
            technique = Techniques.objects.get(id=id)
        except Techniques.DoesNotExist:
            return UpdateTechnique(success=False, message="technique not found")

        if technique.author != user:
            return UpdateTechnique(success=False, message="permission denied")

        if title is not None:
            technique.title = title
        if content is not None:
            technique.content = content
        if preview_text is not None:
            technique.preview_text = preview_text
        if category_id is not None:
            try:
                category = TechniquesCategory.objects.get(id=category_id)
                technique.category = category
            except TechniquesCategory.DoesNotExist:
                return UpdateTechnique(success=False, message="category not found")
        if difficulty is not None:
            if difficulty not in ['Easy', 'Medium', 'Hard']:
                return UpdateTechnique(success=False, message="invalid difficulty value")
            technique.difficulty = difficulty
        if proof_of_concept is not None:
            technique.proof_of_concept = proof_of_concept
        if price is not None:
            technique.price = price
        if is_public is not None:
            technique.is_public = is_public
        if related_tools is not None:
            tools = Tool.objects.filter(id__in=related_tools)
            technique.related_tools.set(tools)

        technique.save()

        return UpdateTechnique(success=True, message="technique updated successfully", technique=technique)



class DeleteTechnique(graphene.Mutation):
    class Arguments:
        techniqueId = graphene.ID(required=True)

    success = graphene.Boolean()
    message = graphene.String()

    def mutate(self, info, techniqueId):
        user = info.context.user
        if user.is_anonymous:
            return DeleteTechnique(success=False, message="Authentication required")

        try:
            technique = Techniques.objects.get(id=techniqueId, author=user)
            technique.delete()
            return DeleteTechnique(success=True, message="Technique deleted successfully")
        except Techniques.DoesNotExist:
            return DeleteTechnique(success=False, message="Technique not found or not owned by user")
