from rest_framework import serializers
from .models import Profile, Post
from django.contrib.auth.models import User

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance
    
class ProfileSerializer(serializers.ModelSerializer):
     user = serializers.StringRelatedField()
     class Meta:
        model = Profile
        fields= ['id','user', 'user_type'] 
        
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No user is associated with this email address.")
        return value
    
        
class PostSerializer(serializers.ModelSerializer):
    # author = serializers.StringRelatedField(many=True)
    # author = ProfileSerializer(source='author.profile', read_only=True)
    # author = serializers.PrimaryKeyRelatedField(many=True, read_only=True) 
    author = serializers.SerializerMethodField()
    class Meta:
        model = Post
        fields = '__all__'
        
    def get_author(self, obj):
        return obj.author.user.username if obj.author else None