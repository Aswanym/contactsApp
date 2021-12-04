from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed

class UserSerializer(serializers.ModelSerializer):

    password = serializers.CharField(
        max_length=65, min_length=4, write_only=True)
    email = serializers.EmailField(max_length=65, min_length=4)
    first_name= serializers.CharField(max_length=255, min_length=2)
    last_name= serializers.CharField(max_length=255, min_length=1)

    class Meta:
        model = User
        fields = ['username','first_name','last_name','email','password']

    def validate(self, attrs):
        email=attrs.get('email','')
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError(
                {'email':('email already exist')})
        return super().validate(attrs)

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(max_length=68, min_length=4)

    def validate(self, attrs):
        email = attrs.get('email','')
        password = attrs.get('password','')

        user = auth.authenticate(email=email, password=password)
        if not user:
            raise serializers.AuthenticationFailed('Invalid credentials, try again')


        return super().validate(attrs)