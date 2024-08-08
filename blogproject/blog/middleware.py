# blog/middleware.py

import jwt
from django.conf import settings
from django.contrib.auth.models import User
from django.urls import reverse
from django.core.exceptions import MiddlewareNotUsed
from rest_framework.exceptions import AuthenticationFailed
from .models import Profile

class JWTAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.excluded_paths = [
            reverse('login'),
            reverse('register'),
            # reverse('password_reset'),
            # reverse('password_reset_confirm'),
            '/favicon.ico',
         ]        
    def __call__(self, request):
        # print("before if",request.path)
        # Check if the request path starts with any of the excluded paths
        if any(request.path.startswith(path) for path in self.excluded_paths) or request.path.startswith("/admin/"):
            # print("During if", request.path)
            return self.get_response(request)
        
        print("after if",request.path)
        
        # token = request.COOKIES.get('jwt')
        # # token = request.META.get('jwt')
        # print("21",token)
        # if token is None:
        #  token = request.headers.get('Authorization', '').split('Bearer ')
        #  if len(token) != 2:
        #     raise AuthenticationFailed('Token not found or invalid!')
        # token = token[1]
        
        # Retrieve token from cookies
        token = request.COOKIES.get('jwt')

        # If token is not found in cookies, check the headers
        if not token:
            auth_header = request.headers.get('Authorization', '')
            # Check if the Authorization header contains the token in the expected format
            if auth_header.startswith('Bearer '):
                token = auth_header.split('Bearer ')[1]
            else:
                raise AuthenticationFailed('Token not found or invalid!')

        print("Token:", token)
        
        
        # print("t", token)
        if not token:
            return self.get_response(request)
        
        try:
            payload = jwt.decode(token, 'secret', algorithms=['HS256'])
            print(payload)
            user = User.objects.filter(id=payload['id']).first()
            print("user",user)
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')

       
       
        if user is None:
            raise AuthenticationFailed('Unauthenticated!')

        request.user = user
        profile = Profile.objects.filter(user=user).first()
        request.profile = profile
        print("from mw1", request.user.id)
        print("from mw2", request.profile)
        response = self.get_response(request)
        print("res", response)
        return response
