from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.shortcuts import get_object_or_404

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import status
from rest_framework.permissions import IsAuthenticated,AllowAny

from django_filters import rest_framework as filters
from rest_framework.pagination import PageNumberPagination
from rest_framework.filters import OrderingFilter
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.generics import ListAPIView


from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout


from .middleware import JWTAuthenticationMiddleware
from .serializers import UserSerializer,PostSerializer,ProfileSerializer
from .models import Profile,Post

import jwt, datetime

######## emails related
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.tokens import AccessToken

class PasswordResetRequestView(APIView):
    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_400_BAD_REQUEST)

        refresh = RefreshToken.for_user(user)
        token = str(refresh.access_token)
        current_site = get_current_site(request).domain
        mail_subject = 'Reset your password'
        message = render_to_string('password_reset_email.html', {
            'user': user,
            'domain': current_site,
            'token': token,
        })
        send_mail(mail_subject, message, 'your-email@example.com', [email])

        return Response({'message': 'Password reset email has been sent.'}, status=status.HTTP_200_OK)

class PasswordResetConfirmView(APIView):
    def get(self, request):
        token = request.query_params.get('token')
        if not token:
            return Response({'error': 'Token is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            access_token = AccessToken(token)
            user_id = access_token['user_id']
            user = User.objects.get(id=user_id)
        except (AccessToken.InvalidToken, User.DoesNotExist):
            return Response({'error': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)

        # Render a password reset form (you can use a template here)
        return render(request, 'password_reset_form.html', {'token': token})

    def post(self, request):
        token = request.data.get('token')
        password = request.data.get('password')
        password_confirm = request.data.get('password_confirm')

        try:
            access_token = AccessToken(token)
            user_id = access_token['user_id']
            user = User.objects.get(id=user_id)
        except (AccessToken.InvalidToken, User.DoesNotExist):
            return Response({'error': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)

        if password and password == password_confirm:
            user.set_password(password)
            user.save()
            return Response({'message': 'Password has been reset.'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Passwords do not match.'}, status=status.HTTP_400_BAD_REQUEST)


# Create your views here.
class RegisterView(APIView):
    # permission_classes = [AllowAny]  # Allow any user to access this view
    
    # @method_decorator(csrf_exempt)
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
         user = serializer.save()
         user.set_password(request.data['password'])
         user.save()
         profile = Profile.objects.create(user=user, user_type=request.data.get('user_type'))
         return Response({
                'user': serializer.data,
                'profile': ProfileSerializer(profile).data,
                'message': 'Signup successful'
            }, status=status.HTTP_201_CREATED)
        return Response({'message':"Failure"}, status=status.HTTP_406_NOT_ACCEPTABLE)
    
    def get(self, request):
        profiles = Profile.objects.all()  # Query the Profile model to get all profiles
        serializer = ProfileSerializer(profiles, many=True)  # Serialize the profiles
        return Response({'message': "List of users", 'data': serializer.data}, status=status.HTTP_200_OK)

# class LoginView(APIView):
#     permission_classes = [AllowAny]  # Allow any user to access this view
#     def post(self, request):
#         username = request.data['username']
#         password = request.data['password']

#         user = User.objects.filter(username=username).first()

#         if user is None:
#             raise AuthenticationFailed('User not found!')

#         if not user.check_password(password):
#             raise AuthenticationFailed('Incorrect password!')

#         payload = {
#             'id': user.id,
#             'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=60),
#             'iat': datetime.datetime.now(datetime.UTC)
#         }

#         token = jwt.encode(payload, 'secret', algorithm='HS256')

#         response = Response()

#         response.set_cookie(key='jwt', value=token, httponly=True)
#         response.data = {
#             'jwt': token
#         }
#         return response
    
class LoginView(APIView): # with session login
    # permission_classes = [AllowAny]  # Allow any user to access this view
    @method_decorator(csrf_exempt)
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(request, username=username, password=password)

        if not user:
            raise AuthenticationFailed('Invalid username or password.')

        # If authentication is successful, login the user
        login(request, user)

        # Generate JWT token (example with jwt.encode)
        payload = {
            'id': user.id,
            'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.now(datetime.UTC)
        }
        token = jwt.encode(payload, 'secret', algorithm='HS256')

         # Set JWT token in response cookie
        response = Response()
        response.set_cookie(
            key='jwt', 
            value=token, 
            httponly=True,  # Set to False for testing to access via JavaScript
            samesite=None,  # Adjust this as per your requirements
            secure=False,     # Set to True if using HTTPS
        )
        response.data = {'message':'login sucessfull', 'jwt': token}

        return response
    
class LogoutView(APIView):
    def post(self, request):
        logout(request)
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'success',
            'status':status.HTTP_200_OK
        }
        return response
    
class PostView(APIView):
    # permission_classes = [IsAuthenticated]
    # @method_decorator(csrf_exempt)
    
    def get(self, request, *args, **kwargs):
        # print("form view", request.author)
        if request.profile.user_type != 'author':
            return Response({'message': "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        posts = Post.objects.filter(author=request.profile)
        print(posts.validated_data)
        serializer = PostSerializer(posts, many=True)
        return Response({'message':"Here is the list of Posts",'data':serializer.data}, status=status.HTTP_200_OK)
    
    def post(self, request):
        print("from view", request.profile)
        print("from view2", request.data)
        serializer = PostSerializer(data=request.data)
        if serializer.is_valid():
            print("s", serializer.validated_data)
            serializer.validated_data['author'] = request.profile
            serializer.save()
            return Response({'message':'Post Added'}, status=status.HTTP_201_CREATED)
        return Response({'message':'something went wrong'}, status=status.HTTP_400_BAD_REQUEST)
    
    # def post(self, request, *args, **kwargs):
    #     # JWTAuthenticationMiddleware()
    #     # serializer = ProfileSerializer(data=request.user)
    #     print("from vw1", request.data)
    #     if not hasattr(request, 'user') or request.user is None:
    #         return Response({'message': "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)
    #     if not hasattr(request, 'profile') or request.profile.user_type != 'author':
    #         return Response({'message': "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)
    #     # print("req",request.profile)
    #     # return Response({'message': 'hi'})
       
    #     # print("self",self)
    #     # if request.user is None:
    #     #     return Response({'message': "21 Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

    #     # if request.profile.user_type != 'author':
    #     #     return Response({'message': "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)
        
    #     print("from view", request.user)
    #     request.data['author'] = request.profile.id  # Assign the author ID to the request data
    #     print("from view", request.data)
    #     serializer = PostSerializer(data=request.data)
    #     # serializer.author = request.user
        
    #     if serializer.is_valid():
    #         serializer.save()
    #         return Response({'message':"Post Added", 'data':serializer.data}, status=status.HTTP_201_CREATED)
    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self, request, *args, **kwargs):
        if request.user is None:
            return Response({'message': "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

        if request.profile.user_type != 'author':
            return Response({'message': "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        try:
            post_id = kwargs.get('pk')
            post = Post.objects.get(id=post_id, author=request.profile)
        except Post.DoesNotExist:
            return Response({'message': "Post not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = PostSerializer(post, data=request.data, partial=True)
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    # @method_decorator(csrf_exempt)
    def delete(self, request, *args, **kwargs):
        if request.user is None:
            return Response({'message': "Unauthenticated"}, status=status.HTTP_401_UNAUTHORIZED)

        if request.profile.user_type != 'author':
            return Response({'message': "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        try:
            post_id = kwargs.get('pk')
            post = Post.objects.get(id=post_id, author=request.profile)
        except Post.DoesNotExist:
            return Response({'message': "Post not found or unauthorized"}, status=status.HTTP_404_NOT_FOUND)

        post.delete()
        return Response({'message':"Post deleted successfully"}, status=status.HTTP_200_OK)
    

class PostListView(APIView): # will not work for pagination, 
    # permission_classes = [IsAuthenticated]
    def get(self, request):
      print(request)
      posts = Post.objects.all()
      serializer = PostSerializer(posts, many=True)
      return Response({'message':"Here is the list of Posts",'data':serializer.data}, status=status.HTTP_200_OK)
    
#     # pagination
#     pagination_class = PageNumberPagination  # Define pagination class
#     filter_backends = [OrderingFilter, DjangoFilterBackend]
#     ordering_fields = ['created_at', 'updated_at']
#     filterset_fields = ['author__username', 'published']

#     def get(self, request):
#         # Get queryset from the database
#         queryset = Post.objects.all()

#         # Apply filtering
#         queryset = self.filter_queryset(queryset)

#         # Apply pagination
#         paginator = self.pagination_class()
#         result_page = paginator.paginate_queryset(queryset, request)

#         # Serialize the paginated queryset
#         serializer = PostSerializer(result_page, many=True)

#         # Return paginated response     
#         return Response({'message':"Here is the list of Posts",'data':paginator.get_paginated_response(serializer.data)}, status=status.HTTP_200_OK)
# class PostFilter(filters.FilterSet):
#     class Meta:
#         model = Post
#         fields = {
#             'author': ['exact'],
#             'published': ['exact'],
#             'created_at': ['gt', 'lt'],
#             'updated_at': ['gt', 'lt'],
#         }
        
# class PostListView(APIView):
#     pagination_class = PageNumberPagination  # Define pagination class
#     filter_backends = [OrderingFilter, DjangoFilterBackend]
#     ordering_fields = ['created_at', 'updated_at']
#     filterset_class = PostFilter

#     def get(self, request):
#         queryset = Post.objects.all()

#         # Apply filtering
#         for backend in self.filter_backends:
#             queryset = backend().filter_queryset(request, queryset, self)

#         # Apply pagination
#         paginator = self.pagination_class()
#         result_page = paginator.paginate_queryset(queryset, request)

#         # Serialize the paginated queryset
#         serializer = PostSerializer(result_page, many=True)

#         # Return paginated response
#         return paginator.get_paginated_response(serializer.data)

# Just for pagination purpose
# class CustomPagination(PageNumberPagination):
#     page_size = 10  # Set the number of items per page
#     page_size_query_param = 'page_size'  # Optional: Allow clients to override the page size
#     max_page_size = 100 
    
# class PostListView(ListAPIView):
#     queryset = Post.objects.all()
#     serializer_class = PostSerializer
#     # pagination_class = PageNumberPagination
#     pagination_class = CustomPagination
#     filter_backends = [OrderingFilter, DjangoFilterBackend]
#     ordering_fields = ['created_at', 'updated_at']
#     filterset_fields = ['author__user__username', 'published']

    # # # Custom pagination settings (if needed)
    # # pagination_class.page_size = 10
    # queryset = Post.objects.all()
    # serializer_class = PostSerializer
    # filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    # ordering_fields = ['author', 'created_at']
    # filterset_fields = ['author', 'published']

# class PostListView(APIView):
#     pagination_class = PageNumberPagination  # Define pagination class
#     filter_backends = [OrderingFilter, DjangoFilterBackend]
#     ordering_fields = ['created_at', 'updated_at']
#     filterset_fields = ['author', 'published']

#     def get(self, request):
#         queryset = Post.objects.all()

#         # Apply filtering
#         for backend in self.filter_backends:
#             backend_instance = backend()
#             if isinstance(backend_instance, DjangoFilterBackend):
#                 queryset = backend_instance.filter_queryset(request, queryset, self)
#             elif isinstance(backend_instance, OrderingFilter):
#                 queryset = backend_instance.filter_queryset(request, queryset, self)

#         # Apply pagination
#         paginator = self.pagination_class()
#         result_page = paginator.paginate_queryset(queryset, request, view=self)

#         # Serialize the paginated queryset
#         serializer = PostSerializer(result_page, many=True)

#         # Return paginated response
#         return paginator.get_paginated_response(serializer.data)
class PostDetailView(APIView):
    # permission_classes = [IsAuthenticated]
    def get(self, request, pk):
        post = get_object_or_404(Post, pk=pk)
        serializer = PostSerializer(post)
        return Response(serializer.data, status=status.HTTP_200_OK)

class AuthorPostsView(APIView):
    # permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        if request.profile.user_type != 'author':
            return Response({'message': "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        posts = Post.objects.filter(author=request.profile)
        serializer = PostSerializer(posts, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)