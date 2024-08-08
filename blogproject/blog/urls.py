from django.urls import path,include
from .views import RegisterView,LoginView, LogoutView, PostView,PostListView,PostDetailView,AuthorPostsView

urlpatterns = [
    # path('password_reset/', PasswordResetRequestView.as_view(), name='password_reset'),
    # path('password_reset_confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('register/',RegisterView.as_view(),name='register'),
    path('login/',LoginView.as_view(),name='login'),
    path('logout/', LogoutView.as_view(), name='logout'), 
    path('posts/',PostView.as_view(),name='post-list'),
    path('posts/<int:pk>/', PostView.as_view(), name='post_detail_update_delete'),
    path('posts/all/', PostListView.as_view(), name='list_posts'),  # New URL for listing all posts
    path('posts/detail/<int:pk>/', PostDetailView.as_view(), name='post_detail'),
    path('author/posts/', AuthorPostsView.as_view(), name='author_posts'),  # URL for author posts
]