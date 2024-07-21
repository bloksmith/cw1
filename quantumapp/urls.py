# quantumapp/urls.py

from django.urls import path
from . import views

app_name = 'quantumapp'  # Define the app namespace

urlpatterns = [
    path('register_master_node/', views.register_master_node, name='register_master_node'),
    # Add other url patterns here
]
