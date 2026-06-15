from django.urls import path
from messenger import views

urlpatterns = [
    # Public
    path('', views.home, name='home'),
    path('login/', views.login_view, name='login'),
    path('signup/', views.signup_view, name='signup'),
    path('logout/', views.logout_view, name='logout'),

    # Dashboard
    path('dashboard/', views.dashboard, name='dashboard'),

    # Encode flow
    path('encrypt/', views.encrypt_view, name='encrypt'),
    path('embed/', views.embed_view, name='embed'),
    path('download/<uuid:op_id>/', views.download_stego, name='download_stego'),

    # Decode flow
    path('extract/', views.extract_view, name='extract'),
    path('decrypt/', views.decrypt_view, name='decrypt'),

    # History & Logs
    path('history/', views.history_view, name='history'),
    path('security-log/', views.security_log_view, name='security_log'),

    # Settings
    path('settings/', views.settings_view, name='settings'),

    # AJAX
    path('api/validate-key/', views.validate_key_ajax, name='validate_key_ajax'),
]
