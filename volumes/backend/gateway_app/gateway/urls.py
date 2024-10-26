from django.contrib import admin
from django.urls import path #, re_path
from gateway import views, viewsAuth, viewsErrors, viewsProfile, viewsPlay, viewsInvitation
from django.conf.urls.static import static
from django.conf import settings
from django.conf.urls.i18n import i18n_patterns
from django.urls import path, include

handler405 = 'gateway.viewsErrors.get_405'

urlpatterns = [
    # errors pages
    path('404/', viewsErrors.get_404, name='404'),
    path('405/', viewsErrors.get_405, name='405'),

    # home page
    path('', views.get_home, name='home'),
    path('home/', views.get_home),

    # authentif api
    path('signup/', viewsAuth.view_signup, name='signup'),
    path('login/', viewsAuth.view_login, name='login'),
    path('logout/', viewsAuth.get_logout, name='logout'),
    path('oauth', viewsAuth.oauth, name='oauth'),
    path('oauth_callback', viewsAuth.oauth_callback, name='oauth_callback'),

    # profile api
    path('profile/', viewsProfile.get_profile, name='profile'),
    path('profile/match_history/<str:username>/', viewsProfile.get_match_history, name='match_history'),
    path('edit_profile/', viewsProfile.get_edit_profile, name='edit_profile'),
    path('edit_profile_general/', viewsProfile.post_edit_profile_general, name='edit_profile_general'),
    path('edit_profile_security/', viewsProfile.post_edit_profile_security, name='edit_profile_security'),
    path('edit_profile_avatar/', viewsProfile.post_edit_profile_avatar, name='edit_profile_avatar'),
    path('friend_profile/<int:friend_id>/', viewsProfile.get_friend_profile, name='friend_profile'),
    path('download_42_avatar/', viewsProfile.download_42_avatar, name='download_42_avatar'),
    path('play/checkNameExists/', viewsProfile.checkNameExists, name='checkNameExists'),

    # invite friends
    path('invite_a_friend/', viewsInvitation.post_invite, name='post_invite'),
    path('invite_to_play/<int:receiver_id>/', viewsInvitation.invite_to_play, name='invite_to_play'),
    path('my_friends/', views.list_friends, name='list_friends'),
	path('getFriends/', views.get_friends, name='get_friends'),
	path('blockFriend/<int:user_id>/', viewsInvitation.block_friends, name='block'),

    # play api
    path('play/', viewsPlay.get_play, name='play'),
    path('tournament/', viewsPlay.get_tournament, name='tournament'),

    # Languages API
    path('i18n/', include('django.conf.urls.i18n')),

]

urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)