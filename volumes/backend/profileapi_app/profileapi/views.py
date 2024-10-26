from django.http import JsonResponse, HttpResponse
from profileapi.forms import InviteFriendForm
from profileapi.models import Profile, Notification
from profileapi.forms import EditProfileForm
from django.db import DatabaseError
from django.utils.translation import gettext as _
import json
import os
import requests
import logging
from django.views.decorators.csrf import csrf_exempt

logger = logging.getLogger(__name__)

@csrf_exempt
def api_signup(request):
    logger.debug("--> hello from api_signup")
    if (request.method != 'POST'):
        logger.debug("Method not allowed")
        return HttpResponse('Method not allowed', status=405)
    logger.debug("--> POST method")
    data = json.loads(request.body)
    try:
        if data['id_42']:
            display_name = data['username']
    except:
        display_name = data['username']
    logger.debug(f"data : {data}")
    try:
      profile = Profile(
        user_id=data['user_id'],
        display_name= display_name,
      )
      logger.debug("--> profile user_id created")
      profile.save()
      logger.debug("--> profile created")
      return JsonResponse({
            'status': 'success',
            'type': 'signup_successful',
            'message': _('Signup successful')
          }, status=201)
    except Exception as e:
      return JsonResponse({'error': str(e)}, status=400)


def api_edit_profile(request):
    logger.debug("api_edit_profile")
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            logger.debug(f'data: {data}')
            user_id = data.get('user_id')
            logger.debug(f'user_id: {user_id}')

            # Use get_object_or_404 to handle the case where the user is not found
            user_obj = Profile.objects.get(user_id=user_id)
            logger.debug('user_obj recovered')

            # Log the current profile data
            logger.debug(f'country: {user_obj.country}')
            logger.debug(f'city: {user_obj.city}')
            logger.debug(f'preferred_language: {user_obj.preferred_language}')

            # Ensure data is passed as a dictionary
            form = EditProfileForm(data, instance=user_obj)
            logger.debug(f'form: {form}')
            # Log the current profile data
            logger.debug('------------------------------')
            logger.debug(f'country: {user_obj.country}')
            logger.debug(f'city: {user_obj.city}')

            if form.is_valid():
                logger.debug('api_edit_profile > Form is valid')
                form.save()
                return JsonResponse({
                      'status': 'success',
                      'type': 'profile_updated',
                      'message': _('Profile updated')
                    }, status=200)
            else:
                logger.debug('api_edit_profile > Form is invalid')
                return JsonResponse({'status': 'error', 'message': _('Invalid profile data')}, status=400)
        except (json.JSONDecodeError, DatabaseError) as e:
            logger.debug(f'api_edit_profile > Invalid JSON error: {str(e)}')
            return JsonResponse({'status': 'error', 'message': _('Error: ') + str(e)}, status=400)
    else:
        logger.debug('api_edit_profile > Method not allowed')
        return JsonResponse({'status': 'error', 'message': _('Method not allowed')}, status=405)

def get_full_profile(request, user_id):
    logger.debug("get_full_profile")
    id = int(user_id)
    logger.debug(f"id: {id}")
    authentif_url = 'https://authentif:9001/api/getUserInfo/' + str(id) + '/'
    try:
        authentif_response = requests.get(authentif_url, verify=os.getenv("CERTFILE"))
        authentif_data = authentif_response.json()
        user_obj = Profile.objects.get(user_id=id)
        logger.debug('user_obj recovered')
        data = {
              'user_id': user_obj.user_id,
              'username': authentif_data['username'],
              'avatar': '/media/' + authentif_data['avatar_url'],
              'country': user_obj.country,
              'city': user_obj.city,
              'display_name': user_obj.display_name,
              'preferred_language': user_obj.preferred_language,
              'played_games': user_obj.played_games,
              'wins': user_obj.wins,
              'defeats': user_obj.defeats,
              'winrate': 0 if user_obj.played_games == 0 else round(user_obj.wins / user_obj.played_games * 100, 2),
              'total_score' : user_obj.wins * 50,
            }
        return JsonResponse(data, status=200)
    except Profile.DoesNotExist:
        logger.debug('get_profile > User not found')
        return JsonResponse({'status': 'error', 'message': _('User not found')}, status=404)
    except Exception as e:
        logger.debug(f'get_profile > {str(e)}')
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

def get_friends(request, user_id):
    logger.debug("get_friends")
    id = int(user_id)
    logger.debug(f"id: {id}")
    try:
        user_obj = Profile.objects.get(user_id=id)
        logger.debug('user_obj recovered')
        friends = user_obj.friends.all()
        logger.debug('friends recovered')
        data = []
        for friend in friends:
            # Recover username and avatar from authentif app
            authentif_url = 'https://authentif:9001/api/getUserInfo/' + str(friend.user_id) + '/'
            response = requests.get(authentif_url, verify=os.getenv("CERTFILE"))
            user_data = response.json()
            logger.debug(f'get_friends > user_data: {user_data}')

            data.append({
                'user_id': friend.user_id,
                'display_name': friend.display_name,
                'country': friend.country,
                'city': friend.city,
                'preferred_language': friend.preferred_language,
                'played_games': friend.played_games,
                'wins': friend.wins,
                'defeats': friend.defeats,
                'avatar': '/media/' + user_data['avatar_url'],
                'username': user_data['username'],
            })
        return JsonResponse(data, status=200, safe=False)
    except Profile.DoesNotExist:
        logger.debug('get_friends > User not found')
        return JsonResponse({'status': 'error', 'message': _('User not found')}, status=404)
    except Exception as e:
        logger.debug(f'get_friends > {str(e)}')
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)


def get_profile_api(request, user_id):
    logger.debug("")
    logger.debug("get_profile_api")
    id = int(user_id)
    logger.debug(f"id: {id}")
    try:
        user_obj = Profile.objects.get(user_id=id)
        logger.debug('user_obj recovered')
        data = {
              'user_id': user_obj.user_id,
              'country': user_obj.country,
              'city': user_obj.city,
              'display_name': user_obj.display_name,
              'preferred_language': user_obj.preferred_language,
              'played_games': user_obj.played_games,
              'wins': user_obj.wins,
              'defeats': user_obj.defeats,
            }
        return JsonResponse(data, status=200)
    except Profile.DoesNotExist:
        logger.debug('get_profile > User not found')
        return JsonResponse({'status': 'error', 'message': _('User not found')}, status=404)
    except Exception as e:
        logger.debug(f'get_profile > {str(e)}')
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

def get_users_ids(request):
    logger.debug("get_users_ids")
    try:
        users = Profile.objects.all()
        logger.debug('users recovered')
        data = []
        for user in users:
            data.append(user.user_id)
        return JsonResponse(data, status=200, safe=False)
    except Exception as e:
        logger.debug(f'get_users_ids > {str(e)}')
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

def create_notifications(request):
    logger.debug("create_notifications")
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            logger.debug(f'data: {data}')
            sender_id = data.get('sender_id')
            receiver_id = data.get('receiver_id')
            message = data.get('message')
            type = data.get('type')

            logger.debug(f'sender: {sender_id}')
            logger.debug(f'receiver: {receiver_id}')
            logger.debug(f'message: {message}')
            logger.debug(f'type: {type}')
            
            if (sender_id == receiver_id):
                return JsonResponse({'status': 'error', 'message': _('You cannot send a notification to yourself')}, status=400)

            sender_obj = Profile.objects.get(user_id=sender_id)
            receiver_obj = Profile.objects.get(user_id=receiver_id)
            logger.debug('sender_obj and receiver_obj recovered')
            notification = Notification(
                sender=sender_obj,
                receiver=receiver_obj,
                message=message,
                type=type
            )
            notification.save()

            return JsonResponse({'status': 'success', 'message': _('Notification created')}, status=201)
        except (json.JSONDecodeError, DatabaseError) as e:
            logger.debug(f'create_notifications > Invalid JSON error: {str(e)}')
            return JsonResponse({'status': 'error', 'message': 'Error: ' + str(e)}, status=400)
    else:
        logger.debug('create_notifications > Method not allowed')
        return JsonResponse({'status': 'error', 'message': _('Method not allowed')}, status=405)

def get_notifications(request, user_id):
    logger.debug("get_notifications")
    id = int(user_id)
    logger.debug(f"id: {id}")
    try:
        user_obj = Profile.objects.get(user_id=id)
        logger.debug('user_obj recovered')
        notifications = Notification.objects.filter(receiver=user_obj)
        logger.debug('notifications recovered')
        data = []
        for notification in notifications:
            data.append({
                'sender': notification.sender.user_id,
                'receiver': notification.receiver.user_id,
                'message': notification.message,
                'type': notification.type,
                'date': notification.date,
                'status': notification.status,
            })
        return JsonResponse(data, status=200, safe=False)
    except Profile.DoesNotExist:
        logger.debug('get_notifications > User not found')
        return JsonResponse({'status': 'error', 'message': _('User not found')}, status=404)
    except Exception as e:
        logger.debug(f'get_notifications > {str(e)}')
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

def set_notif_as_readen(request, sender_id, receiver_id, type, response):
    logger.debug("set_notif_as_readen")
    try:
        sender_obj = Profile.objects.get(user_id=sender_id)
        receiver_obj = Profile.objects.get(user_id=receiver_id)
        if (type == 'friend_request_response'):
          request_type = 'friend_request'
        else:
          request_type = 'game_request'
        logger.debug('sender_obj and receiver_obj recovered')
        notifications = Notification.objects.filter(sender=sender_obj, receiver=receiver_obj, type=request_type)
        logger.debug('notifications recovered')
        for notification in notifications:
            if (response == 'accept'):
              notification.status = 'accepted'
            elif (response == 'decline'):
              notification.status = 'declined'
            notification.save()
            logger.debug('notification marked as read')

            # if friend request accepted, save friendship in database
            if response == 'accept' and type == 'friend_request_response':
                sender_obj.friends.add(receiver_obj)
                sender_obj.save()
                receiver_obj.save()
    except Profile.DoesNotExist:
        logger.debug('set_notif_as_readen > User not found')
        return JsonResponse({'status': 'error', 'message': _('User not found')}, status=404)
    return JsonResponse({'status': 'success', 'message': _('Notification marked as read')}, status=200)


def set_all_notifs_as_readen(request, receiver_id):
    logger.debug("set_all_notifs_as_readen")
    try:
        receiver_obj = Profile.objects.get(user_id=receiver_id)
        logger.debug('receiver_obj recovered')
        notifications = Notification.objects.filter(receiver=receiver_obj, status='unread')
        logger.debug('notifications recovered')
        for notification in notifications:
            notification.status = 'read'
            notification.save()
            logger.debug('notification marked as read')
    except Profile.DoesNotExist:
        logger.debug('set_all_notifs_as_readen > User not found')
        return JsonResponse({'status': 'error', 'message': _('User not found')}, status=404)
    return JsonResponse({'status': 'success', 'message': _('All notifications marked as read')}, status=200)

def check_friendship(request, sender_id, receiver_id):
    logger.debug("check_friendship")
    try:
        sender_obj = Profile.objects.get(user_id=sender_id)
        receiver_obj = Profile.objects.get(user_id=receiver_id)
        logger.debug('sender_obj and receiver_obj recovered')
        if receiver_obj in sender_obj.friends.all():
            logger.debug('check_friendship > Friendship exists')
            return JsonResponse({'status': 'success', 'message': _('Friendship exists')}, status=404)
        else:
            logger.debug('check_friendship > Friendship does not exist')
            return JsonResponse({'status': 'error', 'message': _('Friendship does not exist')}, status=200)
    except Profile.DoesNotExist:
        logger.debug('check_friendship > User not found')
        return JsonResponse({'status': 'error', 'message': _('User not found')}, status=404)
    except Exception as e:
        logger.debug(f'check_friendship > {str(e)}')
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)

def check_displayname_exists(request):
    logger.debug("check_displayname_exists")
    if request.method == 'POST':
        try:
          data = json.loads(request.body)
          name_to_test = data.get('name')
          if Profile.objects.filter(display_name=name_to_test).exists():
              logger.debug('check_displayname_exists > User exists')
              return JsonResponse({'status': 'success', 'message': _('User exists')})
          else:
              logger.debug('check_displayname_exists > User does not exist')
              return JsonResponse({'status': 'failure', 'message': _('User does not exist')}, status=404)
        except json.JSONDecodeError:
            logger.debug('check_displayname_exists > Invalid JSON')
            return JsonResponse({'status': 'error', 'message': _('Invalid JSON')}, status=400)
    logger.debug('check_displayname_exists > Method not allowed')
    return JsonResponse({'status': 'error', 'message': _('Method not allowed')}, status=405)