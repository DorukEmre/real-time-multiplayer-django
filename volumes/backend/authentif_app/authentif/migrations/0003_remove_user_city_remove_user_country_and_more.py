# Generated by Django 4.2.16 on 2024-10-09 18:15

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('authentif', '0002_remove_user_friends_alter_user_username'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='city',
        ),
        migrations.RemoveField(
            model_name='user',
            name='country',
        ),
        migrations.RemoveField(
            model_name='user',
            name='defeats',
        ),
        migrations.RemoveField(
            model_name='user',
            name='played_games',
        ),
        migrations.RemoveField(
            model_name='user',
            name='wins',
        ),
    ]