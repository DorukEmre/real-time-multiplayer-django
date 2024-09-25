# Generated by Django 4.2.16 on 2024-09-25 09:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentif', '0008_alter_user_friends_delete_friendship'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='avatar',
            field=models.ImageField(blank=True, default='avatars/default.png', null=True, upload_to='avatars/'),
        ),
        migrations.AlterField(
            model_name='user',
            name='city',
            field=models.CharField(blank=True, default='Málaga', max_length=100),
        ),
        migrations.AlterField(
            model_name='user',
            name='country',
            field=models.CharField(blank=True, default='Spain', max_length=100),
        ),
    ]