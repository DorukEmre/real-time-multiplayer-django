# Generated by Django 4.2.16 on 2024-10-17 09:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('livechat', '0004_rename_receiver_id_message_dest_user_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='message',
            name='read',
            field=models.BooleanField(default=False),
        ),
    ]