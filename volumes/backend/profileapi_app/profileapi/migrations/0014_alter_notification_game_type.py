# Generated by Django 4.2.16 on 2024-11-06 10:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('profileapi', '0013_rename_game_notification_game_type'),
    ]

    operations = [
        migrations.AlterField(
            model_name='notification',
            name='game_type',
            field=models.CharField(blank=True, default='', max_length=16, null=True),
        ),
    ]
