# Generated by Django 4.2.16 on 2024-11-06 15:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('profileapi', '0015_alter_notification_type'),
    ]

    operations = [
        migrations.AlterField(
            model_name='notification',
            name='type',
            field=models.CharField(max_length=23),
        ),
    ]
