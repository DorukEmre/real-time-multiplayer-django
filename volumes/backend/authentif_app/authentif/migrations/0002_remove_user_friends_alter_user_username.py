# Generated by Django 4.2.16 on 2024-10-09 18:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentif', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='friends',
        ),
        migrations.AlterField(
            model_name='user',
            name='username',
            field=models.CharField(blank=True, default='', max_length=16, unique=True),
        ),
    ]
