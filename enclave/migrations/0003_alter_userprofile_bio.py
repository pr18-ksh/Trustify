# Generated by Django 5.1.3 on 2024-11-28 06:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('enclave', '0002_userprofile'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userprofile',
            name='bio',
            field=models.TextField(blank=True, db_index=True, null=True),
        ),
    ]
