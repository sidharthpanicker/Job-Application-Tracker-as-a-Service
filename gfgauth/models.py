from django.contrib import admin
from django.contrib.auth.models import User
from django.db import models
from oauth2client.contrib.django_util.models import CredentialsField


class CredentialsModel(models.Model):
    id = models.ForeignKey(User, primary_key=True, on_delete=models.CASCADE)
    credential = CredentialsField()
    task = models.CharField(max_length=80, null=True)
    updated_time = models.CharField(max_length=80, null=True)


class TrackStatus(models.Model):
    messageid = models.CharField(max_length=100, null=True)
    userid = models.CharField(max_length=100, null=True)
    date = models.CharField(max_length=100, null=True)
    company = models.CharField(max_length=100, null=True)
    job_role = models.CharField(max_length=100, null=True)
    status = models.CharField(max_length=100, null=True)


class CredentialsAdmin(admin.ModelAdmin):
    pass
