from django.db import models
from django.contrib.auth.models import User

class PortScanResult(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    target = models.CharField(max_length=255)
    port = models.IntegerField()
    state = models.CharField(max_length=50)
    service = models.CharField(max_length=255, null=True, blank=True)
    version = models.CharField(max_length=255, null=True, blank=True)
    scanned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.target}:{self.port} ({self.state})"
    
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    bio = models.TextField(blank=True, null=True)    

class MalwareScanResult(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file_name = models.CharField(max_length=255)
    file_hash = models.CharField(max_length=64)
    scan_date = models.DateTimeField(auto_now_add=True)
    scan_results = models.JSONField()  # Stores VirusTotal API response

class PhishingDetectionResult(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    url = models.URLField()
    is_phishing = models.BooleanField()
    reason = models.TextField()
    scan_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.url