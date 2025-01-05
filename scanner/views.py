from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
import socket
import threading
import time
from .models import PortScanResult
import hashlib
import requests
from .models import MalwareScanResult
from .forms import FileUploadForm
from .forms import URLSubmitForm
from .models import PhishingDetectionResult

def register_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('login')
    else:
        form = UserCreationForm()
    return render(request, 'scanner/register.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')
    return render(request, 'scanner/login.html')

@login_required
def dashboard(request):
    return render(request, 'scanner/dashboard.html')

def scan_port(target, port, result_list):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            service, version = get_service_and_version(target, port)
            result_list.append({
                'port': port,
                'state': 'Open',
                'service': service,
                'version': version
            })
        sock.close()
    except socket.error:
        pass

# Dictionary for common services
COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    137: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    179: "BGP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP Proxy",
    8443: "HTTPS Proxy",
    9200: "Elasticsearch"
}

def get_service_and_version(target, port):
    try:
        # Check for common services
        service = COMMON_SERVICES.get(port, "Unknown Service")

        # Attempt to grab the banner
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)  # Increased timeout for slower responses
        sock.connect((target, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()

        # Combine the service name with the banner details
        version = banner.strip() if banner else "No banner detected"
        return service, version
    except socket.timeout:
        return service, "Connection Timed Out"
    except socket.error:
        return service, "Unknown Version"

@login_required
def port_scan(request):
    if request.method == 'POST':
        target = request.POST.get('target')
        open_ports = []

        # Validate IP or domain
        try:
            socket.gethostbyname(target)
        except socket.error:
            return render(request, 'scanner/port_scan_results.html', {'error': "Invalid IP or Domain"})

        start_time = time.time()
        threads = []

        # Scan ports
        for port in range(1, 1025):
            thread = threading.Thread(target=scan_port, args=(target, port, open_ports))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        for result in open_ports:
            PortScanResult.objects.create(
                user=request.user,
                target=target,
                port=result['port'],
                state=result['state'],
                service=result['service'],
                version=result['version']
            )

        end_time = time.time()
        scan_duration = end_time - start_time

        return render(request, 'scanner/port_scan_results.html', {
            'target': target,
            'open_ports': open_ports,
            'scan_duration': scan_duration
        })

    # Render an empty form for GET requests
    return render(request, 'scanner/port_scan_results.html')



@login_required
def user_profile(request):
    recent_ports = PortScanResult.objects.filter(user=request.user).order_by('-id')[:10]
    recent_malware = MalwareScanResult.objects.filter(user=request.user).order_by('-id')[:10]
    return render(request, 'scanner/profile.html', {
        'recent_ports': recent_ports,
        'recent_malware': recent_malware
    })




METADEFENDER_API_KEY = "405f27497c4e276c9104b0aba1f43e94" 
METADEFENDER_BASE_URL = "https://api.metadefender.com/v4/file"

@login_required
def malware_analysis(request):
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['file']
            file_name = uploaded_file.name
            file_hash = hashlib.sha256(uploaded_file.read()).hexdigest()
            uploaded_file.seek(0)  # Reset file pointer after hashing

            # Step 1: Upload file to Metadefender
            headers = {'apikey': METADEFENDER_API_KEY}
            try:
                response = requests.post(
                    METADEFENDER_BASE_URL,
                    headers=headers,
                    files={'file': uploaded_file}
                )
                if response.status_code == 200:
                    data_id = response.json().get('data_id')
                    result_url = f"{METADEFENDER_BASE_URL}/{data_id}"

                    # Step 2: Poll for the scan result using data_id
                    for attempt in range(10):  # Polling 10 times with a delay
                        result_response = requests.get(result_url, headers=headers)
                        if result_response.status_code == 200:
                            result_data = result_response.json()
                            progress = result_data.get('scan_results', {}).get('progress_percentage')

                            if progress == 100:  # Scan complete
                                # Save result to the database
                                MalwareScanResult.objects.create(
                                    user=request.user,
                                    file_name=file_name,
                                    file_hash=file_hash,
                                    scan_results=result_data,
                                )
                                return render(request, 'scanner/malware_results.html', {'results': result_data})

                        time.sleep(5)  # Wait 5 seconds before polling again

                    # If scan did not complete in time
                    return render(request, 'scanner/malware_analysis.html', {
                        'form': form,
                        'error': "Scan is taking too long. Please try again later."
                    })

                else:
                    return render(request, 'scanner/malware_analysis.html', {
                        'form': form,
                        'error': "Failed to upload the file. Please try again."
                    })

            except requests.RequestException as e:
                return render(request, 'scanner/malware_analysis.html', {
                    'form': form,
                    'error': f"Network error occurred: {str(e)}"
                })

    else:
        form = FileUploadForm()

    return render(request, 'scanner/malware_analysis.html', {'form': form})

import requests
import time
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.conf import settings

# Access the API key securely from settings.py
VIRUS_TOTAL_API_KEY = "9ea9d8ec673a2b8b99e21b2d2ea9232633dc069090668dba1405c2501a03676d"
VIRUS_TOTAL_URL = "https://www.virustotal.com/api/v3/urls/"

@login_required
def phishing_detection(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        encoded_url = encode_url(url)  # URL must be base64 encoded for VirusTotal

        headers = {
            'x-apikey': VIRUS_TOTAL_API_KEY  # Use the API key here
        }

        # Step 1: Send request to VirusTotal to check URL
        try:
            response = requests.get(f"{VIRUS_TOTAL_URL}{encoded_url}", headers=headers)
            if response.status_code == 200:
                data = response.json()

                # Step 2: Extract relevant information from response
                last_analysis_stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = last_analysis_stats.get('malicious', 0)

                # Step 3: Display results
                if malicious > 0:
                    return render(request, 'scanner/phishing_results.html', {
                        'url': url,
                        'is_phishing': True,
                        'reason': f"Malicious URL detected with {malicious} detections."
                    })
                else:
                    return render(request, 'scanner/phishing_results.html', {
                        'url': url,
                        'is_phishing': False,
                        'reason': "The URL is safe and not flagged for phishing."
                    })
            else:
                return render(request, 'scanner/phishing_detection.html', {
                    'error': f"Failed to fetch results from VirusTotal: {response.status_code}"
                })
        except requests.exceptions.RequestException as e:
            return render(request, 'scanner/phishing_detection.html', {
                'error': f"An error occurred while contacting VirusTotal: {str(e)}"
            })

    return render(request, 'scanner/phishing_detection.html')

# Utility function to encode URL to base64 (required by VirusTotal API)
def encode_url(url):
    import base64
    return base64.urlsafe_b64encode(url.encode('utf-8')).decode('utf-8').strip("=")


def logout_view(request):
    logout(request)
    return redirect('login')