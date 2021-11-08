import requests, json, hashlib, sys
import paramiko
import pysftp
import os
from datetime import date, timedelta

today = date.today()
start = today - timedelta(days=today.weekday())
end = start + timedelta(days=1)
today = str(today)
start = str(start)
end   = str(end)

url = "https://api.appc.cisco.com/v1/token"
client_id = "3f998ccf0c34be2b9ec0649dda5c8eeec7ba977e5dc2affe3e86d52a1f290c62"
client_secret = "b2951daaf2cc44497d686b33b726b8ad1b904034dbbb6c04e54f19e31a96f81f"

payload = "client_id=" + str(client_id) +"&""client_secret=" +str(client_secret)
headers = {
    "Accept": "application/json",
    "Content-Type": "application/x-www-form-urlencoded"
}

response = requests.request("POST", url, data=payload, headers=headers)

r = json.loads(response.text.encode('utf8'))

result_tokentype = (r['token_type'])
result_accesstoken = (r['access_token'])

auth = str(result_tokentype) + " " + str(result_accesstoken)


#Generating API Logs.

url = "https://api.dmp.cisco.com/v1/alert_events"

querystring_auth = {"start_date": start,"end_date":end,"alert_types":"authentication_spike"}
querystring_brand = {"start_date": start,"end_date":end,"alert_types":"brand_spoofing"}
querystring_dkim = {"start_date": start,"end_date":end,"alert_types":"dkim_record_changed"}
querystring_dmarc = {"start_date": start,"end_date":end,"alert_types":"dmarc_record_changed"}
querystring_infra = {"start_date": start,"end_date":end,"alert_types":"infrastructure"}
querystring_new = {"start_date": start,"end_date":end,"alert_types":"new_dkim_selector"}
querystring_sender = {"start_date": start,"end_date":end,"alert_types":"new_sender"}
querystring_new_well = {"start_date": start,"end_date":end,"alert_types":"new_well_known_sender"}
querystring_spf = {"start_date": start,"end_date":end,"alert_types":"spf_record_changed"}
querystring_threat = {"start_date": start,"end_date":end,"alert_types":"threat_spike"}
querystring_unauthorized = {"start_date": start,"end_date":end,"alert_types":"unauthorized_netblock"}

headers = {
    "Accept": "application/json",
    "Authorization": auth
}

response_auth = requests.request("GET", url, headers=headers, params=querystring_auth)

f1= open('dmp/auth.log', 'a')
#print(today,response_auth.text, file=f1)
print(response_auth.text, file=f1)
f1.close()

response_dkim = requests.request("GET", url, headers=headers, params=querystring_dkim)

f2= open('dmp/dkim.log', 'a')
#print(today,response_auth.text, file=f1)
print(response_dkim.text, file=f2)
f2.close()

response_brand = requests.request("GET", url, headers=headers, params=querystring_brand)

f3= open('dmp/brand.log', 'a')
#print(today,response_auth.text, file=f1)
print(response_brand.text, file=f3)
f3.close()

response_dmarc = requests.request("GET", url, headers=headers, params=querystring_dmarc)

f4= open('dmp/dmarc.log', 'a')
#print(today,response_auth.text, file=f1)
print(response_dmarc.text, file=f4)
f4.close()

response_infra = requests.request("GET", url, headers=headers, params=querystring_infra)

f5= open('dmp/infra.log', 'a')
#print(today,response_auth.text, file=f1)
print(response_infra.text, file=f5)
f5.close()

response_new = requests.request("GET", url, headers=headers, params=querystring_new)


f6= open('dmp/new.log', 'a')
#print(today,response_auth.text, file=f1)
print(response_new.text, file=f6)
f6.close()

response_sender = requests.request("GET", url, headers=headers, params=querystring_sender)


f7= open('dmp/sender.log', 'a')
#print(today,response_auth.text, file=f1)
print(response_sender.text, file=f7)
f7.close()

response_new_well = requests.request("GET", url, headers=headers, params=querystring_new_well)


f8= open('dmp/new_well.log', 'a')
#print(today,response_auth.text, file=f1)
print(response_new_well.text, file=f8)
f8.close()


response_spf = requests.request("GET", url, headers=headers, params=querystring_spf)


f9= open('dmp/spf.log', 'a')
#print(today,response_auth.text, file=f1)
print(response_spf.text, file=f9)
f9.close()

response_threat = requests.request("GET", url, headers=headers, params=querystring_threat)


f10= open('dmp/threat.log', 'a')
#print(today,response_auth.text, file=f1)
print(response_threat.text, file=f10)
f10.close()

response_unauthorized = requests.request("GET", url, headers=headers, params=querystring_unauthorized)


f11= open('dmp/unauthorized.log', 'a')
#print(today,response_auth.text, file=f1)
print(response_unauthorized.text, file=f11)
f11.close()



url = "https://api.appc.cisco.com/v1/messages"

querystring = {"start_date":start,"end_date":end}

headers = {
    "Accept": "application/json",
    "Authorization": auth
}

response = requests.request("GET", url, headers=headers, params=querystring)

f12=open('appc/appc.log', 'a')
print(response.text, file=f12)
f12.close()

HOST = "192.168.181.247"
USERNAME = "root"
PASSWORD = "root123"
source_path = '/home/deathranger/Documents/beginner/dmp/'
target_path = '/opt/sftp/logs/dmp/'

class MySFTPClient(paramiko.SFTPClient):
    def put_dir(self, source, target):
        ''' Uploads the contents of the source directory to the target path. The
            target directory needs to exists. All subdirectories in source are 
            created under target.
        '''
        for item in os.listdir(source):
            if os.path.isfile(os.path.join(source, item)):
                self.put(os.path.join(source, item), '%s/%s' % (target, item))
            else:
                self.mkdir('%s/%s' % (target, item), ignore_existing=True)
                self.put_dir(os.path.join(source, item), '%s/%s' % (target, item))

    def mkdir(self, path, mode=511, ignore_existing=False):
        ''' Augments mkdir by adding an option to not fail if the folder exists  '''
        try:
            super(MySFTPClient, self).mkdir(path, mode)
        except IOError:
            if ignore_existing:
                pass
            else: 
                raise
        
transport = paramiko.Transport((HOST))
transport.connect(username=USERNAME, password=PASSWORD)
sftp = MySFTPClient.from_transport(transport)
sftp.mkdir(target_path, ignore_existing=True)
sftp.put_dir(source_path, target_path)
sftp.close()

source_path = '/home/deathranger/Documents/beginner/appc/'
target_path = '/opt/sftp/logs/appc/'

class MySFTPClient(paramiko.SFTPClient):
    def put_dir(self, source, target):
        ''' Uploads the contents of the source directory to the target path. The
            target directory needs to exists. All subdirectories in source are 
            created under target.
        '''
        for item in os.listdir(source):
            if os.path.isfile(os.path.join(source, item)):
                self.put(os.path.join(source, item), '%s/%s' % (target, item))
            else:
                self.mkdir('%s/%s' % (target, item), ignore_existing=True)
                self.put_dir(os.path.join(source, item), '%s/%s' % (target, item))

    def mkdir(self, path, mode=511, ignore_existing=False):
        ''' Augments mkdir by adding an option to not fail if the folder exists  '''
        try:
            super(MySFTPClient, self).mkdir(path, mode)
        except IOError:
            if ignore_existing:
                pass
            else: 
                raise
        
transport = paramiko.Transport((HOST))
transport.connect(username=USERNAME, password=PASSWORD)
sftp = MySFTPClient.from_transport(transport)
sftp.mkdir(target_path, ignore_existing=True)
sftp.put_dir(source_path, target_path)
sftp.close()

