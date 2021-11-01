import requests, json, hashlib, sys
from datetime import date, timedelta

today = date.today()
start = today - timedelta(days=today.weekday())
end = start + timedelta(hours=12)
today = str(today)
start = str(start)
end   = str(end)

url = "https://api.appc.cisco.com/v1/token"
client_id = "3f998ccf0c34be2bb9ec0649dda5c8eeec7ba977e5dc2affe3e86d52a1f290c62"
client_secret = "b2951daaf2cc444497d686b33b726b8ad1b904034dbbb6c04e54f19e31a96f81f"

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

headers = {
    "Accept": "application/json",
    "Authorization": auth
}

response_auth = requests.request("GET", url, headers=headers, params=querystring_auth)

print(response_auth.text)
f1= open('auth.log', 'a')
print(today,response_auth.text, file=f1)
f1.close()




#import pysftp
#import sys

#path = './THETARGETDIRECTORY/' + sys.argv[1]    #hard-coded
#localpath = sys.argv[1]

#host = "THEHOST.com"                    #hard-coded
#password = "THEPASSWORD"                #hard-coded
#username = "THEUSERNAME"                #hard-coded

#with pysftp.Connection(host, username=username, password=password) as sftp:
#    sftp.put(localpath, path)

#print 'Upload done.'
