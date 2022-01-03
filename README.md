
## Requirement
#### - python3.9
#### - pip
#### - pip install requests
#### - pip install pysftp
#### - pip install paramiko

## Changes Required in script
#### - In windows/scrript.py file at line number 15 and 16 change the tokens
#### - In windows/scrript.py file at line number 57,64,71,78,85,93,101,109,118,126,134,152 chnage the location to save dmp logs
#### - In windows/scrript.py file at line number 152 change the location to save appc logs

## Windows
#### - Create scheduler and provide the windows/bat file to execute
#### - Follow the link to create a scheduler : https://www.ibm.com/docs/en/datacap/9.1.6?topic=application-configuring-windows-task-scheduler-automatically-run-ruleset

## Linux Linux
#### - Create a cron entry and add windows/scrript.py
#### - Cron entry follow this link : https://www.geeksforgeeks.org/crontab-in-linux-with-examples/
