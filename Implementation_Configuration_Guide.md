# Set Up 
1. Request a community license from TheHive
2. Download the OVA file, log into machine 
-> student, Student1
3. On host machine (Powershell):
```
ssh analyst@192.168.56.200
```
*password: analyst

Taken from docker-compose.yml:
```
#   Run this after boot: sudo chmod 777 /tmp/cortex-jobs
#   To restart manually: cd catnip-sco && sudo docker compose up -d
#   To check status: sudo docker compose ps
#   To view logs: sudo docker compose logs -f
```
To navigate to TheHive: http:192.168.56.20:9000
Login Credentials: analyst@catnip.local, password: analyst
