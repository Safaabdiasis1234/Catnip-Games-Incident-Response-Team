# Set Up 
1. Request a community license from TheHive
2. Download the OVA file, log into machine 
-> student, Student1
3. On host machine (Powershell):
```
ssh analyst@192.168.56.200
```
*password: analyst

File Structure:
- docker-compose.yml
- analysers/
- - GameThreat_1_0/
  - README.md
- cortex/
- - application.conf
  - logs/
- scripts/
- - add_tasks.py
  - automation.code.py
  - generate_cases.py
  - requirements.txt
  - tag_based_ttps.py

Taken from docker-compose.yml:
```
#   Run this after boot: sudo chmod 777 /tmp/cortex-jobs
#   To restart manually: cd catnip-sco && sudo docker compose up -d
#   To check status: sudo docker compose ps
#   To view logs: sudo docker compose logs -f
```
