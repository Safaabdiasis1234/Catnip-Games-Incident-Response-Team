# Set Up 
1. Download given OVA files (one containing The Hive & Cortex, one containing MISP)
2. Log into the Ubunutu machines 
-> student, Student1
3. In terminal:
```
cd docker/prod1-thehive
sudo docker compose up -d
```
4. To navigate to The Hive, go to browser and search https://localhost:443
5. Connect Cortex & MISP
-> Test server connection
-> Update the server URLs for Cortex and MISP under 'Connectors' in thehive
6. When exiting, make sure to decompose the docker:
```
sudo docker compose down
```
