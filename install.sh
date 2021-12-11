#!/bin/sh

sudo apt install -y python3-pip

read -p 'Token: ' domeneshop_token
read -p 'Secret: ' domeneshop_secret



sed -i "s/{TOKEN}/$domeneshop_token/g" service.py
sed -i "s/{SECRET}/$domeneshop_secret/g" service.py

referenceAbsPath="/usr/local/dipdup/reference.json"
sed -i "s^reference.json^$referenceAbsPath^g" service.py


pip install dnspython 
pip install termcolor
pip install requests
pip install domeneshop

systemctl stop dipdup.service
systemctl disable dipdup.service

rm /etc/systemd/system/dipdup.service

systemctl daemon-reload

sleep 10s

mkdir --parents /usr/local/dipdup/
cp ./service.py /usr/local/dipdup/service.py
cp ./reference.json /usr/local/dipdup/reference.json

cat > /etc/systemd/system/dipdup.service <<EOL
[Unit]
Description=Dynamic IP Service - Dns Updater

[Service]
Type=simple
Restart=always
ExecStart=/usr/bin/python3 -u /usr/local/dipdup/service.py
Environment=PYTHONUNBUFFERED=1


[Install]
WantedBy=multi-user.target
EOL


chmod 700 /usr/local/dipdup/service.py
chmod +x /usr/local/dipdup/service.py
chown root:root /usr/local/dipdup/service.py


systemctl daemon-reload

systemctl enable dipdup.service
systemctl start dipdup.service

systemctl status dipdup.service

