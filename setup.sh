#!/bin/sh

read -p 'Token: ' domeneshop_token
read -p 'Secret: ' domeneshop_secret

sed "s/{TOKEN}/$domeneshop_token/g"
sed "s/{SECRET}/$domeneshop_secret/g"


pip install dnspython 
pip install termcolor
pip install requests
pip install domeneshop

systemctl stop dip.service
systemctl disable dip.service

rm /etc/systemd/system/dip.service

systemctl daemon-reload

sleep 10s

mkdir --parents /usr/local/dips/
mv ./dips.py /usr/local/dips/dips.py

cat > /etc/systemd/system/dip.service <<EOL
[Unit]
Description=Dynamic IP Service
After=multi-user.target

[Service]
Type=simple
Restart=always
ExecStart=/usr/bin/python3 -u /usr/local/dips/dips.py
Environment=PYTHONUNBUFFERED=1


[Install]
WantedBy=multi-user.target
EOL


chmod 700 /usr/local/dips/dips.py
chmod +x /usr/local/dips/dips.py
chown root:root /usr/local/dips/dips.py


systemctl daemon-reload

systemctl enable dip.service
systemctl start dip.service

systemctl status dip.service

