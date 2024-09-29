# Dynamic Ip Dns Updater
Dynamic IP - Dns Updater: Linux (systemd) service that pulls dns record and verifies that the IP on dns and IP on nic is the same

Make sure that your replace the domain and FQDN in the reference.json file as this is tied to my setup, and won't work

Token and Secret is required when you run the install.sh
# How to install

## Dependencies
```shell
net-tools
```


To install and start DRU
- Clone the project 
- Modify reference.json
 - `./install.sh` 

</br>
Make sure that you run the script with sudo or as root, as the script needs access. <br>

Or you can do the following:
```shell
curl -sSL -o install.sh https://raw.githubusercontent.com/iktdev-no/pyDynamicDnsUpdater/master/install.sh && sudo bash install.sh
```
This will request you to define table name and select interface thrould selection.


<br>