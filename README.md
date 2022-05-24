# Dynamic Ip Dns Updater
Dynamic IP - Dns Updater: Linux (systemd) service that pulls dns record and verifies that the IP on dns and IP on nic is the same

Make sure that your replace the domain and FQDN in the reference.json file as this is tied to my setup, and won't work

Token and Secret is required when you run the install.sh or setup.sh

install.sh installs the dip-dup service which is a multi-domain service.
setup.sh is a single sub-domain service.

Example of reference.json
```json
[
    {
        "interface": "wan0",
        "ipv4": true,
        "ipv6": false,
        "domains": [
            {
                "parent": "example.com",
                "FQDN": [
                    "example.com",
                    "one.example.com"
                ]
            }
        ]
    }
]
```
