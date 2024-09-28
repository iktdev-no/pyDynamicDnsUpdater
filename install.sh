#!/bin/bash

declare -A interface_config
declare -A interface_domains

prerequisites() {

    sudo apt install -y python3-pip python3-venv
    mkdir --parents /usr/local/dynamic-dns-updater/
    python3 -m venv /usr/local/dynamic-dns-updater/venv
    source /usr/local/dynamic-dns-updater/venv/bin/activate

    echo "Installing dependencies"
}


recordAuthentication() {
    token=$(whiptail --inputbox "Token:" 10 60 --title "Autentiserings token" 3>&1 1>&2 2>&3)
    secret=$(whiptail --inputbox "Secret:" 10 60 --title "Autentiserings token" 3>&1 1>&2 2>&3)

    json=$(jq -n --arg token "$token" --arg secret "$secret" '{token: $token, secret: $secret}')

}

_getSelectedInterfaces() {
    # Hent ut interfaces og deres ikke-lokale IP-adresser
    ifaces=$(ip -o addr show | awk '$3 == "inet" || $3 == "inet6" {print $2, $4}' | sed 's/\/[0-9]*//')

    # Lagre interfaces og filtrer ut lokale og private IP-er
    ifaces=$(echo "$ifaces" | while read -r iface ip_addr; do
        if [[ $ip_addr =~ ^(127\.|::1|fe80:|169\.254\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.) ]]; then
            continue
        fi
        echo "$iface ($ip_addr)"
    done)

    # Bruk sort og uniq for å få distinct interface-navn
    distinct_ifaces=$(echo "$ifaces" | awk '{print $1}' | sort -u)

    # Lagre IP-er i et array basert på distinct_ifaces
    local iface_list=()
    
    for iface in $distinct_ifaces; do
        # Finn IP-er for hvert interface
        ip_addresses=$(echo "$ifaces" | grep "^$iface" | awk -F'[()]' '{print $2}' | xargs | sed 's/ /, /g')
        
        # Lagre interface med IP-er som beskrivelse
        iface_list+=("$iface" "$ip_addresses" ON)
    done

    local selected_adapters=""
    while true; do
        # Bruk whiptail for å vise en dialog med interfaces
        selected_adapters=$(whiptail --title "Select Network Interface" --checklist "Choose interfaces:" 20 120 20 "${iface_list[@]}" 3>&1 1>&2 2>&3)
        exit_status=$?

        if [ $exit_status != 0 ]; then
            # Bruker avbrøt dialogen
            return 1
        fi

        # Sjekk om brukeren har valgt noen alternativer
        if [[ -n "$selected_adapters" ]]; then
            # Output de valgte alternativene
            echo "$selected_adapters"
            break
        else
            # Be brukeren om å velge minst ett alternativ
            whiptail --title "Error" --msgbox "Please select at least one option." 10 60
        fi
    done

    if [ -z "$selected_adapters" ]; then
        echo "No selection made, exiting..."
        return 1
    fi
}



_configureInterfaceProtocols() {
    local iface=$1
    protocol_choices=$(whiptail --title "Configure $iface" --checklist \
    "Velg hvilke protokoller som skal være aktive for $iface:" 10 60 2 \
    "IPv4" "Aktiver IPv4" ON \
    "IPv6" "Aktiver IPv6" ON 3>&1 1>&2 2>&3)

    if echo "$protocol_choices" | grep -q "IPv4"; then
        interface_config["$iface,ipv4"]=true
    else
        interface_config["$iface,ipv4"]=false
    fi

    if echo "$protocol_choices" | grep -q "IPv6"; then
        interface_config["$iface,ipv6"]=true
    else
        interface_config["$iface,ipv6"]=false
    fi
}

# Funksjon for å håndtere domener for et interface
manage_domains() {
    local iface=$1
    domains=()

    while true; do
        domain_menu=$(whiptail --title "Domener for $iface" --menu \
        "Velg handling for domenene til $iface" 15 60 4 \
        "1" "Legg til domene" \
        "2" "Fjern domene" \
        "3" "Rediger domene" \
        "4" "Ferdig" 3>&1 1>&2 2>&3)

        case $domain_menu in
            "1") add_domain ;;
            "2") remove_domain ;;
            "3") edit_domain ;;
            "4") break ;;
        esac
    done

    # Lagre domenene for interfacet som en kommaseparert streng
    interface_domains["$iface"]=$(IFS=,; echo "${domains[*]}")
}

# Funksjon for å legge til et nytt domene
add_domain() {
    new_domain=$(whiptail --inputbox "Legg til et nytt domene for $iface:" 10 60 "" 3>&1 1>&2 2>&3)
    domains+=("$new_domain")
}

# Funksjon for å fjerne domener
remove_domain() {
    if [ ${#domains[@]} -eq 0 ]; then
        whiptail --msgbox "Ingen domener å fjerne." 10 60
    else
        remove_domains=$(whiptail --title "Fjern domene" --checklist \
        "Velg domenene du vil fjerne for $iface:" 15 60 6 \
        $(for domain in "${domains[@]}"; do echo "$domain" ""; done) 3>&1 1>&2 2>&3)
        
        for domain in $remove_domains; do
            domain=$(echo "$domain" | sed 's/"//g')
            domains=("${domains[@]/$domain}")
        done
    fi
}

# Funksjon for å redigere et domene
edit_domain() {
    if [ ${#domains[@]} -eq 0 ]; then
        whiptail --msgbox "Ingen domener å redigere." 10 60
    else
        selected_domain=$(whiptail --title "Rediger domene" --menu \
        "Velg et domene å redigere for $iface:" 15 60 6 \
        $(for domain in "${domains[@]}"; do echo "$domain" ""; done) 3>&1 1>&2 2>&3)

        selected_domain=$(echo "$selected_domain" | sed 's/"//g')
        edited_domain=$(whiptail --inputbox "Rediger domene $selected_domain for $iface:" 10 60 "$selected_domain" 3>&1 1>&2 2>&3)

        # Oppdater det redigerte domenet
        for i in "${!domains[@]}"; do
            if [ "${domains[$i]}" == "$selected_domain" ]; then
                domains[$i]=$edited_domain
            fi
        done
    fi
}

# Funksjon for å oppsummere konfigurasjonen
summarize_configuration() {
    echo "Konfigurasjon av valgte interfaces:"
    for iface in $selected_adapters; do
        iface=$(echo "$iface" | awk -F'(' '{print $1}')
        echo "Interface: $iface"
        echo "  IPv4 aktiv: ${interface_config["$iface,ipv4"]}"
        echo "  IPv6 aktiv: ${interface_config["$iface,ipv6"]}"
        echo "  Domener: ${interface_domains[$iface]}"
    done
}


setup() {
    if [ -f "./auth.json" ]; then
        if whiptail --title "Eksisterende autentisering" --yesno "Vil du oppdatere autentiseringen?" 10 60; then
            recordAuthentication
        else
            echo "Bruker eksisterende autentisering."
        fi
    else
        recordAuthentication        
    fi


    if [ -f "./reference.json" ]; then
        echo "Using existing reference.json"
    else
        selected_adapters=$(_getSelectedInterfaces)
        
        # Check if the selection was successful
        if [ $? -ne 0 ]; then
            echo "No interfaces selected or user cancelled."
            exit 1
        fi


        for iface in $selected_adapters; do
            # Fjern eventuell parentes og IP-adresse fra valgte adaptere
            iface=$(echo "$iface" | awk -F'(' '{print $1}')
            _configureInterfaceProtocols "$iface"
        done

        # Spør om domener for hvert interface
        for iface in $selected_adapters; do
            iface=$(echo "$iface" | awk -F'(' '{print $1}')
            manage_domains "$iface"
        done
        summarize_configuration
    fi
}


setup











# sudo apt install -y python3-pip
# 
# read -p 'Token: ' domeneshop_token
# read -p 'Secret: ' domeneshop_secret
# 
# 
# 
# pip install dnspython -U
# pip install termcolor -U
# pip install domeneshop
# 
# systemctl stop dipdup.service
# systemctl disable dipdup.service
# 
# rm /etc/systemd/system/dipdup.service
# 
# systemctl daemon-reload
# 
# sleep 10s
# 
# mkdir --parents /usr/local/dipdup/
# cp ./service.py /usr/local/dipdup/service.py
# cp ./reference.json /usr/local/dipdup/reference.json
# 
# 
# sed -i "s/{TOKEN}/$domeneshop_token/g" /usr/local/dipdup/service.py
# sed -i "s/{SECRET}/$domeneshop_secret/g" /usr/local/dipdup/service.py
# 
# referenceAbsPath="/usr/local/dipdup/reference.json"
# sed -i "s^reference.json^$referenceAbsPath^g" /usr/local/dipdup/service.py
# 
# 
# cat > /etc/systemd/system/dipdup.service <<EOL
# [Unit]
# Description=Dynamic IP Service - Dns Updater
# 
# [Service]
# Type=simple
# Restart=always
# ExecStart=/usr/bin/python3 -u /usr/local/dipdup/service.py
# Environment=PYTHONUNBUFFERED=1
# 
# 
# [Install]
# WantedBy=multi-user.target
# EOL
# 
# 
# chmod 700 /usr/local/dipdup/service.py
# chmod +x /usr/local/dipdup/service.py
# chown root:root /usr/local/dipdup/service.py
# 
# 
# systemctl daemon-reload
# 
# systemctl enable dipdup.service
# systemctl start dipdup.service
# 
# systemctl status dipdup.service
# 
# 