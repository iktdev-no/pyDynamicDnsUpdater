#!/bin/bash

package_name="pyDynamicDnsUpdater"
install_location="/usr/local/dynamic-dns-updater"
service_name="dynamic-dns-updater.service"

declare -A interface_config
declare -A interface_domains

prerequisites() {

    sudo apt install -y python3-pip python3-venv
    mkdir --parents /usr/local/dynamic-dns-updater/
    sudo chmod -R 0777 /usr/local/dynamic-dns-updater/

    if [ ! -d "$install_location/venv" -o ! -f "$install_location/venv/bin/activate" ]; then
        rm -r "$install_location/venv"
        python3 -m venv "$install_location/venv"
    fi

    source "$install_location/venv/bin/activate"

    echo "Installing dependencies"
    # Sjekk om pakken er installert
    if python -c "import $package_name" &> /dev/null; then
        # Lagre gjeldende versjon
        current_version=$(pip show $package_name | grep Version | awk '{print $2}')
        echo "Gjeldende versjon av $package_name er $current_version"
    else
        echo "$package_name er ikke installert."
    fi

    # Installer eller oppdater pakken
    pip install $package_name -U

    # Sjekk om installasjonen var vellykket
    if [ $? -eq 0 ]; then
        # Sjekk om versjonsnummeret har endret seg
        new_version=$(pip show $package_name | grep Version | awk '{print $2}')
        if [ "$current_version" != "$new_version" ]; then
            echo "$package_name ble oppdatert fra versjon $current_version til $new_version."
        else
            echo "$package_name var allerede på den nyeste versjonen $new_version."
        fi
    else
        echo "Feil under installasjon eller oppdatering av $package_name. Avbryter."
        exit 1
    fi
    deactivate
}


recordAuthentication() {
    token=$(whiptail --inputbox "Token:" 10 60 --title "Autentiserings token" 3>&1 1>&2 2>&3)
    secret=$(whiptail --inputbox "Secret:" 10 60 --title "Autentiserings token" 3>&1 1>&2 2>&3)

    json=$(jq -n --arg token "$token" --arg secret "$secret" '{token: $token, secret: $secret}')
    echo $json > "$install_location/auth.json"
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
        iface_list+=("$iface" "$ip_addresses" OFF)
    done

    local selected_adapters=""
    while true; do
        # Bruk whiptail for å vise en dialog med interfaces
        selected_adapters=$(whiptail --title "Select Network Interface" --checklist "Choose interfaces:" 20 100 10 "${iface_list[@]}" 3>&1 1>&2 2>&3)
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
    "IPv6" "Aktiver IPv6" OFF 3>&1 1>&2 2>&3)

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
            *) echo "User aborted.. Exiting.."
                exit 1 
            ;;
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
        echo "Ingen domener å fjerne"
        whiptail --msgbox "Ingen domener å fjerne." 10 60
    else
        display_list=()
        for domain in "${domains[@]}"; do
            # Lagre interface med IP-er som beskrivelse
            display_list+=("$domain" " " OFF)
        done

        # Bruker whiptail for å velge domener å fjerne
        remove_domains=$(whiptail --title "Fjern domene" --checklist "Velg domenene du vil fjerne for $iface:" 15 60 6 "${display_list[@]}" 3>&1 1>&2 2>&3)

        if [ -n "$remove_domains" ]; then
            # Fjern valgte domener fra arrayen
            for domain in $remove_domains; do
                domain=$(echo "$domain" | sed 's/"//g')  # Fjern anførselstegn
                for i in "${!domains[@]}"; do
                    if [ "${domains[i]}" = "$domain" ]; then
                        unset 'domains[i]'  # Fjern elementet
                    fi
                done
            done
            # Fjern tomme elementer fra arrayen
            domains=("${domains[@]}")
        fi
    fi
}

# Funksjon for å redigere et domene
edit_domain() {
    if [ ${#domains[@]} -eq 0 ]; then
        echo "Ingen domener å redigere"
        whiptail --msgbox "Ingen domener å redigere." 10 60
    else
        display_list=()
        for domain in "${domains[@]}"; do
            # Lagre interface med IP-er som beskrivelse
            display_list+=("$domain" " ")
        done

        selected_domain=$(whiptail --title "Rediger domene" --menu  "Velg et domene å redigere for $iface:" 15 60 6 "${display_list[@]}" 3>&1 1>&2 2>&3)

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

createReference() {
    local json_output="{"

    # Iterer over de valgte adapterne
    for iface in $selected_adapters; do
        # Fjern eventuelle parenteser fra interface-navnet
        iface=$(echo "$iface" | awk -F'(' '{print $1}' )
        
        clean_iface=$(echo "$iface" | tr -d '"')

        # Legg til interface i JSON-strukturen
        json_output+="\"$clean_iface\": {"
        
        # Legg til IPv4 og IPv6 konfigurasjoner
        json_output+="\"ipv4\": ${interface_config["$iface,ipv4"]},"
        json_output+="\"ipv6\": ${interface_config["$iface,ipv6"]},"
        
        # Legg til domener
        json_output+="\"domains\": ["
        domains=${interface_domains[$iface]}
        
        # Split domener basert på komma og legg til i JSON
        IFS=', ' read -ra domain_array <<< "$domains"
        for domain in "${domain_array[@]}"; do
            json_output+="\"$domain\","
        done
        
        # Fjern siste komma
        json_output=$(echo "$json_output" | sed 's/,$//')
        
        # Lukk domains array og interface object
        json_output+="]},"
    done

    # Fjern siste komma og lukk JSON-strukturen
    json_output=$(echo "$json_output" | sed 's/,$//')
    json_output+="}"

    # Returner JSON-strukturen
    echo "$json_output"
}

recordReference() {
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
    json_output=$(createReference)

    echo $json_output > "$install_location/reference.json"


}


create_services() {
    systemctl stop $service_name
    systemctl disable $service_name

    rm "/etc/systemd/system/$service_name"
    systemctl daemon-reload

    echo "Creating Dynamic Dns Updater Runner" 

    cat > "$install_location/service.py" <<EOL
from DynamicDnsUpdater import DynamicDnsUpdater
reference = "reference.json"
auth = "auth.json"
service = DynamicDnsUpdater(reference, auth)
service.start()
EOL


    sed -i "s^reference.json^$install_location/reference.json^g" "$install_location/service.py"
    sed -i "s^auth.json^$install_location/auth.json^g" "$install_location/service.py"

    echo "Creating DDNSUHook"

    echo '
#! /bin/bash

# Dynamic Dns Updater Hook (DDNSHook)
# A component of DynamicDnsUpdater
# 
# The purpose of DDNSHook is to be notified by the system when there are changes to net network interface
# If this script is placed correctly inside a hook folder for the network manager, 
# the network manager will call up this script whith the interface that has been updated or altered
#
# This script will then proceed to update a temporary file which the service DDNS will watch and respond to
#

IFACE = $1
STATUS = $2


echo "DDNS - DynamicIpWatcherAction: Registered change to network adpater $IFACE"

if [ ! -z $IFACE ]; then
    echo -e "$IFACE\n" >> /tmp/ddns-hook
fi
' | tee /etc/networkd-dispatcher/routable.d/ddns-hook.sh > /usr/lib/networkd-dispatcher/routable.d/ddns-hook.sh > /etc/NetworkManager/dispacher.d/ddns-hook.sh 


    echo "Creating DDNSU Service"
    cat > "/etc/systemd/system/$service_name" <<EOL
[Unit]
Description=Dynamic Dns Updater

[Service]
Type=simple
Restart=always
ExecStart=/usr/local/dynamic-dns-updater/venv/bin/python -u /usr/local/dynamic-dns-updater/service.py
Environment=PYTHONUNBUFFERED=1


[Install]
WantedBy=multi-user.target
EOL
    CHMOD_FILES=(
    "/etc/networkd-dispatcher/routable.d/ddns-hook.sh"
    "/usr/lib/networkd-dispatcher/routable.d/ddns-hook.sh"
    "/etc/NetworkManager/dispacher.d/ddns-hook.sh"
    "$install_location/service.py"
    )

    for FILE in "${CHMOD_FILES[@]}"; do
        chmod 755 $FILE
        chmod +x $FILE
    done

    chown root:root "$install_location/service.py"

    systemctl daemon-reload

    systemctl enable $service_name
    systemctl start $service_name

    systemctl status $service_name

    journalctl -exfu $service_name
    sudo chmod -R 755 "$install_location"

}

setup() {
    prerequisites

    if [ -f "$install_location/auth.json" ]; then
        if whiptail --title "Eksisterende autentisering" --yesno "Vil du oppdatere autentiseringen?" 10 60; then
            recordAuthentication
        else
            echo "Bruker eksisterende autentisering."
        fi
    else
        recordAuthentication        
    fi


    if [ -f "$install_location/reference.json" ]; then
        if whiptail --title "Eksisterende konfigurasjon" --yesno "Vil du oppdatere konfigurasjonen?" 10 60; then
            recordReference
        else
            echo "Bruker eksisterende reference."
        fi
    else
        recordReference
    fi

    create_services

    echo "Done!"
}


setup
