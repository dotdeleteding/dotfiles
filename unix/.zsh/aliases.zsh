############################# PACKAGE #############################
not_support="[!] Sorry, your system is not supported."
wrong_input="[!] Wrong input, try again!"
if [[ -n $(uname -mrs | grep -w Microsoft | sed "s/.*\-//" | awk "{print $1}") ]]; then
    system="windows"
else
    system="linux"
fi

if [ -d "/data/data/com.termux/files/usr" ]; then
    pm="pkg"
    system="termux"
else
    for package in pacman apk zypper xbps-install pkg yum dnf apt; do
        if which $package >/dev/null; then
            pm=$package
        else
            pm="not included"
        fi
    done
fi

function install() {
    if [[ $system == "termux" ]]; then
        $pm install $*
    else
        if [[ $pm == "apt" || $pm == "dnf" || $pm == "yum" || $pm == "pkg" ]]; then
            sudo $pm install $*
        elif [[ $pm == "pacman" || $pm == "xbps-install" ]]; then
            sudo $pm -S $*
        elif [[ $pm == "apk" ]]; then
            sudo $pm add $*
        else
            echo $not_support
            return 1
        fi
    fi
}

function update() {
    if [[ $system == "termux" ]]; then
        $pm update
    else
        if [[ $pm == "apt" || $pm == "apk" || $pm == "pkg" ]]; then
            sudo $pm update
        elif [[ $pm == "pacman" ]]; then
            sudo $pm -Sy
        elif [[ $pm == "xbps-install" ]]; then
            sudo $pm -S
        elif [[ $pm == "zypper" ]]; then
            sudo $pm refresh
        elif [[ $pm == "dnf" || $pm == "yum" ]]; then
            sudo $pm check-update
        else
            echo $not_support
            return 1
        fi
    fi
}

function upgrade() {
    if [[ $system == "termux" ]]; then
        $pm upgrade
    else
        if [[ $pm == "pacman" ]]; then
            sudo $pm -Syu
        elif [[ $pm == "xbps-install" ]]; then
            sudo $pm -Su
        elif [[ $pm == "zypper" || $pm == "dnf" || $pm == "yum" ]]; then
            sudo $pm update
        elif [[ $pm == "apt" || $pm == "pkg" ]]; then
            sudo $pm upgrade
        else
            echo $not_support
            return 1
        fi
    fi
}

function remove() {
    if [[ $system == "termux" ]]; then
        $pm uninstall $*
    else
        if [[ $pm == "pkg" ]]; then
            sudo $pm remove $*
        elif [[ $pm == "apt" || $pm == "zypper" || $pm == "dnf" || $pm == "yum" ]]; then
            sudo $pm remove $*
        elif [[ $pm == "pacman" ]]; then
            sudo $pm -R $*
        elif [[ $pm == "xbps-install" ]]; then
            sudo xbps-remove -R $*
        elif [[ $pm == "apk" ]]; then
            sudo $pm del $*
        else
            echo $not_support
            return 1
        fi
    fi
}

function search() {
    if [[ $system == "termux" ]]; then
        $pm search $*
    else
        if [[ $pm == "apt" || $pm == "zypper" || $pm == "apk" || $pm == "pkg" || $pm == "dnf" || $pm == "yum" ]]; then
            $pm search $*
        elif [[ $pm == "xbps-install" ]]; then
            xbps-query -Rs $*
        elif [[ $pm == "pacman" ]]; then
            $pm -Ss $*
        else
            echo $not_support
            return 1
        fi
    fi
}

function orphan() {
    if [[ $system == "termux" ]]; then
        $pm autoremove && $pm autoclean
    else
        if [[ $pm == "apt" || $pm == "apk" || $pm == "pkg" || $pm == "dnf" || $pm == "yum" ]]; then
            sudo $pm autoremove
        elif [[ $pm == "pacman" ]]; then
            sudo $pm -Rns $(pacman -Qtdq)
        elif [[ $pm == "zypper" ]]; then
            sudo $pm remove $(rpm -qa --qf "%{NAME}\n" | grep -vx "$(rpm -qa --qf "%{INSTALLTIME}:%{NAME}\n" | sort -n | uniq -f1 | cut -d: -f2-)")
        elif [[ $pm == "xbps-install" ]]; then
            sudo xbps-remove -O
        else
            echo $not_support
            return 1
        fi
    fi
}

function reinstall() {
    if [[ $system == "termux" ]]; then
        $pm reinstall $*
    else
        if [[ $pm == "pacman" ]]; then
            sudo $pm -S --needed $*
        elif [[ $pm == "zypper" ]]; then
            sudo $pm in -f $*
        elif [[ $pm == "apk" ]]; then
            sudo $pm add --force --no-cache $*
        elif [[ $pm == "xbps-install" ]]; then
            sudo $pm -f $*
        elif [[ $pm == "yum" || $pm == "dnf" ]]; then
            sudo $pm reinstall $*
        elif [[ $pm == "pkg" ]]; then
            sudo $pm install -f $*
        elif [[ $pm == "apt" ]]; then
            sudo apt reinstall $*
        else
            echo $not_support
            return 1
        fi
    fi
}

function updateandupgrade() {
    if [[ $system == "termux" ]]; then
        $pm update && $pm upgrade
    else
        if [[ $pm == "apt" || $pm == "apk" ]]; then
            sudo $pm update && sudo $pm upgrade
        elif [[ $pm == "pacman" ]]; then
            sudo $pm -Syu
        elif [[ $pm == "zypper" || $pm == "dnf" || $pm == "yum" ]]; then
            sudo $pm update
        elif [[ $pm == "xbps-install" ]]; then
            sudo $pm -Su
        elif [[ $pm == "pkg" ]]; then
            sudo freebsd-update install
        else
            echo $not_support
            return 1
        fi
    fi
}

function detail() {
    if [[ $system == "termux" ]]; then
        $pm show $*
    else
        if [[ $pm == "apt" ]]; then
            $pm show $*
        elif [[ $pm == "pacman" ]]; then
            $pm -Si $*
        elif [[ $pm == "zypper" || $pm == "dnf" || $pm == "yum" || $pm == "pkg" ]]; then
            $pm info $*
        elif [[ $pm == "apk" ]]; then
            $pm info -a $*
        elif [[ $pm == "xbps-install" ]]; then
            xbps-query -R $*
        else
            echo $not_support
            return 1
        fi
    fi
}

function checkpkg() {
    if [[ $system == "termux" ]]; then
        echo $not_support
        return 1
    else
        if [[ $pm == "apt" ]]; then
            dpkg -C
        elif [[ $pm == "pacman" ]]; then
            $pm -Qkk
        elif [[ $pm == "zypper" || $pm == "dnf" || $pm == "yum" ]]; then
            rpm -Va
        elif [[ $pm == "apk" || $pm == "pkg" ]]; then
            $pm check
        elif [[ $pm == "xbps-install" ]]; then
            xbps-query -H check
        else
            echo $not_support
            return 1
        fi
    fi
}

function listpkg() {
    if [[ $system == "termux" ]]; then
        $pm list-installed
    else
        if [[ $pm == "apt" ]]; then
            dpkg --list
        elif [[ $pm == "pacman" ]]; then
            $pm -Q
        elif [[ $pm == "zypper" || $pm == "dnf" || $pm == "yum" ]]; then
            rpm -qa
        elif [[ $pm == "apk" ]]; then
            $pm list
        elif [[ $pm == "xbps-install" ]]; then
            xbps-query -l
        elif [[ $pm == "pkg" ]]; then
            $pm info
        else
            echo $not_support
            return 1
        fi
    fi
}

function holdpkg() {
    if [[ $system == "termux" ]]; then
        echo $not_support
        return 1
    else
        if [[ $pm == "apt" ]]; then
            sudo apt-mark hold $*
        elif [[ $pm == "pacman" ]]; then
            sudo $pm -D $*
        elif [[ $pm == "zypper" ]]; then
            sudo $pm addlock $*
        elif [[ $pm == "apk" ]]; then
            sudo $pm add --lock $*
        elif [[ $pm == "pkg" ]]; then
            sudo $pm lock $*
        else
            echo $not_support
            return 1
        fi
    fi
}

function aurs() {
    if [[ $pm != "pacman" ]]; then
        echo "Sorry, your system is not based of Arch Linux"
        return 1
    fi
    function usage() {
        echo "Usage: aurs [-i] [-d] [-r] [-u] [-U] [-s]"
        echo "  -d    Display package details"
        echo "  -i    Install package"
        echo "  -r    Remove package"
        echo "  -s    Search for package"
        echo "  -u    Update package"
        echo "  -U    Upgrade package"
    }
    while getopts ":i:d:r:s:uUh" opt; do
        case $opt in
        i) yay -S $OPTARG ;;
        d) pacman -Qm $OPTARG ;;
        r) yay -Runscd $OPTARG ;;
        u) yay -Sy ;;
        U) yay -Syu ;;
        s) yay -Ss $OPTARG ;;
        \?)
            echo "Invalid option" >&2
            usage
            ;;
        esac
    done
}
########################### END PACKAGE ###########################

############################### IPs ###############################
function myip() {
    gateways=$(ip route list match 0 table all scope global 2>/dev/null | awk '$4 ~ /\./ { gateways = gateways $4 ", " } END { print substr(gateways, 1, length(gateways)-2) }')
    public_ip=$(curl -s ifconfig.me)
    # ALL Local IP
    if [[ $system == 'termux' ]]; then
        if ! $pm list-installed &>/dev/null 2>&1 | grep -w iproute2 >/dev/null 2>&1; then
            echo "cloudflared is not installed. Installing now..."
            install iproute2
        fi
        gateway=$(ip route list match 0 table all scope global 2>/dev/null | awk '$3 ~ /\./ {print $5" "$3}')
    else
        gateway=$(ip route list match 0 table all scope global 2>/dev/null | awk '$4 ~ /\./ {print $6" "$4}')
    fi
    wifi_interface=$(echo $gateway | grep -n -E '\b(wlo|wlan|wifi|wlp0s|wlp1s|wlp2s|wlp3s|wlp4s|ath)[0-9]+\b')
    lan_interface=$(echo $gateway | grep -n -E '\b(eth|enp|enp0s|enp1s|enp2s|enp3s|enp4s|eno|ens)[0-9]+\b')
    if [[ -n $(echo $wifi_interface | awk -F: '{print $1}') ]]; then
        int=$(echo $gateway | awk -v i=$(echo $wifi_interface | awk -F: '{print $1}') 'NR==i{print $1}')
        if [[ $system == 'termux' ]]; then
            ip_wifi=$(ip address show wlan0 | awk '/inet / {print $2}' | cut -f1 -d'/')
            mac_wifi=$(ip address show wlan0 | awk '/link\/ether / {print $2}' | cut -f1 -d'/')
        else
            ip_wifi=$(ip address show $int | awk '/inet / {print $2}' | cut -f1 -d'/')
            mac_wifi=$(cat /sys/class/net/"$int"/address)
        fi
        gateway_wifi=$(echo $wifi_interface | awk '{print $2}')
    else
        ip_wifi="Disconnect"
        gateway_wifi="Disconnect"
        mac_wifi="Disconnect"
    fi
    if [[ -n $(echo $lan_interface | awk -F: '{print $1}') ]]; then
        int=$(echo $gateway | awk -v i=$(echo $lan_interface | awk -F: '{print $1}') 'NR==i{print $1}')
        ip_lan=$(ip address show $int | awk '/inet / {print $2}' | cut -f1 -d'/')
        gateway_lan=$(echo $lan_interface | awk '{print $2}')
        mac_lan=$(cat /sys/class/net/"$int"/address)
    else
        ip_lan="Disconnect"
        gateway_lan="Disconnect"
        mac_lan="Disconnect"

    fi

    echo "=================================="
    echo "|            IP Info             |"
    echo "=================================="
    echo " IP Public    : $public_ip"
    echo " Gateway WIFI : $gateway_wifi"
    echo " IP WIFI      : $ip_wifi"
    echo " MAC WIFI     : $mac_wifi"
    if [[ $system != 'termux' ]]; then
        echo " Gateway LAN  : $gateway_lan"
        echo " IP LAN       : $ip_lan"
        echo " MAC LAN      : $mac_lan"
    fi
    echo "=================================="
}

function netch() {
    if [[ $system != 'windows' ]]; then
        echo $not_support
        return 1
    fi
    gateway=$(ip route list match 0 table all scope global 2>/dev/null | awk '$4 ~ /\./ {print $6" "$4}')
    wifi_interface=$(echo $gateway | grep -n -E '\b(wlo|wlan|wifi|wlp0s|wlp1s|wlp2s|wlp3s|wlp4s|ath)[0-9]+\b')
    lan_interface=$(echo $gateway | grep -n -E '\b(eth|enp|enp0s|enp1s|enp2s|enp3s|enp4s|eno|ens)[0-9]+\b')
    interfaces=$(echo $gateway | awk '{ gateways = gateways $1 " " } END { print substr(gateways, 0, length(gateways)0) }')
    wifi=$(echo $gateway | grep -E '\b(wlo|wlan|wifi|wlp0s|wlp1s|wlp2s|wlp3s|wlp4s|ath)[0-9]+\b' | awk '{ print $1 }')
    gw_wifi=$(echo $gateway | grep -E '\b(wlo|wlan|wifi|wlp0s|wlp1s|wlp2s|wlp3s|wlp4s|ath)[0-9]+\b' | awk '{ print $2 }')
    lan=$(echo $gateway | grep -E '\b(eth|enp|enp0s|enp1s|enp2s|enp3s|enp4s|eno|ens)[0-9]+\b' | awk '{ print $1 }')
    gw_lan=$(echo $gateway | grep -E '\b(eth|enp|enp0s|enp1s|enp2s|enp3s|enp4s|eno|ens)[0-9]+\b' | awk '{ print $2 }')
    if [[ ! $wifi_interface && $lan_interface ]]; then
        echo "You can modify only LAN Network Interface"
    elif [[ $wifi_interface && ! $lan_interface ]]; then
        echo "You can modify only WIFI Network Interface"
    elif [[ $wifi_interface && $lan_interface ]]; then
        echo "You can modify LAN and WIFI Network Interface"
    else
        echo "You can not modify LAN and WIFI Network Interface, because your network is disconnected"
        return 1
    fi
    generate_ip=$(powershell.exe /c ipconfig)
    if [[ -z $(echo "$generate_ip" | grep -A2 'Ethernet adapter Ethernet:' | grep -e 'disconnected') ]]; then
        windows_ethernet="Ethernet"
    fi
    if [[ -z $(echo "$generate_ip" | grep -A2 'Wireless LAN adapter WiFi:' | grep -e 'disconnected') ]]; then
        windows_wireless="WiFi"
    fi
    if [[ -z $windows_wireless ]]; then wire=""; else wire="Wireless"; fi
    if [[ -z $windows_ethernet ]]; then ether=""; else ether="Ethernet"; fi
    PS3="What do you want to change? "
    select netoption in IP DNS; do
        case $netoption in
        IP)
            nextOption="ip"
            break
            ;;
        DNS)
            nextOption="dns"
            break
            ;;
        *)
            echo $wrong_input
            return 1
            ;;
        esac
    done
    if [[ $nextOption == "ip" ]]; then
        PS3="Select type IP: "
        select opt in Static DHCP; do
            case $opt in
            Static)
                type_ip='static'
                break
                ;;
            DHCP)
                type_ip='dhcp'
                break
                ;;
            *)
                echo $wrong_input
                return 1
                ;;
            esac
        done
        if [[ $type_ip == 'static' ]]; then
            PS3="Select interface: "
            select opt in $wire $ether; do
                case $opt in
                Wireless)
                    interface_selected=$windows_wireless
                    break
                    ;;
                Ethernet)
                    interface_selected=$windows_ethernet
                    break
                    ;;
                *)
                    echo $wrong_input
                    return 1
                    ;;
                esac
            done
            echo -ne "Change IP for interface $interface_selected to : "
            read ip_address
            if [[ -z $ip_address ]]; then
                if [[ $interface_selected == 'WiFi' ]]; then
                    ip_address=$(ip address show $wifi | awk '/inet / {print $2}' | cut -f1 -d'/')
                fi
                if [[ $interface_selected == 'Ethernet' ]]; then
                    ip_address=$(ip address show $lan | awk '/inet / {print $2}' | cut -f1 -d'/')
                fi
                echo "IP Address not replace"
            fi
            if [[ ! $ip_address =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                echo "IP Address is not valid. Try again!"
                return 1
            fi
            echo -ne "Change netmask to : "
            read netmask
            if [ -z $netmask ]; then
                netmask='255.255.255.0'
                echo "Subnetmask using default $netmask"
            fi
            if [[ ! $netmask =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                echo "Netmask is not valid. Try again!"
                return 1
            fi
            echo -ne "Change gateway to : "
            read chg_gateway
            if [[ -z $chg_gateway ]]; then
                if [[ $interface_selected == 'WiFi' ]]; then
                    chg_gateway=$gw_wifi
                fi
                if [[ $interface_selected == 'Ethernet' ]]; then
                    chg_gateway=$gw_lan
                fi
                echo "Gateway not replace"
            fi
            if [[ ! $chg_gateway =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                echo "Gateway is not valid. Try again!"
                return 1
            fi
            echo "Setting up interface $interface_selected to IP '$ip_address', netmask '$netmask', and gateway '$chg_gateway'"
            powershell.exe /c "Start-Process powershell -verb RunAs -ArgumentList 'netsh interface ipv4 set address name=$interface_selected static $ip_address $netmask $chg_gateway'"
        elif [[ $type_ip == 'dhcp' ]]; then
            PS3="Select interface: "
            select opt in $wire $ether; do
                case $opt in
                Wireless)
                    interface_selected=$windows_wireless
                    break
                    ;;
                Ethernet)
                    interface_selected=$windows_ethernet
                    break
                    ;;
                *)
                    echo $wrong_input
                    return 1
                    ;;
                esac
            done
            echo "Setting up IP interface $interface_selected to DHCP.."
            powershell.exe /c "Start-Process powershell -verb RunAs -ArgumentList 'netsh interface ipv4 set address name=$interface_selected dhcp'"
        fi
    elif [[ $nextOption == "dns" ]]; then
        PS3="Select type DNS: "
        select opt in Static DHCP; do
            case $opt in
            Static)
                type_dns='static'
                break
                ;;
            DHCP)
                type_dns='dhcp'
                break
                ;;
            *)
                echo $wrong_input
                return 1
                ;;
            esac
        done
        if [[ $type_dns == 'static' ]]; then
            PS3="Select interface: "
            select opt in $wire $ether; do
                case $opt in
                Wireless)
                    interface_selected=$windows_wireless
                    break
                    ;;
                Ethernet)
                    interface_selected=$windows_ethernet
                    break
                    ;;
                *)
                    echo $wrong_input
                    return 1
                    ;;
                esac
            done
            PS3="Change DNS to : "
            select dns in Local Google Cloudflare OpenDNS Adguard Quad9; do
                case $dns in
                Local)
                    dnsname="Local DNS"
                    dnsone="127.0.0.1"
                    dnstwo="127.0.1.1"
                    break
                    ;;
                Google)
                    dnsname="Google DNS"
                    dnsone="8.8.8.8"
                    dnstwo="8.8.4.4"
                    break
                    ;;
                Cloudflare)
                    dnsname="Cloudflare DNS"
                    dnsone="1.1.1.1"
                    dnstwo="1.0.0.1"
                    break
                    ;;
                OpenDNS)
                    dnsname="OpenDNS"
                    dnsone="208.67.222.222"
                    dnstwo="208.67.220.;break220"
                    break
                    ;;
                AdGuard)
                    dnsname="Adguard DNS"
                    dnsone="94.140.14.14"
                    dnstwo="94.140.15.15"
                    break
                    ;;
                Quad9)
                    dnsname="Quad9 DNS"
                    dnsone="9.9.9.9"
                    dnstwo="149.112.112.112"
                    break
                    ;;
                *)
                    echo "Input Wrong.."
                    break
                    ;;
                esac
            done
            echo "Setting up $dnsname"
            powershell.exe /c "Start-Process powershell -verb RunAs -ArgumentList 'netsh interface ipv4 set dns name=$interface_selected static $dnsone;netsh interface ipv4 add dns name=$interface_selected $dnstwo index=2'"
        elif [[ $type_dns == 'dhcp' ]]; then
            PS3="Select interface: "
            select opt in $wire $ether; do
                case $opt in
                Wireless)
                    interface_selected=$windows_wireless
                    break
                    ;;
                Ethernet)
                    interface_selected=$windows_ethernet
                    break
                    ;;
                *)
                    echo $wrong_input
                    return 1
                    ;;
                esac
            done
            echo "Setting up DNS to nonactive.."
            powershell.exe /c "Start-Process powershell -verb RunAs -ArgumentList 'netsh interface ipv4 set dns name=$interface_selected dhcp'"
        fi
    fi
}

function proxy() {
    if [[ $system != 'windows' ]]; then
        echo $not_support
        return 1
    fi
    case $1 in
    -sc | socks-custom)
        echo -ne "Port : "
        read proxyport
        powershell.exe /c "& {Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'ProxyServer' -type 'String' -value 'socks=127.0.0.1:$proxyport'; Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'ProxyOverride' -type 'String' -value 'localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*'; Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'ProxyEnable' -type 'DWord' -value '1'}"
        echo "Success set custom proxy.."
        ;;
    -hs | hotshare)
        echo -ne "Proxy : "
        read proxyip
        echo -ne "Port : "
        read proxyport
        powershell.exe /c "& {Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'ProxyServer' -type 'String' -value '$proxyip:$proxyport'; Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'ProxyOverride' -type 'String' -value 'localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*'; Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'ProxyEnable' -type 'DWord' -value '1'}"
        echo "Success set hotshare proxy.."
        ;;
    -hi | http-injector)
        PS3="Select proxy source: "
        select data in $(ip route list match 0 table all scope global 2>/dev/null | awk '{print $4}'); do
            case $data in
            $data)
                powershell.exe /c "& {Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'ProxyServer' -type 'String' -value '$data:44355'; Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'ProxyOverride' -type 'String' -value 'localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*'; Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'ProxyEnable' -type 'DWord' -value '1'}"
                echo "Success set hotshare proxy.."
                break
                ;;
            esac
        done
        ;;
    -hc | http-custom)
        PS3="Select proxy source: "
        select data in $(ip route list match 0 table all scope global 2>/dev/null | awk '{print $4}'); do
            case $data in
            $data)
                powershell.exe /c "& {Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'ProxyServer' -type 'String' -value '$data:7071'; Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'ProxyOverride' -type 'String' -value 'localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*'; Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'ProxyEnable' -type 'DWord' -value '1'}"
                echo "Success set hotshare proxy.."
                break
                ;;
            esac
        done
        ;;
    -r | reset)
        powershell.exe /c "& {Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'ProxyServer' -type 'String' -value ''; Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'ProxyOverride' -type 'String' -value ''; Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'ProxyEnable' -type 'DWord' -value '0'}"
        echo "Success Reset Proxy.."
        ;;
    -s | socks)
        powershell.exe /c "& {Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'ProxyServer' -type 'String' -value 'socks=127.0.0.1:1080'; Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'ProxyOverride' -type 'String' -value 'localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*'; Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'ProxyEnable' -type 'DWord' -value '1'}"
        echo "Success set socks5 proxy.."
        ;;
    -e | enable) powershell.exe /c "& {Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'ProxyEnable' -type 'DWord' -value '1'}" ;;
    -d | disable) powershell.exe /c "& {Set-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name 'ProxyEnable' -type 'DWord' -value '0'}" ;;
    *)
        echo "Usage : proxy [options]"
        echo ""
        echo "Options :"
        echo "------------------------------------------------"
        echo "    -d      Disable proxy"
        echo "    -e      Enable current proxy"
        echo "    -hi     Enable Hotshare HTTP Injector proxy"
        echo "    -hs     Enable Hotshare proxy"
        echo "    -r      Reset proxy settings"
        echo "    -s      Enable Socks Proxy"
        echo "    -sc     Setup Custom socks proxy port"
        echo ""
        ;;
    esac
}

function redns() {
    if [[ $system == 'termux' ]]; then
        echo "$not_support"
        return 1
    elif [[ $system == 'windows' ]]; then
        powershell.exe /c "ipconfig /flushdns"
    else
        if [[ $pm == 'apt' ]]; then
            sudo systemd-resolve --flush-caches
        elif [[ $pm == 'apk' ]]; then
            sudo rc-service dnsmasq restart
        elif [[ $pm == 'zypper' ]]; then
            sudo systemctl restart systemd-resolved.service
        elif [[ $pm == 'dnf' || $pm == 'yum' ]]; then
            sudo systemd-resolve --flush-caches
        elif [[ $pm == 'pkg' ]]; then
            sudo service nscd restart
        elif [[ $pm == 'xbps-install' ]]; then
            sudo sv restart dnsmasq
        else
            echo "$not_support"
            return 1
        fi
    fi
}

function cloudflare() {
    if [[ -n $(search cloudflared &>/dev/null | grep "cloudflared") ]]; then
        if ! which cloudflared &>/dev/null; then
            echo "cloudflared is not installed. Installing now..."
            install cloudflared -y
            return 1
        fi
    else
        system_architecture=$(uname -m)
        case $system_architecture in
        x86_64) sudo wget -O /usr/bin/cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 ;;
        i686) sudo wget -O /usr/bin/cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-386 ;;
        armv7l) sudo wget -O /usr/bin/cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm ;;
        aarch64) sudo wget -O /usr/bin/cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64 ;;
        *)
            echo "Error: Unsupported system architecture."
            return 1
            ;;
        esac
        sudo chmod +x /usr/bin/cloudflared
        return 1
    fi

    function usage() {
        echo "Usage: cloudflare [options]"
        echo ""
        echo "Options:"
        echo "------------------------------------------------"
        echo "    -c <tunnel>         Create a new tunnel"
        echo "    -C                  Configuration"
        echo "    -d <tunnel>         Delete a tunnel"
        echo "    -h                  Show this message"
        echo "    -L                  List available tunnels"
        echo "    -l                  Login to Cloudflare"
        echo "    -r <tunnel> DOMAIN  Route a DNS entry for the tunnel"
        echo "    -s <tunnel>         Start a tunnel"
    }
    configs=false
    while getopts ":s:c:d:r:ChlL" opt; do
        case $opt in
        C)
            configs=true
            break
            ;;
        s)
            cloudflared tunnel run "$OPTARG"
            break
            ;;
        l)
            if [[ -f $HOME/.cloudflared/cert.pem ]]; then
                echo "You detected logged in, delete cert.pem file for relogin"
                return 1
            fi
            cloudflared tunnel login
            break
            ;;
        c)
            cloudflared tunnel create "$OPTARG"
            break
            ;;
        L)
            for file in $HOME/.cloudflared/*.json; do
                filename=$(basename "$file" .json)
            done
            if [[ -z $filename ]]; then
                echo "No tunnel found, use -c instead to create tunnel"
                return 1
            fi
            echo $filename
            #cloudflared tunnel list
            break
            ;;
        d)
            cloudflared tunnel delete "$OPTARG"
            break
            ;;
        r)
            if [ -z "$3" ]; then
                echo "Error: Domain name required for -r option"
                usage
                return 1
            fi
            cloudflared tunnel route dns "$OPTARG" "$2"
            break
            ;;
        h) usage ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            usage
            return 1
            ;;
        :)
            echo "Option -$OPTARG requires an argument." >&2
            usage
            return 1
            ;;
        esac
    done
    if [[ $# -eq 0 ]]; then
        usage
        return 1
    fi
    if [[ ! -f $HOME/.cloudflared/cert.pem ]]; then
        echo "You detected not log in, please login first"
        return 1
    fi
    if $configs; then
        PS3="Select location: "
        select loc in $HOME/.cloudflared $HOME/.cloudflare-warp $HOME/cloudflare-warp /etc/cloudflared /usr/local/etc/cloudflared; do
            case $loc in
            $HOME/.cloudflared)
                if [[ ! -d $HOME/.cloudflared ]]; then
                    mkdir -p $HOME/.cloudflared
                fi
                dir=$HOME/.cloudflared
                break
                ;;
            $HOME/.cloudflare-warp)
                if [[ ! -d $HOME/.cloudflare-warp ]]; then
                    mkdir -p $HOME/.cloudflare-warp
                fi
                dir=$HOME/.cloudflare-warp
                break
                ;;
            $HOME/cloudflare-warp)
                if [[ ! -d $HOME/cloudflare-warp ]]; then
                    mkdir -p $HOME/cloudflare-warp
                fi
                dir=$HOME/cloudflare-warp
                break
                ;;
            /etc/cloudflared)
                if [[ ! -d /etc/cloudflared ]]; then
                    sudo mkdir -p /etc/cloudflared
                fi
                dir=/etc/cloudflared
                break
                ;;
            /usr/local/etc/cloudflared)
                if [[ ! -d /usr/local/etc/cloudflared ]]; then
                    sudo mkdir -p /usr/local/etc/cloudflared
                fi
                dir=/usr/local/etc/cloudflared
                break
                ;;
            *)
                echo "Invalid!"
                return 1
                ;;
            esac
        done
        PS3="Select action: "
        select act in Create Add Delete Show; do
            case $act in
            Create)
                if [[ -f $(ls $dir/*.json) ]]; then
                    echo "Tunnel is exists"
                    return 1
                fi
                echo -ne "Input ID Tunnel: "
                read tunnelID
                if [[ -z $tunnelID ]]; then
                    echo "Cancel action"
                    return 1
                fi
                if [[ ! -f $dir/config.yaml ]]; then
                    echo -ne "tunnel: $tunnelID\ncredentials-file: ${dir}/${tunnelID}.json\ningress:\n  - service: http_status:404" >$dir/config.yaml
                    echo "Success create config.yaml file"
                else
                    echo "File config is exists"
                fi
                break
                ;;
            Add)
                if [[ ! -f $dir/config.yaml ]]; then
                    echo "Use option Create first"
                    return 1
                fi
                echo -n "Enter hostname: "
                read hostname
                echo -n "Enter service (in the format host:port): "
                read service
                sed -i "/http_status:404/ i \  - hostname: $hostname\n    service: $service" $dir/config.yaml
                echo "Ingress added successfully"
                break
                ;;
            Delete)
                if [[ ! -f $dir/config.yaml ]]; then
                    echo "Use option Create first"
                    return 1
                fi
                local check=$(sed -n '/ingress:/,/- service: http_status:404/p' $dir/config.yaml | grep -oP '(?<=hostname: ).*' | awk '{print $1}')
                if [[ -z $check ]]; then
                    echo "No hostname configured, use Add instead."
                    return 1
                fi
                PS3="Select to delete: "
                select hostname in $check; do
                    sed -i "/- hostname: $hostname/,+1 d" $dir/config.yaml
                    echo "Ingress deleted successfully"
                    break
                done
                break
                ;;
            Show)
                if [[ ! -f $dir/config.yaml ]]; then
                    echo "Use option Create first"
                    return 1
                fi
                check=$(sed -n '/ingress:/,/- service: http_status:404/p' $dir/config.yaml | grep -oP '(?<=hostname: ).*' | awk '{print $1}')
                if [[ -z $check ]]; then
                    echo "No hostname configured, use Add instead."
                    return 1
                fi
                echo $check
                break
                ;;
            *)
                echo "Invalid select! Try again"
                return 1
                ;;
            esac
        done
    fi

}

function speeds() {
    if [[ $system == 'termux' ]]; then
        if ! which speedtest-go &>/dev/null; then
            echo "speedtest-go not found. Installing now..."
            install speedtest-go
            return 1
        else
            speedtest-go
        fi
    else
        if ! which speedtest &>/dev/null; then
            echo "speedtest not found. Installing now..."
            if [[ $pm == 'apt' ]]; then
                install speedtest-cli
                return 1
            else
                echo $not_support
                return 1
            fi
        else
            speedtest
        fi
    fi
}
############################# END IPs #############################

############################# SERVICE #############################

function play() {
    echo "Hope you fun to play this game!"
    local list=("Moon-buggy" "Tetris" "Pacman" "Space-Invaders" "Snake" "Greed" "Nethack" "Sudoku" "2048")
    PS3="Choose game: "
    select choosed in "${list[@]}"; do
        case $choosed in
        Moon-buggy)
            gamename="moon-buggy"
            break
            ;;
        Tetris)
            gamename="bastet"
            break
            ;;
        Pacman)
            gamename="pacman"
            break
            ;;
        Space-Invaders)
            gamename="ninvaders"
            break
            ;;
        Snake)
            gamename="nsnake"
            break
            ;;
        Greed)
            gamename="greed"
            break
            ;;
        Nethack)
            gamename="nethack"
            break
            ;;
        Sudoku)
            gamename="nudoku"
            break
            ;;
        2048)
            gamename="2048"
            break
            ;;
        *) echo "Invalid input. Try again!" ;;
        esac
    done

    if ! which $gamename >/dev/null 2>&1; then
        if [[ $gamename == "2048" ]]; then
            install clang -y
            wget -q https://raw.githubusercontent.com/mevdschee/2048.c/master/2048.c
            gcc -o $PREFIX/bin/2048 2048.c
            chmod +x $PREFIX/bin/2048
            rm 2048.c
        else
            install $gamename -y
        fi
        $gamename
    else
        $gamename
    fi
}

function kali() {
    if [ "$system" != "termux" ]; then
        echo "$not_support"
        return 1
    fi
    if [ ! -f "$HOME/.config/.kali" ]; then
        actions=("Install")
    else
        actions=("Uninstall" "Start-GUI" "Start-CLI" "End-GUI" "Passwd" Command "Root")
    fi
    echo -e "May you need 'NetHunter-KeX client' or 'AVNC' and 'Hacker’s keyboard'\n"
    PS3="Choose an action: "
    select action in "${actions[@]}"; do
        case $action in
        Install)
            if [ ! -d "$HOME/storage" ]; then
                termux-setup-storage
            fi
            if ! which wget &>/dev/null; then
                install wget -y
            fi
            if [ ! -f "$HOME/nh-termux" ]; then
                wget -q --show-progress -O "$HOME/nh-termux" "https://offs.ec/2MceZWr" && chmod +x "$HOME/nh-termux" && "$HOME/nh-termux"
            else
                chmod +x "$HOME/nh-termux" && "$HOME/nh-termux"
            fi
            if [ ! -d "$HOME/.config" ]; then
                mkdir "$HOME/.config"
            fi
            touch "$HOME/.config/.kali"
            break
            ;;
        Uninstall)
            rm -rf $HOME/kali-arm64 $HOME/.config/.kali
            break
            ;;
        Start-GUI)
            nethunter kex &
            break
            ;;
        Start-CLI)
            nethunter
            break
            ;;
        End-GUI)
            nethunter kex stop
            break
            ;;
        Passwd)
            nethunter kex passwd
            break
            ;;
        Command)
            read -rp "Input command: " cmd
            if [ -n "$cmd" ]; then
                nethunter "$cmd"
            else
                echo "Invalid command."
            fi
            break
            ;;
        Root)
            nethunter -r
            break
            ;;
        *)
            echo "Invalid input. Read more at https://www.kali.org/docs/nethunter/nethunter-rootless/"
            ;;
        esac
    done
}

function docker-install() {
    if [[ $system == "termux" ]]; then
        echo "$not_support"
    fi
    if ! command -v docker >/dev/null 2>&1; then
        myos=$(grep -oP '^ID=\K\S+' /etc/os-release)
        if [[ $pm == "apt" ]]; then
            echo "Docker service not found. Installing now..."
            sudo apt update &&
                sudo apt install -y ca-certificates curl gnupg2 software-properties-common
            curl -fsSL https://download.docker.com/linux/$myos/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
            echo \
                "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/$myos \
                $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
            sudo apt update &&
                sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx docker-compose
            sudo usermod -aG docker $USER
        elif [[ $pm == "yum" ]]; then
            if [[ $myos == "centos" ]]; then
                sudo yum install -y yum-utils
                sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
                sudo yum install -y docker-ce docker-ce-cli containerd.io docker-buildx docker-compose
                sudo usermod -aG docker $USER
            elif [[ $myos == "fedora" ]]; then
                sudo dnf install -y dnf-plugins-core
                sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
                sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx docker-compose
                sudo usermod -aG docker $USER
            fi
        else
            echo "$not_support"
        fi
    fi
}

function kubectl() {
    if [[ $system == "termux" ]]; then
        echo "$not_support"
    fi
    if ! which minikube >/dev/null 2>&1; then
        if [[ $system == "windows" ]]; then
            echo "Detected using WSL 1! May you cannot using it, try out on WSL 2."
            sleep 3
        fi
        echo -ne "minikube not found. Do you want install [y/N]? "
        read response
        case $response in
            y|Y )   if [[ $system == "linux" ]]; then
                        system_architecture=$(uname -m)
                        case $system_architecture in
                            x86_64)     curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
                                        sudo install minikube-linux-amd64 /usr/local/bin/minikube
                                        ;;
                            armv7l)     curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-arm64
                                        sudo install minikube-linux-arm64 /usr/local/bin/minikube
                                        ;;
                            aarch64)    curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-arm64
                                        sudo install minikube-linux-arm64 /usr/local/bin/minikube
                                        ;;
                            *)          echo "See https://minikube.sigs.k8s.io/docs/start/";;
                        esac
                    fi;;
            * ) return 1;;
        esac
    fi
    if ! which kubectl >/dev/null 2>&1 && which minikube >/dev/null 2>&1; then
        minikube kubectl $*
    elif which kubectl >/dev/null 2>&1 && which minikube >/dev/null 2>&1; then
        kubectl $*
    fi
}

function sctl() {
    if [[ $system == "termux" ]]; then
        if which sv >/dev/null 2>&1; then
            system_service="sv"
        else
            echo "termux service not found. Installing now..."
            install termux-services -y
            echo -ne "Installation success.\nRestart termux for using service daemon."
            return 1
        fi
    elif [[ $system == "windows" ]]; then
        if which service >/dev/null 2>&1; then
            system_service="service"
        else
            echo "$not_support"
            return 1
        fi
    else
        if which systemctl >/dev/null 2>&1; then
            system_service="systemctl"
        elif which service >/dev/null 2>&1; then
            system_service="service"
        elif which sv >/dev/null 2>&1; then
            system_service="sv"
        else
            echo "$not_support"
            return 1
        fi
    fi

    # Set default values
    action=""
    service=""

    function usage() {
        if [[ $system == "termux" ]]; then
            echo "Usage: sctl <option> [service]"
            echo ""
            echo "Options:"
            echo "------------------------------------------------"
            echo "  -d    Disable service"
            echo "  -e    Enable service"
            echo "  -h    Show this help message"
            echo "  -R    Reload service"
            echo "  -r    Restart service"
            echo "  -s    Start service"
            echo "  -S    Stop service"
            echo "  -t    Status service"
            return 1
        elif [[ $system == "windows" ]]; then
            echo "Usage: sctl <option> [service]"
            echo ""
            echo "Options:"
            echo "------------------------------------------------"
            echo "  -a    Show all services"
            echo "  -h    Show this help message"
            echo "  -R    Reload service"
            echo "  -r    Restart service"
            echo "  -s    Start service"
            echo "  -S    Stop service"
            echo "  -t    Status service"
            return 1
        else
            echo "Usage: sctl <option> [service]"
            echo ""
            echo "Options:"
            echo "------------------------------------------------"
            echo "  -d    Disable service"
            echo "  -e    Enable service"
            echo "  -h    Show this help message"
            echo "  -r    Restart service"
            echo "  -s    Start service"
            echo "  -S    Stop service"
            echo "  -t    Status service"
            echo ""
            echo "  -D    Down service"
            echo "  -R    Reload service"
            echo "  -u    Up service"
        fi
    }

    while getopts ":s:r:e:S:d:t:u:D:R:ah" opt; do
        case $opt in
        a) action="show-all" ;;
        s)
            action="start"
            service="$OPTARG"
            ;;
        r)
            action="restart"
            service="$OPTARG"
            ;;
        e)
            if [[ $system == "termux" ]]; then
                action="sv-enable"
            else
                action="enable"
            fi
            service="$OPTARG"
            ;;
        S)
            action="stop"
            service="$OPTARG"
            ;;
        d)
            if [[ $system == "termux" ]]; then
                action="sv-disable"
            else
                action="disable"
            fi
            service="$OPTARG"
            ;;
        t)
            action="status"
            service="$OPTARG"
            ;;
        u)
            action="up"
            service="$OPTARG"
            ;;
        D)
            action="down"
            service="$OPTARG"
            ;;
        R)
            action="reload"
            service="$OPTARG"
            ;;
        h)
            usage
            return 1
            ;;
        :)
            echo "Error: Option -$OPTARG requires an argument" >&2
            return 1
            ;;
        *)
            echo "Error: Invalid option -$OPTARG" >&2
            return 1
            ;;
        esac
    done

    if [[ -z $action ]]; then
        echo "Error: Must specify one option" >&2
        usage
        return 1
    elif [[ $(echo $action | wc -w) -ne 1 ]]; then
        echo "Error: Can only specify one option" >&2
        usage
        return 1
    fi
    if [[ $system == "termux" ]]; then
        if [[ $action == "start" || $action == "restart" || $action == "stop" || $action == "reload" || $action == "status" || $action == "sv-enable" || $action == "sv-disable" ]]; then
            $system_service $action $service
        else
            echo $not_support
            return 1
        fi
    elif [[ $system == "windows" ]]; then
        if [[ $action == "start" || $action == "restart" || $action == "stop" || $action == "reload" || $action == "status" ]]; then
            sudo $system_service $service $action
        elif [[ $action == "show-all" ]]; then
            service --status-all
        else
            echo $not_support
            return 1
        fi
    else
        if [[ $system_service == "systemctl" ]]; then
            if [[ $action == "start" || $action == "restart" || $action == "stop" || $action == "reload" || $action == "status" || $action == "enable" || $action == "disable" ]]; then
                sudo $system_service $action $service
            else
                echo $not_support
                return 1
            fi
        elif [[ $system_service == "service" ]]; then
            if [[ $action == "start" || $action == "restart" || $action == "stop" || $action == "reload" || $action == "status" || $action == "enable" || $action == "disable" ]]; then
                sudo $system_service $service $action
            else
                echo $not_support
                return 1
            fi
        elif [[ $system_service == "sv" ]]; then
            if [[ $action == "start" || $action == "restart" || $action == "stop" ]]; then
                sudo $system_service $action $service
            elif [[ $action == "enable" ]]; then
                sudo $system_service enable $service
            elif [[ $action == "disable" ]]; then
                sudo $system_service disable $service
            elif [[ $action == "status" ]]; then
                sudo $system_service status $service
            elif [[ $action == "up" ]]; then
                sudo $system_service up $service
            elif [[ $action == "down" ]]; then
                sudo $system_service down $service
            else
                echo $not_support
                return 1
            fi
        fi
    fi
}

function sc() {
    if ! which ssh &>/dev/null; then
        echo "openssh is not installed. Installing now..."
        install openssh -y
        return 1
    fi
    function usage() {
        echo "Usage: sc [options]"
        echo ""
        echo "Options :"
        echo "------------------------------------------------"
        echo "    -a ACCOUNT  Add ssh account"
        echo "    -c          Connect ssh account"
        echo "    -d          Delete ssh account"
        echo "    -h          Show this message"
        echo "    -k KEY      Add public key"
        echo "    -K          Show default public key"
        echo "    -s          Show all ssh account"
        return 1
    }
    file_config=$HOME/.scrc
    if [[ ! -f $HOME/.scrc ]]; then
        touch $file_config
    fi
    if [[ $# -eq 0 ]]; then
        usage
        return 1
    fi
    while getopts ":a:k:Ksdch" opt; do
        case $opt in
        a)
            if [[ ! $OPTARG =~ '^[^@]+@[^@]+$' ]]; then
                echo "Error: Input is must be user@hostname only"
                return 1
            else
                echo $OPTARG >>$file_config 2>/dev/null
                echo "[*] Success added $OPTARG"
            fi
            break
            ;;
        d)
            if [[ -z $(cat $file_config) ]]; then
                echo "Error: No has ssh account"
                return 1
            else
                declare -A options=()
                while read -r line; do
                    options["$line"]=$line
                done <"$file_config"
                PS3="Choose account: "
                select option in "${options[@]}"; do
                    sed -i "/$option/d" $file_config
                    if grep -q $option $file_config; then
                        echo "Error: Failed to delete account $option"
                        return 1
                    else
                        echo "Success delete account $option"
                        return 1
                    fi
                done
            fi
            break
            ;;
        s)
            if [[ -z $(cat $file_config) ]]; then
                echo "Error: No has ssh account"
                return 1
            else
                echo -ne "Show all account :\n"
                cat $file_config
            fi
            break
            ;;
        k)
            if [ ! -f ~/.ssh/authorized_keys ]; then
                if [ !-d ~/.ssh ]; then
                    mkdir ~/.ssh
                fi
                touch ~/.ssh/authorized_keys
            fi
            ssh_regex='^(ssh-ed25519|ssh-rsa)\s+[A-Za-z0-9+/]+[=]{0,2}\s+[A-Za-z0-9@.-]+$'
            if [[ ! $OPTARG =~ $ssh_regex ]]; then
                echo "Error: Input is must be ssh key only"
                return 1
            else
                echo $OPTARG >>~/.ssh/authorized_keys 2>/dev/null
                echo "Success: Added key$OPTARG"
            fi
            break
            ;;
        K)
            local choosed=("rsa" "ed25519")
            PS3="What encryption type? "
            select protocol in "${choosed[@]}"; do
                case $protocol in
                rsa)
                    if [[ ! -f $HOME/.ssh/id_rsa.pub || ! -f $HOME/.ssh/id_rsa ]]; then
                        ssh-keygen -t rsa -b 4096 -o -a 100
                        cat $HOME/.ssh/id_rsa.pub
                    else
                        cat $HOME/.ssh/id_rsa.pub
                    fi
                    break
                    ;;
                ed25519)
                    if [[ ! -f $HOME/.ssh/id_ed25519.pub || ! -f $HOME/.ssh/id_ed25519 ]]; then
                        ssh-keygen -t ed25519 -a 100
                        cat $HOME/.ssh/id_ed25519.pub
                    else
                        cat $HOME/.ssh/id_ed25519.pub
                    fi
                    break
                    ;;
                esac
            done
            break
            ;;
        c)
            if [[ -z $(cat $file_config) ]]; then
                echo "Error: No has ssh account"
                return 1
            else
                function check() {
                    local port=$1
                    if ! [[ $port =~ ^[0-9]+$ ]]; then
                        echo "[!] Your input is not valid"
                        return 1
                    fi
                    if (($port < 1 || $port > 65535)); then
                        echo "[!] Only port 1 - 65535"
                        return 1
                    fi
                }
                declare -A options=()
                while read -r line; do
                    options["$line"]=$line
                done <"$file_config"

                PS3="Choose account: "
                select option in "${options[@]}"; do
                    if [[ -n $option ]]; then
                        account_ssh=${options["$option"]}
                        break
                    else
                        echo "[!] Invalid option. Try again!"
                    fi
                done
                echo -n "Custom ssh port [22]: "
                read custom_port
                if [[ -n $custom_port ]]; then
                    check $custom_port
                fi
                echo -n "Custom dynamic local port [default]: "
                read local_port
                if [[ -n $local_port ]]; then
                    check $local_port
                fi

                if [[ -z $custom_port ]]; then
                    port="22"
                else
                    port="$custom_port"
                fi
                if [[ -z $local_port ]]; then
                    socks=""
                else
                    socks="-D 127.0.0.1:$local_port"
                fi
                chiper="Ciphers=chacha20-poly1305@openssh.com"
                keax="KexAlgorithms=curve25519-sha256@libssh.org"
                macs="MACs=hmac-sha2-256-etm@openssh.com"
                hka="HostKeyAlgorithms=ssh-ed25519"
                ssh $account_ssh -p $port $socks -o $chiper -o $keax -o $macs -o $hka
            fi
            break
            ;;
        h)
            usage
            break
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            usage
            ;;
        :)
            echo "Option -$OPTARG requires an ssh account." >&2
            usage
            break
            return 1
            ;;
        *) echo "Invalid command" ;;
        esac
    done
}

function backup() {
    PS3="Select what backup: "
    select typebr in Folder Database; do
        type=$typebr
        break
    done
    PS3="Select action: "
    select actionbr in Backup Restore; do
        action=$actionbr
        break
    done
    function usage() {
        echo "Usage: backup [options] <path to backup and restore>"
        echo ""
        echo "Options:"
        echo "------------------------------------------------"
        echo "    -d DIR         Directory to backup"
        echo "    -h             Show this message"
    }
    while getopts ":f:d:h" opt; do
        case $opt in
        d) directory="$OPTARG" ;;
        h) usage ;;
        \? | *)
            echo "Invalid option: -$OPTARG" >&2
            usage
            return 1
            ;;
        :)
            echo "Option -$OPTARG requires an argument." >&2
            usage
            return 1
            ;;
        esac
    done
    if [[ $type == 'Folder' ]]; then
        if [[ -z $directory ]]; then
            echo "Use option -d for use this setup"
            return 1
        fi

        if [[ $action == 'Backup' ]]; then
            path="Backup-F-$filename-$(date +%Y-%m-%d).tar.gz"
            tar -czvf "$path" "$directory"
        elif [[ $action == 'Restore' ]]; then
            PS3="Select file: "
            select files in $(ls *.tar.gz); do
                if [[ -z $files ]]; then
                    echo "Invalid selection"
                    continue
                else
                    tar -xzvf "$files" -C "$directory"
                    break
                fi
            done
        fi
    elif [[ $type == 'Database' ]]; then
        if [[ $action == 'Backup' ]]; then
            echo "Coming soon"
        elif [[ $action == 'Restore' ]]; then
            echo "Coming soon"
        fi
    fi
    if [[ $# -eq 0 ]]; then
        usage
        return 1
    fi
}

function monitoring() {
    if [[ $system == 'termux' ]]; then
        echo $not_support
        return 1
    fi
    install=false
    show=false
    function usage() {
        echo "Usage: monitoring [options] <path to backup and restore>"
        echo ""
        echo "Options:"
        echo "------------------------------------------------"
        echo "    -h             Show this message"
        echo "    -i             Install monitoring"
        echo "    -s             Show monitoring"
    }
    while getopts "sih" opt; do
        case $opt in
        i)
            install=true
            break
            ;;
        s)
            show=true
            break
            ;;
        h)
            usage
            break
            ;;
        *)
            echo "Invalid option" >&2
            break
            ;;
        esac
    done
    if $show; then
        while true; do
            if [ ! -d ~/.log ]; then
                mkdir -p ~/.log
            fi
            echo -ne "Monitoring is running.."
            echo "CPU   MEM    SWP     DATE                UPTIME" >~/.log/monitoring-$(date +%F).log
            while true; do
                cpu="$(top -b -n1 | grep "Cpu(s)" | awk '{print $2 + $4}')"
                if [[ $cpu == "0" ]]; then
                    cpu_usage="$cpu.0%"
                else
                    cpu_usage="$cpu%"
                fi
                memory_usage=$(free -m | awk 'NR==2{printf "%.2f%%\t\t", $3*100/$2}' | tr -d '[:space:]')
                swap_usage=$(free -m | awk 'NR==3{printf "%.2f%%\t\t", $3*100/$2}' | tr -d '[:space:]')
                dates=$(date +%F_%H:%M:%S)
                uptime=$(uptime | awk '{print $3,$4}' | sed 's/,//')
                if [ ! -f ~/.log/monitoring-$(date +%F).log ]; then
                    touch ~/.log/monitoring-$(date +%F).log
                fi
                #echo "$cpu_usage $memory_usage $swap_usage, $dates, $uptime"
                echo "$cpu_usage $memory_usage $swap_usage, $dates, $uptime" >>~/.log/monitoring-$(date +%F).log
                if [[ $(date +%H:%M:%S) == "23:59:59" ]]; then
                    break 2
                fi
            done
        done
    elif $install; then
        echo "Coming soon"
    fi
    if [[ $# -eq 0 ]]; then
        usage
        return 1
    fi
}

function webservice() {
    webs=false
    PS3="What service do you want?"
    select service in Web; do
        case $service in
        Web)
            webs=true
            break
            ;;
        *) echo "Error: Need valid number selected" ;;
        esac
    done
    if $webs; then
        function addsites() {
            echo -ne "Input port (example: 8080): "
            read port
            if [[ -z $port ]]; then
                echo "Need port for web server!"
                return 1
            fi
            echo -ne "Input path DocumentRoot (example: /var/www/html): "
            read docroot
            if [[ -z $docroot ]]; then
                echo "Need path of web!"
                return 1
            fi
            echo -ne "Input domain if you has (example: example.com): "
            read domain
            if [[ -z $domain ]]; then
                domain="_"
            fi
            if [[ $system == 'termux' ]]; then
                port_Listen=$(grep -E '^\s*Listen\s+[0-9]+' $PREFIX/etc/apache2/httpd.conf | grep -v '#' | tr -s ' ' | tail -n 1)
                sed -i "/$port_Listen/i $port/" $PREFIX/etc/apache2/httpd.conf
                echo -ne "<VirtualHost *:$port>\n  DocumentRoot $docroot\n  ServerName $domain\n  <Directory $docroot>\n    AllowOverride None\n    Options Indexes FollowSymLinks\n    Require all granted\n  </Directory>\n  <IfModule dir_module>\n    DirectoryIndex index.php\n  </IfModule>\n</VirtualHost>" >>$PREFIX/etc/apache2/extra/httpd-vhosts.conf
            else
                echo "Coming soon"
            fi
        }
        function deletesites() {
            if [[ $system == 'termux' ]]; then
                PS3='Select port:'
                check=$(grep -E '^\s*Listen\s+[0-9]+' $PREFIX/etc/apache2/httpd.conf | grep -v '#' | tr -s ' ' | tail -n 1 | awk '{print $2}')
                select opt in $check; do
                    sed -i "/$opt/d" $PREFIX/etc/apache2/httpd.conf
                    break
                done
                if [[ -z $(echo $check | grep "$opt") ]]; then
                    echo "Success delete sites"
                else
                    echo "Failed delete sites"
                fi
            else
                echo "Coming soon"
            fi
        }
        function enable() {
            if [[ $system == 'termux' ]]; then
                port_Listen=$(grep -E '^\s*Listen\s+[0-9]+' $PREFIX/etc/apache2/httpd.conf | grep -v '#' | tr -s ' ' | tail -n 1)
                sed -i "/$port_Listen/i $port/" $PREFIX/etc/apache2/httpd.conf
            else
                echo "Coming soon"
            fi
        }
        function disable() {
            if [[ $system == 'termux' ]]; then
                port_Listen=$(grep -E '^\s*Listen\s+[0-9]+' $PREFIX/etc/apache2/httpd.conf | grep -v '#' | tr -s ' ' | tail -n 1)
                sed -i "/$port_Listen/d" $PREFIX/etc/apache2/httpd.conf
            else
                echo "Coming soon"
            fi
        }
        function show() {
            if [[ $system == 'termux' ]]; then
                if [[ -f $PREFIX/etc/apache2/extra/httpd-vhosts.conf ]]; then
                    cat $PREFIX/etc/apache2/extra/httpd-vhosts.conf
                    return 1
                fi
                echo "Install web server first"
            else
                echo "Coming soon"
            fi
        }
        function update() {
            if [[ $system == 'termux' ]]; then
                if [[ -f $PREFIX/etc/apache2/httpd.conf ]]; then
                    nano $PREFIX/etc/apache2/httpd.conf
                    return 1
                fi
                echo "Cannot find '$PREFIX/etc/apache2/httpd.conf'"
            else
                echo "Coming soon"
            fi
        }
        function ssl() {
            if [[ $system == 'termux' ]]; then
                echo "$not_support"
                echo "Use cloudflared tunnel instead."
                return 1
            else
                echo "Coming soon"
            fi
        }
        if [[ $system == 'termux' ]]; then
            if [[ ! -f $PREFIX/var/log/installed ]]; then
                echo "Web server not configured. Configuration now..."
                packages=("apache2" "libapache2-mod-php" "autoconf" "automake" "bison" "bzip2" "clang" "cmake" "coreutils" "diffutils" "flex" "gawk" "git" "grep" "gzip" "libtool" "make" "patch" "perl" "sed" "silversearcher-ag" "tar" "apache2" "php" "php-apache" "php-apache-ldap" "php-apache-opcache" "php-apache-pgsql" "php-apache-sodium" "php-apcu" "php-fpm" "php-imagick" "php-ldap" "php-pgsql" "php-psr" "php-redis" "php-sodium" "php-zephir-parser" "mariadb" "phpmyadmin")
                for i in "${packages[@]}"; do
                    if ! $pm list-installed &>/dev/null 2>&1 | grep -w $i >/dev/null 2>&1; then
                        echo "Package $i is not installed, installing now..."
                        install $i -y &>/dev/null 2>&1
                    fi
                done
                sed -i 's/LoadModule mpm_worker_module libexec\/apache2\/mod_mpm_worker.so/#LoadModule mpm_worker_module libexec\/apache2\/mod_mpm_worker.so/' $PREFIX/etc/apache2/httpd.conf
                sed -i 's/#LoadModule mpm_prefork_module libexec\/apache2\/mod_mpm_prefork.so/LoadModule mpm_prefork_module libexec\/apache2\/mod_mpm_prefork.so/' $PREFIX/etc/apache2/httpd.conf
                sed -i 's/#LoadModule rewrite_module libexec\/apache2\/mod_rewrite.so/LoadModule rewrite_module libexec\/apache2\/mod_rewrite.so/' $PREFIX/etc/apache2/httpd.conf
                sed -i '/<IfModule unixd_module>/i LoadModule php_module libexec\/apache2\/libphp.so' $PREFIX/etc/apache2/httpd.conf
                sed -i '/<IfModule unixd_module>/i AddHandler php-script .php' $PREFIX/etc/apache2/httpd.conf
                sed -i "s/\(\$cfg\['Servers'\]\[\$i\]\['host'\]\s*=\s*\)'localhost';/\1'127.0.0.1:3306';/" $PREFIX/share/phpmyadmin/config.inc.php
                echo "Include etc/apache2/extra/php_module.conf" >>$PREFIX/etc/apache2/httpd.conf
                touch $PREFIX/etc/apache2/extra/php_module.conf
                echo "Done configure webserver..."
                echo "Setup phpmyadmin..."
                sed -i 's/#Include etc\/apache2\/extra\/httpd-vhosts.conf/Include etc\/apahce2\/extra\/httpd-vhosts.conf/g' $PREFIX/etc/apache2/httpd.conf
                sed -i "s///g" $PREFIX/share/phpmyadmin/config.inc.php
                sed -i '/Listen 8080/i Listen 8081/' $PREFIX/etc/apache2/httpd.conf
                echo -ne "<VirtualHost *:8081>\n  DocumentRoot "/data/data/com.termux/files/usr/share/phpmyadmin"\n  <Directory "/data/data/com.termux/files/usr/share/phpmyadmin">\n    AllowOverride None\n    Options Indexes FollowSymLinks\n    Require all granted\n  </Directory>\n  <IfModule dir_module>\n    DirectoryIndex index.php\n  </IfModule>\n</VirtualHost>" >>$PREFIX/etc/apache2/extra/httpd-vhosts.conf
                echo "Web server ready..."
                touch $PREFIX/var/log/installed
                return 1
            else
                PS3="Select action: "
                select act in Add Delete Enable Disable Show Update SSL; do
                    case $act in
                    Add)
                        addsites
                        break
                        ;;
                    Delete)
                        deletesites
                        break
                        ;;
                    Enable)
                        enable
                        break
                        ;;
                    Disable)
                        disable
                        break
                        ;;
                    Show)
                        show
                        break
                        ;;
                    Update)
                        update
                        break
                        ;;
                    SSL)
                        ssl
                        break
                        ;;
                    *)
                        echo "Select that number, not others!"
                        break
                        ;;
                    esac
                done
            fi
        else
            if [[ ! -f /var/log/installed ]]; then
                echo "Web server not configured. Configuration now..."
                if ! which nginx &>/dev/null; then
                    echo "nginx not found. Installing now..."
                    install nginx -y
                fi
                if ! which mysql &>/dev/null; then
                    echo "mysql not found. Installing mariadb now..."
                    if [[ $system == 'termux' ]]; then
                        install mariadb -y
                    else
                        install mariadb-server -y
                    fi
                fi
                if ! which php &>/dev/null; then
                    echo "php not found. Installing now..."
                    if [[ $pm == 'apt' ]]; then
                        install software-properties-common php8.1 php8.1-fpm php8.1-mysql php8.1-curl php8.1-gd php8.1-intl php8.1-mbstring php8.1-soap php8.1-xml php8.1-zip
                    elif [[ $pm == 'pacman' ]]; then
                        install php php-fpm php-mysql php-curl php-gd php-intl php-mbstring php-soap php-xml php-zip
                    elif [[ $pm == 'zypper' ]]; then
                        install php8 php8-fpm php8-mysql php8-curl php8-gd php8-intl php8-mbstring php8-soap php8-xml php8-zip
                    elif [[ $pm == 'apk' ]]; then
                        install php8 php8-fpm php8-mysqli php8-curl php8-gd php8-intl php8-mbstring php8-soap php8-xml php8-zip
                    else
                        echo "$not_support"
                        return 1
                    fi
                fi
                echo "Done configure webserver..."
            else
                PS3="Select action: "
                select act in Add Delete Enable Disable Show Update SSL; do
                    case $act in
                    Add)
                        addsites
                        break
                        ;;
                    Delete)
                        deletesites
                        break
                        ;;
                    Enable)
                        enable
                        break
                        ;;
                    Disable)
                        disable
                        break
                        ;;
                    Show)
                        show
                        break
                        ;;
                    Update)
                        update
                        break
                        ;;
                    SSL)
                        ssl
                        break
                        ;;
                    *)
                        echo "Select that number, not others!"
                        break
                        ;;
                    esac
                done
            fi
        fi

    fi
}

function firewall() {
    if [[ $system == 'termux' ]]; then
        echo "$not_support"
        return 1
    fi
    echo "Coming soon"
    return 1
}
########################### END SERVICE ###########################
############################# REGULAR #############################
function cloudfile() {
    if ! which curl &>/dev/null; then
        echo "curl not found. Installing now..."
        install curl
        return 1
    fi
    if ! which filebrowser &>/dev/null; then
        echo "filebrowser not found. Installing now..."
        curl -fsSL https://raw.githubusercontent.com/filebrowser/get/master/get.sh | bash
    fi

    function usage() {
        echo "Usage: cloudfile [options]"
        echo ""
        echo "Options :"
        echo "------------------------------------------------"
        echo "    -a IP             Set the IP address to listen [Default: 0.0.0.0]"
        echo "    -d DIR            Set the directory to serve [Default: home directory]"
        echo "    -h                Show this message"
        echo "    -p NUMBER         Set the port number [Default: 8080]"
        return 1
    }

    while getopts ":p:d:a:h" option; do
        case "$option" in
        a) addr="$OPTARG" ;;
        p) port="$OPTARG" ;;
        d) dirs="$OPTARG" ;;
        h)
            usage
            return
            ;;
        \?)
            echo "[!] Invalid option: -$OPTARG"
            return
            ;;
        esac
    done

    if [[ -z $addr ]]; then addr="0.0.0.0"; fi
    if [[ $system == 'termux' ]]; then
        if [[ -z $port ]]; then port="8080"; fi
    else
        if [[ -z $port ]]; then port="80"; fi
    fi
    if [[ -z $dirs ]]; then dirs="$HOME"; fi

    filebrowser -d "$HOME/.filebrowser.db" -p "$port" -a "$addr" -r "$dirs"
}

function troot() {
    if [[ $system != 'termux' ]]; then
        echo "$not_support"
        return 1
    fi
    if ! which proot-distro &>/dev/null; then
        echo "proot-distro is not installed. Installing now..."
        install proot-distro -y
        return 1
    fi

    function usage() {
        echo "Usage: troot [options] <select>"
        echo ""
        echo "Options:"
        echo "------------------------------------------------"
        echo "    -h       Show this help message"
        echo "    -i       Install Distro"
        echo "    -L       List distro"
        echo "    -l       Login to distro"
        return 1
    }
    while getopts ":L:i:l:h" opt; do
        case $opt in
        L)
            proot-distro list
            break
            ;;
        i)
            proot-distro install "$OPTARG"
            break
            ;;
        l)
            proot-distro login "$OPTARG"
            break
            ;;
        h) usage ;;
        \?)
            echo "Invalid option -$OPTARG" >&2
            usage
            ;;
        :)
            echo "Option -$OPTARG requires an distro name." >&2
            break
            return 1
            ;;
        esac
    done
}

function giit() {
    if ! which git &>/dev/null; then
        echo "Git is not installed"
        echo "Installing Git..."
        install git -y
        return 1
    fi
    function usage() {
        echo "Usage: giit [options]"
        echo ""
        echo "Options:"
        echo "------------------------------------------------"
        echo "    -h                Show this message"
        echo "    -i                Git Ignore Manager"
        echo "    -m <TARGET DIR>   Make folder a working directory for this git server"
        echo "    -S                Make current directory for Git server"
    }
    if [ $# -eq 0 ]; then
        usage
        return 1
    fi
    while getopts ":p:s:m:iSh" opt; do
        case $opt in
        p)
            if [[ -n $OPTARG ]]; then
                git add . && git commit -m "$OPTARG" && git push
            fi
            break
            ;;
        m)
            if [[ -d ./hooks ]]; then
                if [[ ! -f ./hooks/post-receive ]]; then
                    touch ./hooks/post-receive
                    chmod +x ./hooks/post-receive
                fi
                if [[ -z $OPTARG ]]; then
                    echo "Cancel creating work directory!"
                    return 1
                fi
                if [[ ! -d $OPTARG ]]; then
                    mkdir -p $OPTARG
                fi
                echo -ne "#!/bin/sh\nGIT_WORK_TREE=$OPTARG git checkout -f" >>./hooks/post-receive
                echo "Success make directory to $OPTARG"
            else
                echo "Error: Only git server directory can use"
                return 1
            fi
            break
            ;;
        S)
            git init --bare
            echo "Success create git server"
            echo -ne "Do you want create working directory [y/N]? "
            read opt
            case $opt in
            [yY])
                if [[ ! -f ./hooks/post-receive ]]; then
                    touch ./hooks/post-receive
                    chmod +x ./hooks/post-receive
                fi
                echo -ne "Where? "
                read inhere
                if [[ -z $inhere ]]; then
                    echo "Cancel creating work directory!"
                    return 1
                fi
                if [[ ! -d $inhere ]]; then
                    mkdir -p $inhere
                fi
                echo -ne "#!/bin/sh\nGIT_WORK_TREE=$inhere git checkout -f" >>./hooks/post-receive
                echo "Success make directory to $inhere"
                break
                ;;
            [nN] | *)
                return 1
                ;;
            esac
            break
            ;;
        i)
            if [[ ! -d ./.git ]]; then
                echo "Only support git folder"
                return 1
            fi
            if [[ ! -f .gitignore ]]; then
                touch .gitignore
            fi
            PS3="Select option: "
            select act in Add Show Delete Update; do
                case $act in
                Add)
                    echo -ne "Input ignore for: "
                    read ign
                    echo $ign >>.gitignore
                    break
                    ;;
                Show) cat .gitignore ;;
                Delete)
                    PS3="Select for delete: "
                    select del in $(cat .gitignore); do
                        sed -i "/$del/d" .gitignore
                    done
                    ;;
                *) echo "Error: Invalid option" ;;
                esac
            done
            break
            ;;
        h)
            usage
            break
            ;;
        \?)
            echo "Invalid option -$OPTARG" >&2
            break
            return 1
            ;;
        :)
            echo "Option -$OPTARG requires an argument." >&2
            break
            return 1
            ;;
        esac
    done
}

function ttmux() {
    if [[ $system != 'termux' ]]; then
        echo "$not_support"
        return 1
    fi
    function usage() {
        echo "Usage: ttmux [options]"
        echo ""
        echo "------------------------------------------------"
        echo "Options:"
        echo "    -b FILENAME   Create autorun script on boot"
        echo "    -E FILENAME   Edit autorun script"
        echo "    -B            Backup Termux"
        echo "    -t            Restore Termux"
        echo "    -g            Install game-repo"
        echo "    -h            Show this help message"
        echo "    -R            Change repo"
        echo "    -r            Install root-repo"
        echo "    -S            Install science-repo"
        echo "    -s            Setup storage on termux"
        echo "    -x            Install x11-repo"
    }
    if [[ ! -d ~/.termux/boot/ ]]; then
        mkdir -p ~/.termux/boot/
    fi
    while getopts ":b:E:RshgSrxBt" opt; do
        case $opt in
        b)
            nano mkdir -p ~/.termux/boot/$OPTARG
            break
            ;;
        E)
            nano ~/.termux/boot/$OPTARG
            break
            ;;
        R)
            termux-change-repo
            break
            ;;
        s)
            termux-setup-storage
            break
            ;;
        g)
            install game-repo
            break
            ;;
        S)
            install science-repo
            break
            ;;
        r)
            install root-repo
            break
            ;;
        x)
            install x11-repo
            break
            ;;
        B)
            if [[ -f /sdcard/termux-backup.tar.gz ]]; then
                echo "Do you want replace termux backup [y/N]? "
                read response
                case response in
                y | Y)
                    tar -zcf /sdcard/termux-backup.tar.gz -C /data/data/com.termux/files ./home ./usr
                    break
                    ;;
                n | N | *) return 1 ;;
                esac
            fi
            tar -zcf /sdcard/termux-backup.tar.gz -C /data/data/com.termux/files ./home ./usr
            break
            ;;
        t)
            if [[ ! -f /sdcard/termux-backup.tar.gz ]]; then
                echo "Make sure backup with directory and filename like this '/sdcard/termux-backup.tar.gz'"
                return 1
            fi
            tar -zxf /sdcard/termux-backup.tar.gz -C /data/data/com.termux/files --recursive-unlink --preserve-permissions
            break
            ;;
        h)
            usage
            break
            ;;
        \?)
            if [[ -n $OPTARG ]]; then
                echo "Invalid option $OPTARG" >&2
            else
                echo "Invalid option" >&2
            fi
            break
            return 1
            ;;
        :)
            if [[ -n $OPTARG ]]; then
                echo "Option $OPTARG requires an FILENAME" >&2
            fi
            break
            return 1
            ;;
        esac
    done
    if [[ $# -eq 0 ]]; then
        usage
        return 1
    fi
}

function download() {
    function usage() {
        echo "Usage  : download [-p] <url>"
        echo ""
        echo "------------------------------------------------"
        echo "Options:"
        echo "    -h         Show this help message"
        echo "    -p         Personal download directory"
        echo ""
        echo ""
        echo ""
        echo "Default: download <url> with current directory"
    }
    while getopts ":p:" opt; do
        case $opt in
        p)
            getname=$(basename $OPTARG)
            filename=$(echo ${getname%%\?*})
            if [[ $system == 'termux' ]]; then
                dl_dirs="/sdcard/Download/$filename"
                echo "Preparing..."
                wget -q --show-progress -O $dl_dirs $OPTARG
            elif [[ $system == 'windows' ]]; then
                finduser=$(powershell.exe /c "[System.Environment]::UserName")
                user=$(echo "$finduser" | tr -d '\r')
                dl_dirs="/mnt/c/Users/${user}/Downloads"
                echo "Preparing..."
                wget -O -q --show-progress $dl_dirs/$filename $OPTARG
            elif [[ $system == 'linux' ]]; then
                user=$(whoami)
                dl_dirs="/home/${user}/Downloads"
                echo "Preparing..."
                wget -O -q --show-progress $dl_dirs/$filename $OPTARG
            else
                echo $not_support
                return 1
            fi
            ;;
        \?)
            echo "Invalid option $OPTARG" >&2
            break
            ;;
        :)
            echo "Option $OPTARG requires an URL" >&2
            break
            ;;
        esac
    done
    if [[ $# -eq 1 && $# != 'p' ]]; then
        echo "Preparing..."
        wget -q --show-progress $1
        return 1
    elif [[ $# -eq 0 ]]; then
        usage
        return 1
    fi
}

function cv() {
    if [[ ! $(which convert &>/dev/null) || ! $(which ffmpeg &>/dev/null) ]]; then
        echo "Dependency for converter not found. Installing now..."
        install imagemagick ffmpeg -y
        return 1
    fi
    function usage() {
        echo "Usage  : cv <following>"
        return 1
    }

    function video() {
        PS3="Select video: "
        select filename in $(ls | grep -E ".(avi|mp4|mkv|flv|wmv|mov|3gp)$" | sed 's/ /\\ /g' | xargs -I{} echo {}); do
            low=false
            high=false
            best=false
            PS3="Select quality: "
            select quality in Low Best High; do
                case $quality in
                Low)
                    low=true
                    break
                    ;;
                Best)
                    best=true
                    break
                    ;;
                High)
                    high=true
                    break
                    ;;
                *) echo "Invalid option. Try again!" ;;
                esac
            done
            PS3="Select Target: "
            select ext in mkv mp4 h265 avi mov flv wmv webm 3gp; do
                if [[ $ext == 'mkv' ]]; then
                    if $low; then
                        ffmpeg -i $filename -c:v libx264 -crf 28 -preset ultrafast -c:a copy "${filename%.*}-[x264].mkv"
                    elif $best; then
                        ffmpeg -i $filename -c:v libx264 -crf 23 -preset fast -c:a copy "${filename%.*}-[x264].mkv"
                    elif $high; then
                        ffmpeg -i $filename -c:v libx264 -crf 18 -preset slower -c:a copy "${filename%.*}-[x264].mkv"
                    fi
                    echo "[*] Success convert $filename to $ext"
                    break
                elif [[ $ext == 'mp4' ]]; then
                    if $low; then
                        ffmpeg -i $filename -c:v libx264 -preset veryfast -crf 28 -c:a aac -b:a 128k "${filename%.*}-[x264].mp4"
                    elif $best; then
                        ffmpeg -i $filename -c:v libx264 -preset veryfast -crf 23 -c:a aac -b:a 192k "${filename%.*}-[x264].mp4"
                    elif $high; then
                        ffmpeg -i $filename -c:v libx264 -preset veryfast -crf 18 -c:a aac -b:a 256k "${filename%.*}-[x264].mp4"
                    fi
                    echo "[*] Success convert $filename to $ext"
                    break
                elif [[ $ext == 'h265' ]]; then
                    if $low; then
                        ffmpeg -i $filename -c:v libx265 -preset ultrafast -x265-params crf=28 -c:a libopus -b:a 128k "${filename%.*}-[x264].mp4"
                    elif $best; then
                        ffmpeg -i $filename -c:v libx265 -preset fast -x265-params crf=23 -c:a copy -c:a libopus -b:a 192k "${filename%.*}-[x264].mp4"
                    elif $high; then
                        ffmpeg -i $filename -c:v libx265 -preset medium -x265-params crf=18 -c:a copy "${filename%.*}-[x264].mp4"
                    fi
                    echo "[*] Success convert $filename to $ext"
                    break
                elif [[ $ext == 'avi' ]]; then
                    echo "Comming soon"
                    return 1
                elif [[ $ext == 'mov' ]]; then
                    echo "Comming soon"
                    return 1
                elif [[ $ext == 'flv' ]]; then
                    echo "Comming soon"
                    return 1
                elif [[ $ext == 'wmv' ]]; then
                    echo "Comming soon"
                    return 1
                elif [[ $ext == 'webm' ]]; then
                    echo "Comming soon"
                    return 1
                elif [[ $ext == '3gp' ]]; then
                    echo "Comming soon"
                    return 1
                fi
                break
            done
            break
        done
    }
    function audio() {
        echo "Comming soon"
    }
    function image() {
        echo "Comming soon"
    }
    function document() {
        echo "Comming soon"
    }
    PS3="Select type: "
    select type in Video Audio Image Document; do
        case $type in
        Video)
            video
            break
            ;;
        Audio)
            audio
            break
            ;;
        Image)
            image
            break
            ;;
        Document)
            document
            break
            ;;
        *)
            usage
            break
            ;;
        esac
    done
}

########################### END REGULAR ###########################

function kl() {
    function usage() {
        echo "Usage: kl <program>"
        return 1
    }
    if [[ $# -eq 0 ]]; then
        usage
    fi
    kill $(ps -e | grep $1 | awk '{print $1}')
}

function ca() {
    if [ -f $HOME/.aliases ]; then
        rm $HOME/.aliases && nano $HOME/.aliases && exec zsh
    else
        nano $HOME/.aliases && exec zsh
    fi
}

function troubleshoot() {
    local action=("ping")
    PS3="What do you want to solve? "
    select opt in "${action[@]}"; do
        case $opt in
        ping)
            if [[ $system == "windows" ]]; then
                sudo setcap cap_net_raw+p /bin/ping
                echo "Success fix ping permission"
            else
                echo "$not_support"
                return 1
            fi
            break
            ;;
        esac
    done
}

function ah() {
    function usage() {
        echo "Usage: ah <option>"
        echo ""
        echo "Options:"
        echo "------------------------------------------------"
        echo "    -H    Show helper with simpler command"
        echo "    -h    Show this help message"
        echo "    -i    Show ip manager helper"
        echo "    -p    Show package manager helper"
        echo "    -P    Show proxy manager helper"
        return 1
    }
    package_Manager() {
        echo "Usage: ah <option>"
        echo ""
        echo "Default command can used:"
        echo "------------------------------------------------"
        if [[ $pm == 'pacman' ]]; then
            echo "  aurs                       AUR Arch Linux"
        fi
        echo "    cpkg | checkpkg            Check package"
        echo "    d | detail                 Detail package"
        echo "    hpkg | holdpkg             Hold package"
        echo "    i | install                Install package"
        echo "    lpkg | listpkg             List of package"
        echo "    r | remove                 Remove package"
        echo "    ri | reinstall             Reinstall package"
        echo "    ro | orphan                Remove orphan package"
        echo "    s | search                 Search package"
        echo "    u | update                 Update package"
        echo "    uu | upgrade               Upgrade package"
        echo "    uuu | updateandupgrade     Update and upgrade package"
        return 1
    }

    proxy_Manager() {
        echo "Usage: ah <option>"
        echo ""
        echo "Default command can used:"
        echo "------------------------------------------------"
        echo "    proh                       Proxy hotshare"
        echo "    prohc                      Proxy http-custom"
        echo "    prohi                      Proxy http-injector"
        echo "    pror                       Proxy reset"
        echo "    pros                       Proxy socks"
        echo "    prosc                      Proxy custom"
        echo "    proxy                      Regular proxy command"
        return 1
    }
    helper_Manager() {
        echo "Usage: ah <option>"
        echo ""
        echo "Default command can used:"
        echo "------------------------------------------------"
        echo "    ca                         Change Alias"
        echo "    cfs | cloudfile            Local to internet"
        echo "    cv                         Convert all media <video>, <image>, <audio>, <document>"
        echo "    dl | download              Download with simple command"
        echo "    giit                       GIT Program make it simple"
        echo "    rz                         Restart zsh"
        echo "    sctl                       Service of system"
        echo "    kali                       Kali Nethunter manager"
        echo "    ts | troubleshoot          Fixing Manager"
        if [[ $system == 'termux' ]]; then
            echo "    troot                      Termux using proot"
        fi
        return 1
    }
    ip_Manager() {
        echo "Usage: ah <option>"
        echo ""
        echo "Default command can used:"
        echo "------------------------------------------------"
        echo "    cf | cloudflare            Cloudflare operation"
        echo "    myip                       Check my ip"
        echo "    netch                      Change IP and DNS local"
        echo "    sc                         Connect SSH with database"
        if [[ $system != 'termux' ]]; then
            echo "    redns                      Flush DNS"
        fi
        return 1
    }
    while getopts "iPpHh" opt; do
        case $opt in
        i)
            ip_Manager
            break
            ;;
        P)
            proxy_Manager
            break
            ;;
        p)
            package_Manager
            break
            ;;
        H)
            helper_Manager
            break
            ;;
        h | *)
            usage
            break
            ;;
        \? | :)
            echo "Invalid option" >&2
            usage
            break
            return 1
            ;;
        esac
    done
    if [[ $# -eq 0 ]]; then
        usage
        return 1
    fi

}

# Package Manager
alias i="install"
alias u="update"
alias uu="upgrade"
alias r="remove"
alias s="search"
alias ro="orphan"
alias ri="reinstall"
alias uuu="updateandupgrade"
alias d="detail"
alias cpkg="checkpkg"
alias lpkg="listpkg"
alias hpkg="holdpkg"

# Tools
alias cf="cloudflare"
alias cfs="cloudfile"
alias dl="download"
alias mon="monitoring"
alias ts="troubleshoot"

# Regular
alias e="exit"
alias c="clear"
alias v="nvim"
alias p="ping"
alias ijin="chmod +x"
alias suser="sudo chmod u+s"
alias unv="rm ~/.config/nvim/init.vim && nano ~/.config/nvim/init.vim"
alias vz="vim ~/.zshrc"
alias vv="vim ~/.vimrc"
alias rz="exec zsh"
alias l="ls --color=auto"
alias la="ls -la --color=auto"
alias ll="ls -l --color=auto"

# Proxy
alias prosc="proxy socks-custom"
alias proh="proxy hotshare"
alias prohi="proxy http-injector"
alias prohc="proxy http-custom"
alias pros="proxy socks"
alias pror="proxy reset"
