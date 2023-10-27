#!/bin/bash

#colors
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
purple='\033[0;35m'
cyan='\033[0;36m'
white='\033[0;37m'
rest='\033[0m'

root_access() {
    # Check if the script is running as root
    if [ "$EUID" -ne 0 ]; then
        echo "This script requires root access. please run as root."
        exit 1
    fi
}

detect_distribution() {
    # Detect the Linux distribution
    local supported_distributions=("ubuntu" "debian" "centos" "fedora")
    
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        if [[ "${ID}" = "ubuntu" || "${ID}" = "debian" || "${ID}" = "centos" || "${ID}" = "fedora" ]]; then
            package_manager="apt-get"
            [ "${ID}" = "centos" ] && package_manager="yum"
            [ "${ID}" = "fedora" ] && package_manager="dnf"
        else
            echo "Unsupported distribution!"
            exit 1
        fi
    else
        echo "Unsupported distribution!"
        exit 1
    fi
}

check_dependencies() {
    detect_distribution

    local dependencies=("wget" "lsof" "iptables" "unzip" "gcc" "git" "curl" "tar")
    
    for dep in "${dependencies[@]}"; do
        if ! command -v "${dep}" &> /dev/null; then
            echo "${dep} is not installed. Installing..."
            sudo "${package_manager}" install "${dep}" -y
        fi
    done
}

#Check installed service
check_installed() {
    if [ -f "/etc/systemd/system/tunnel.service" ]; then
        echo "The service is already installed."
        exit 1
    fi
}

# last or custom version
install_selected_version() {
    read -p "Do you want to install the Latest version? [yes/no] default: yes): " choice

    if [[ "$choice" == "no" ]]; then
        install_rtt_custom
    else
        install_rtt
    fi
}

# Function to download and install RTT
install_rtt() {
    wget "https://raw.githubusercontent.com/radkesvat/ReverseTlsTunnel/master/scripts/install.sh" -O install.sh && chmod +x install.sh && bash install.sh
}


#custom version
install_rtt_custom() {
    if pgrep -x "RTT" > /dev/null; then
        echo "Tunnel is running! You must stop the tunnel before update. (pkill RTT)"
        echo "Update is canceled."
        exit
    fi
    # Get custom version
    read -p "Please Enter your custom version (e.g : 3.6) : " version
    apt-get update -y

    echo "Downloading ReverseTlsTunnel version : $version"

    printf "\n"

    case $(uname -m) in
        x86_64)  URL="https://github.com/radkesvat/ReverseTlsTunnel/releases/download/V$version/v${version}_linux_amd64.zip" ;;
        arm)     URL="https://github.com/radkesvat/ReverseTlsTunnel/releases/download/V$version/v${version}_linux_arm64.zip" ;;
        aarch64) URL="https://github.com/radkesvat/ReverseTlsTunnel/releases/download/V$version/v${version}_linux_arm64.zip" ;;
        *)       echo "Unable to determine system architecture."; exit 1 ;;
    esac

    wget $URL -O v${version}_linux_amd64.zip
    unzip -o v${version}_linux_amd64.zip
    chmod +x RTT
    rm v${version}_linux_amd64.zip

    echo "Finished."
}


# Function to configure arguments based on user's choice
configure_arguments() {
    read -p "Which server do you want to use? (Enter '1' for Iran(internal-server) or '2' for Kharej(external-server) ) : " server_choice
    read -p "Please Enter SNI (default : sheypoor.com): " sni
    sni=${sni:-sheypoor.com}

    if [ "$server_choice" == "2" ]; then
        read -p "Please Enter IRAN IP(internal-server) : " server_ip
        read -p "Please Enter Password (Please choose the same password on both servers): " password
        arguments="--kharej --iran-ip:$server_ip --iran-port:443 --toip:127.0.0.1 --toport:multiport --password:$password --sni:$sni --terminate:24"
    elif [ "$server_choice" == "1" ]; then
        read -p "Please Enter Password (Please choose the same password on both servers): " password
        read -p "Do you want to use fake upload? (yes/no): " use_fake_upload
        if [ "$use_fake_upload" == "yes" ]; then
            read -p "Enter upload-to-download ratio (e.g., 5 for 5:1 ratio): " upload_ratio
            upload_ratio=$((upload_ratio - 1))
            arguments="--iran --lport:23-65535 --sni:$sni --password:$password --noise:$upload_ratio --terminate:24"
        else
            arguments="--iran --lport:23-65535 --sni:$sni --password:$password --terminate:24"
        fi
    else
        echo "Invalid choice. Please enter '1' or '2'."
        exit 1
    fi
}

# Function to handle installation
install() {
    root_access
    check_dependencies
    check_installed
    install_selected_version
    # Change directory to /etc/systemd/system
    cd /etc/systemd/system

    configure_arguments

    # Create a new service file named tunnel.service
    cat <<EOL > tunnel.service
[Unit]
Description=my tunnel service

[Service]
Type=idle
User=root
WorkingDirectory=/root
ExecStart=/root/RTT $arguments
Restart=always

[Install]
WantedBy=multi-user.target
EOL

    # Reload systemctl daemon and start the service
    sudo systemctl daemon-reload
    sudo systemctl start tunnel.service
    sudo systemctl enable tunnel.service
}

check_lbinstalled() {
    if [ -f "/etc/systemd/system/lbtunnel.service" ]; then
        echo "The Load-balancer is already installed."
        exit 1
    fi
}

# Function to configure arguments2 based on user's choice
configure_arguments2() {
    read -p "Which server do you want to use? (Enter '1' for Iran(internal-server) or '2' for Kharej(external-server) ) : " server_choice
    read -p "Please Enter SNI (default : sheypoor.com): " sni
    sni=${sni:-sheypoor.com}

    if [ "$server_choice" == "2" ]; then
        read -p "Is this your main server (VPN server)? (yes/no): " is_main_server
        read -p "Please Enter IRAN IP(internal-server) : " server_ip
        read -p "Please Enter Password (Please choose the same password on both servers): " password

        if [ "$is_main_server" == "yes" ]; then
            arguments="--kharej --iran-ip:$server_ip --iran-port:443 --toip:127.0.0.1 --toport:multiport --password:$password --sni:$sni --terminate:24"
        elif [ "$is_main_server" == "no" ]; then
            read -p "Enter your main IP (VPN Server):  " main_ip
            arguments="--kharej --iran-ip:$server_ip --iran-port:443 --toip:$main_ip --toport:multiport --password:$password --sni:$sni --terminate:24"
        else
            echo "Invalid choice for main server. Please enter 'yes' or 'no'."
            exit 1
        fi

    elif [ "$server_choice" == "1" ]; then
        read -p "Please Enter Password (Please choose the same password on both servers): " password
        read -p "Do you want to use fake upload? (yes/no): " use_fake_upload
        if [ "$use_fake_upload" == "yes" ]; then
            read -p "Enter upload-to-download ratio (e.g., 5 for 5:1 ratio): " upload_ratio
            upload_ratio=$((upload_ratio - 1))
            arguments="--iran --lport:23-65535 --password:$password --sni:$sni --noise:$upload_ratio --terminate:24"
        else
            arguments="--iran --lport:23-65535 --password:$password --sni:$sni --terminate:24"
        fi
        
        num_ips=0
        while true; do
            ((num_ips++))
            read -p "Please enter ip server $num_ips (or type 'done' to finish): " ip

            if [ "$ip" == "done" ]; then
                break
            else
                arguments="$arguments --peer:$ip"
            fi
        done
    else
        echo "Invalid choice. Please enter '1' or '2'."
        exit 1
    fi

    echo "Configured arguments: $arguments"
}

load-balancer() {
    root_access
    check_dependencies
    check_lbinstalled
    install_selected_version
    # Change directory to /etc/systemd/system
    cd /etc/systemd/system
    configure_arguments2
    # Create a new service file named tunnel.service
    cat <<EOL > lbtunnel.service
[Unit]
Description=my lbtunnel service

[Service]
Type=idle
User=root
WorkingDirectory=/root
ExecStart=/root/RTT $arguments
Restart=always

[Install]
WantedBy=multi-user.target
EOL

    # Reload systemctl daemon and start the service
    sudo systemctl daemon-reload
    sudo systemctl start lbtunnel.service
    sudo systemctl enable lbtunnel.service
}

lb_uninstall() {
    # Check if the service is installed
    if [ ! -f "/etc/systemd/system/lbtunnel.service" ]; then
        echo "The Load-balancer is not installed."
        return
    fi

    # Stop and disable the service
    sudo systemctl stop lbtunnel.service
    sudo systemctl disable lbtunnel.service

    # Remove service file
    sudo rm /etc/systemd/system/lbtunnel.service
    sudo systemctl reset-failed
    sudo rm RTT
    sudo rm install.sh 2>/dev/null

    echo "Uninstallation completed successfully."
}

# Function to handle uninstallation
uninstall() {
    # Check if the service is installed
    if [ ! -f "/etc/systemd/system/tunnel.service" ]; then
        echo "The service is not installed."
        return
    fi

    # Stop and disable the service
    sudo systemctl stop tunnel.service
    sudo systemctl disable tunnel.service

    # Remove service file
    sudo rm /etc/systemd/system/tunnel.service
    sudo systemctl reset-failed
    sudo rm RTT
    sudo rm install.sh 2>/dev/null

    echo "Uninstallation completed successfully."
}

update_services() {
    # Get the current installed version of RTT
    installed_version=$(./RTT -v 2>&1 | grep -o '"[0-9.]*"')

    # Fetch the latest version from GitHub releases
    latest_version=$(curl -s https://api.github.com/repos/radkesvat/ReverseTlsTunnel/releases/latest | grep -o '"tag_name": "[^"]*"' | cut -d":" -f2 | sed 's/["V ]//g' | sed 's/^/"/;s/$/"/')

    # Compare the installed version with the latest version
    if [[ "$latest_version" > "$installed_version" ]]; then
        echo "Updating to $latest_version (Installed: $installed_version)..."
        
        if sudo systemctl is-active --quiet tunnel.service; then
            echo "tunnel.service is active, stopping..."
            sudo systemctl stop tunnel.service > /dev/null 2>&1
        elif sudo systemctl is-active --quiet lbtunnel.service; then
            echo "lbtunnel.service is active, stopping..."
            sudo systemctl stop lbtunnel.service > /dev/null 2>&1
        fi

        # Download and run the installation script
        wget "https://raw.githubusercontent.com/radkesvat/ReverseTlsTunnel/master/scripts/install.sh" -O install.sh && chmod +x install.sh && bash install.sh

        # Start the previously active service
        if sudo systemctl list-units --type=service --all | grep -q 'tunnel.service'; then
            echo "Starting tunnel.service..."
            sudo systemctl start tunnel.service
        fi

        if sudo systemctl list-units --type=service --all | grep -q 'lbtunnel.service'; then
            echo "Starting lbtunnel.service..."
            sudo systemctl start lbtunnel.service
        fi

        echo "Service updated and restarted successfully."
    else
        echo "You have the latest version ($installed_version)."
    fi
}

compile() {
    detect_distribution
    check_dependencies
    # Detect the operating system
    if [[ "$OSTYPE" == "linux-gnu" ]]; then
        # Linux operating system
        if [[ "$(uname -m)" == "x86_64" ]]; then
            # 64-bit architecture
            file_url="https://github.com/nim-lang/nightlies/releases/download/latest-version-2-0/linux_x64.tar.xz"
        elif [[ "$(uname -m)" == "x86" ]]; then
            # 32-bit architecture
            file_url="https://github.com/nim-lang/nightlies/releases/download/latest-version-2-0/linux_x32.tar.xz"
        elif [[ "$(uname -m)" == "aarch64" ]]; then
            # arm64 architecture
            file_url="https://github.com/nim-lang/nightlies/releases/download/latest-version-2-0/linux_arm64.tar.xz"
        elif [[ "$(uname -m)" == "armv7l" ]]; then
            # armv7l architecture
            file_url="https://github.com/nim-lang/nightlies/releases/download/latest-version-2-0/linux_armv7l.tar.xz"
        else
            echo "Unknown architecture!"
            exit 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS operating system
        file_url="https://github.com/nim-lang/nightlies/releases/download/latest-version-2-0/macosx_x64.tar.xz"
    else
        echo "Unsupported operating system!"
        exit 1
    fi

    # Download the file based on the operating system and architecture
    wget "$file_url"
    tar -xvf "$(basename "$file_url")"

    # Add the Nim path to PATH
    export PATH="$(pwd)/nim-2.0.1/bin:$PATH"

    # Clone the project
    git clone https://github.com/radkesvat/ReverseTlsTunnel.git

    # Navigate to the project directory
    cd ReverseTlsTunnel

    # Install and compile the project
    nim install 
    nim build
    # Successful message
    echo "Project compiled successfully."
    # Display the path of the RTT file
    echo "RTT file is located at: ReverseTlsTunnel/dist"
}

# Function to start the tunnel service
start_tunnel() {
    # Check if the service is installed
    if sudo systemctl is-enabled --quiet tunnel.service; then
        # Service is installed, start it
        sudo systemctl start tunnel.service > /dev/null 2>&1

        if sudo systemctl is-active --quiet tunnel.service; then
            echo "Tunnel service started."
        else
            echo "Tunnel service failed to start."
        fi
    else
        echo "Multiport Tunnel is not installed."
    fi
}

stop_tunnel() {
    # Check if the service is installed
    if sudo systemctl is-enabled --quiet tunnel.service; then
        # Service is installed, stop it
        sudo systemctl stop tunnel.service > /dev/null 2>&1

        if sudo systemctl is-active --quiet tunnel.service; then
            echo "Tunnel service failed to stop."
        else
            echo "Tunnel service stopped."
        fi
    else
        echo "Multiport Tunnel is not installed."
    fi
}

check_tunnel_status() {
    # Check the status of the tunnel service
    if sudo systemctl is-active --quiet tunnel.service; then
        echo -e "${yellow}Multiport is: ${green}    [running ✔]${rest}"
    else
        echo -e "${yellow}Multiport is:${red}    [Not running ✗ ]${rest}"
    fi
}

# Function to start the tunnel service
start_lb_tunnel() {
    # Check if the service is installed
    if sudo systemctl is-enabled --quiet lbtunnel.service; then
        # Service is installed, start it
        sudo systemctl start lbtunnel.service > /dev/null 2>&1

        if sudo systemctl is-active --quiet lbtunnel.service; then
            echo "Tunnel service started."
        else
            echo "Tunnel service failed to start."
        fi
    else
        echo "Load-Balancer is not installed."
    fi
}


stop_lb_tunnel() {
    # Check if the service is installed
    if sudo systemctl is-enabled --quiet lbtunnel.service; then
        # Service is installed, stop it
        sudo systemctl stop lbtunnel.service > /dev/null 2>&1

        if sudo systemctl is-active --quiet lbtunnel.service; then
            echo "Load-Balancer failed to stop."
        else
            echo "Load-Balancer stopped."
        fi
    else
        echo "Load-Balancer is not installed."
    fi
}

check_lb_tunnel_status() {
    # Check the status of the load balancer tunnel service
    if sudo systemctl is-active --quiet lbtunnel.service; then
        echo -e "${yellow}Load balancer is: ${green}[running ✔]${rest}"
    else
        echo -e "${yellow}Load balancer is:${red}[Not running ✗ ]${rest}"
    fi
}

check_c_installed() {
    if [ -f "/etc/systemd/system/custom_tunnel.service" ]; then
        echo "The Custom Tunnel is already installed."
        exit 1
    fi
}

# Function to start the custom tunnel service
start_c_tunnel() {
    # Check if the service is installed
    if sudo systemctl is-enabled --quiet custom_tunnel.service; then
    
        sudo systemctl start custom_tunnel.service > /dev/null 2>&1

        if sudo systemctl is-active --quiet custom_tunnel.service; then
            echo "Custom Tunnel started."
        else
            echo "Custom Tunnel failed to start."
        fi
    else
        echo "Custom Tunnel is not installed."
    fi
}

check_c_tunnel_status() {
    # Check the status of the load balancer tunnel service
    if sudo systemctl is-active --quiet custom_tunnel.service; then
        echo -e "${yellow}Custom Tunnel is: ${green}[running ✔]${rest}"
    else
        echo -e "${yellow}Custom Tunnel is:${red}[Not running ✗ ]${rest}"
    fi
}


stop_c_tunnel() {
    # Check if the service is installed
    if sudo systemctl is-enabled --quiet custom_tunnel.service; then
    
        sudo systemctl stop custom_tunnel.service > /dev/null 2>&1

        if sudo systemctl is-active --quiet custom_tunnel.service; then
            echo "Custom Tunnel failed to stop."
        else
            echo "Custom Tunnel stopped."
        fi
    else
        echo "Custom Tunnel is not installed."
    fi
}

install_custom() {
    root_access
    check_dependencies
    check_c_installed
    install_selected_version
    cd /etc/systemd/system
    read -p "Enter RTT arguments (Example: RTT --iran --lport:443 --sni:splus.ir --password:123): " arguments
    
    # Create the custom_tunnel.service file with user input
    cat <<EOL > custom_tunnel.service
[Unit]
Description=my custom tunnel service

[Service]
Type=idle
User=root
WorkingDirectory=/root
ExecStart=/root/$arguments
Restart=always

[Install]
WantedBy=multi-user.target
EOL

    # Reload systemctl daemon and start the service
    sudo systemctl daemon-reload
    sudo systemctl start custom_tunnel.service
    sudo systemctl enable custom_tunnel.service
}

c_uninstall() {
    # Check if the service is installed
    if [ ! -f "/etc/systemd/system/custom_tunnel.service" ]; then
        echo "The Custom Tunnel is not installed."
        return
    fi

    # Stop and disable the service
    sudo systemctl stop custom_tunnel.service
    sudo systemctl disable custom_tunnel.service

    # Remove service file
    sudo rm /etc/systemd/system/custom_tunnel.service
    sudo systemctl reset-failed
    sudo rm RTT
    sudo rm install.sh 2>/dev/null

    echo "Uninstallation completed successfully."
}

#ip  & version
myip=$(hostname -I | awk '{print $1}')
version=$(./RTT -v 2>&1 | grep -o 'version="[0-9.]*"')

# Main menu
clear
echo -e "${cyan}By --> Peyman * Github.com/Ptechgithub * ${rest}"
echo -e "Your IP is: ${cyan}($myip)${rest} "
echo -e "${yellow}******************************${rest}"
check_tunnel_status
check_lb_tunnel_status
check_c_tunnel_status
echo -e "${yellow}******************************${rest}"
echo -e " ${purple}--------#- Reverse Tls Tunnel -#--------${rest}"
echo -e "${green}1) Install (Multiport)${rest}"
echo -e "${red}2) Uninstall (Multiport)${rest}"
echo "3) Start Multiport"
echo "4) Stop Multiport"
echo "5) Check Status"
echo -e "${yellow} ----------------------------${rest}"
echo -e "${green}6) Install Load-balancer${rest}"
echo -e "${red}7) Uninstall Load-balancer${rest}"
echo "8) Start Load Balancer"
echo "9) Stop Load Balancer"
echo "10) Check status"
echo -e "${yellow} ----------------------------${rest}"
echo -e "${green}11) Install Custom${rest}"
echo -e "${red}12) Uninstall Custom${rest}"
echo "13) Start Custom"
echo "14) Stop Custom"
echo "15) Check status"
echo -e "${yellow} ----------------------------${rest}"
echo -e "${cyan}16) Update RTT${rest}"
echo -e "${cyan}17 Compile RTT${rest}"
echo "0) Exit"
echo -e "${purple} --------------${cyan}$version${purple}--------------${rest}"
read -p "Please choose: " choice

case $choice in
    1)
        install
        ;;
    2)
        uninstall
        ;;
    3)
        start_tunnel
        ;;
    4)
        stop_tunnel
        ;;
    5)
        check_tunnel_status
        ;;
    6)
        load-balancer
        ;;
    7)
        lb_uninstall
        ;;
    8)
        start_lb_tunnel
        ;;
    9)
        stop_lb_tunnel
        ;;
    10)
        check_lb_tunnel_status
        ;;
    11)
        install_custom
        ;;
    12)
        c_uninstall
        ;;
    13)
        start_c_tunnel
        ;;
    14) 
        stop_c_tunnel
        ;;
    15) 
        check_c_tunnel_status
        ;;
    16) 
        update_services
        ;;
    17)
        compile
        ;;
    0)   
        exit
        ;;
    *)
        echo "Invalid choice. Please try again."
       ;;
esac
