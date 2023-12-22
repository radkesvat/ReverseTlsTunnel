if [ "$EUID" -ne 0 ]
  then echo "Please run as root."
  exit
fi
#echo nameserver 8.8.8.8 | sudo tee /etc/resolv.conf


if pgrep -x "RTT" > /dev/null; then
	echo "Tunnel is running!. you must stop the tunnel before update. (pkill RTT)"
	echo "update is canceled."
  exit
fi



apt-get update -y

REQUIRED_PKG="unzip"
PKG_OK=$(dpkg-query -W --showformat='${Status}\n' $REQUIRED_PKG|grep "install ok installed")
echo Checking for $REQUIRED_PKG: $PKG_OK
if [ "" = "$PKG_OK" ]; then
  echo "Setting up $REQUIRED_PKG."
  sudo apt-get --yes install $REQUIRED_PKG
fi

REQUIRED_PKG="wget"
PKG_OK=$(dpkg-query -W --showformat='${Status}\n' $REQUIRED_PKG|grep "install ok installed")
echo Checking for $REQUIRED_PKG: $PKG_OK
if [ "" = "$PKG_OK" ]; then
  echo "Setting up $REQUIRED_PKG."
  sudo apt-get --yes install $REQUIRED_PKG
fi

REQUIRED_PKG="lsof"
PKG_OK=$(dpkg-query -W --showformat='${Status}\n' $REQUIRED_PKG|grep "install ok installed")
echo Checking for $REQUIRED_PKG: $PKG_OK
if [ "" = "$PKG_OK" ]; then
  echo "Setting up $REQUIRED_PKG."
  sudo apt-get --yes install $REQUIRED_PKG
fi




printf  "\n"
printf  "\n"


echo "downloading ReverseTlsTunnel"

printf  "\n"


case $(uname -m) in
    x86_64)  URL="https://github.com/radkesvat/ReverseTlsTunnel/releases/download/V7.1/v7.1_linux_amd64.zip" ;;
    arm)     URL="https://github.com/radkesvat/ReverseTlsTunnel/releases/download/V7.1/v7.1_linux_arm64.zip" ;;
    aarch64) URL="https://github.com/radkesvat/ReverseTlsTunnel/releases/download/V7.1/v7.1_linux_arm64.zip" ;;
    
    *)   echo "Unable to determine system architecture."; exit 1 ;;

esac


wget  $URL -O v7.1_linux_amd64.zip
unzip -o v7.1_linux_amd64.zip
chmod +x RTT
rm v7.1_linux_amd64.zip

echo "finished."

printf  "\n"