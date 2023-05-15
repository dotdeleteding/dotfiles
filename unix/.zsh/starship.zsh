if [[ -f $(ls /etc/*-release) ]]; then
  _system=$(grep -oP '^ID=\K\S+' /etc/*-release)
  if [[ -n $(uname -mrs | awk '{print $2}' | sed "s/.*\-//") ]]; then
    DEVICE=""
  else
    DEVICE=""
  fi
elif [[ -f /System/Library/CoreServices/SystemVersion.plist ]]; then
  _system="macos"
  _device=$(system_profiler SPHardwareDataType | awk '/Model Name/ {print $3,$4,$5,$6,$7}')
  case $_device in
    *MacBook*)     DEVICE="";;
    *mini*)        DEVICE="󰇄";;
    *)             DEVICE="";;
  esac
elif [[ -d /data/data/com.termux/files ]]; then
  _system="termux"
  DEVICE=""
fi

case $_system in
  *kali*)                  ICON="ﴣ";;
  *arch*)                  ICON="";;
  *debian*)                ICON="";;
  *raspbian*)              ICON="";;
  *ubuntu*)                ICON="";;
  *elementary*)            ICON="";;
  *fedora*)                ICON="";;
  *coreos*)                ICON="";;
  *gentoo*)                ICON="";;
  *mageia*)                ICON="";;
  *centos*)                ICON="";;
  *opensuse*|*tumbleweed*) ICON="";;
  *sabayon*)               ICON="";;
  *slackware*)             ICON="";;
  *linuxmint*)             ICON="";;
  *alpine*)                ICON="";;
  *aosc*)                  ICON="";;
  *nixos*)                 ICON="";;
  *devuan*)                ICON="";;
  *manjaro*)               ICON="";;
  *rhel*)                  ICON="";;
  *macos*)                 ICON="";;
  *)                       ICON="";;
esac
export STARSHIP_DISTRO="$ICON"
export STARSHIP_DEVICE="$DEVICE"