if [[ -f $(ls /etc/*-release 2>/dev/null) ]]; then
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
  _system=""
  export USER=$(whoami)
  DEVICE=""
fi

case $_system in
  *alpine*)                ICON="";;
  *aosc*)                  ICON="";;
  *arch*)                  ICON="";;
  *centos*)                ICON="";;
  *coreos*)                ICON="";;
  *debian*)                ICON="";;
  *devuan*)                ICON="";;
  *elementary*)            ICON="";;
  *fedora*)                ICON="";;
  *gentoo*)                ICON="";;
  *kali*)                  ICON="ﴣ";;
  *linuxmint*)             ICON="";;
  *macos*)                 ICON="";;
  *mageia*)                ICON="";;
  *manjaro*)               ICON="";;
  *nixos*)                 ICON="";;
  *opensuse*|*tumbleweed*) ICON="";;
  *raspbian*)              ICON="";;
  *rhel*)                  ICON="";;
  *sabayon*)               ICON="";;
  *slackware*)             ICON="";;
  *ubuntu*)                ICON="";;
  *)                       ICON="";;
esac

export STARSHIP_DISTRO="$ICON"
export STARSHIP_DEVICE="$DEVICE"