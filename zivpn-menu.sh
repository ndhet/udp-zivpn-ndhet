#!/bin/bash
set +e
# ZIVPN Menu - COLOR UI (MULTI USER)
# READY FOR SELLING | NO AUTO BLOCK

CONFIG="/etc/zivpn/config.json"
DB="/etc/zivpn/users.db"
DOMAIN_FILE="/etc/zivpn/domain.conf"

mkdir -p /etc/zivpn
touch "$DB"
[ ! -f "$DOMAIN_FILE" ] && echo "-" > "$DOMAIN_FILE"

DOMAIN=$(cat "$DOMAIN_FILE")

# ===== TELEGRAM FILE =====
TG_FILE="/etc/zivpn/telegram.conf"

# load telegram config jika ada
if [ -f "$TG_FILE" ]; then
  source "$TG_FILE"
fi

# ===== ENSURE JQ =====
if ! command -v jq >/dev/null 2>&1; then
  apt update -y >/dev/null 2>&1
  apt install -y jq >/dev/null 2>&1
fi

# ===== ENSURE ZIP & UNZIP =====
if ! command -v zip >/dev/null 2>&1; then
  apt install -y zip >/dev/null 2>&1
fi

if ! command -v unzip >/dev/null 2>&1; then
  apt install -y unzip >/dev/null 2>&1
fi

# ===== COLORS =====
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# ===== SYSTEM INFO =====
OS=$(lsb_release -ds 2>/dev/null | tr -d '"')
IP=$(curl -s ifconfig.me)
UPTIME=$(uptime -p)
CPU=$(nproc)
RAM_USED=$(free -m | awk '/Mem:/ {print $3}')
RAM_TOTAL=$(free -m | awk '/Mem:/ {print $2}')
DISK_USED=$(df -h / | awk 'NR==2 {print $3}')
DISK_TOTAL=$(df -h / | awk 'NR==2 {print $2}')
ZIVPN_STATUS=$(systemctl is-active zivpn 2>/dev/null)

menu() {
  USER_COUNT=$(grep -c '|' "$DB" 2>/dev/null)
  ZIVPN_STATUS=$(systemctl is-active zivpn 2>/dev/null)

  clear
  echo -e "${CYAN}══════════════════════════════════════${NC}"
  echo -e "${WHITE}        Z I V P N   SWEATER PINK ${NC}"
  echo -e "${CYAN}══════════════════════════════════════${NC}"
  echo -e "${GREEN} OS      ${NC}: $OS"
  echo -e "${GREEN} Domain  ${NC}: ${YELLOW}$DOMAIN${NC}"
  echo -e "${GREEN} IP      ${NC}: $IP"
  echo -e "${GREEN} Uptime  ${NC}: $UPTIME"
  echo -e "${GREEN} CPU     ${NC}: $CPU Cores"
  echo -e "${GREEN} RAM     ${NC}: $RAM_USED / $RAM_TOTAL MB"
  echo -e "${GREEN} Disk    ${NC}: $DISK_USED / $DISK_TOTAL"
  echo -e "${GREEN} ZIVPN   ${NC}: ${YELLOW}$ZIVPN_STATUS${NC}"
  echo -e "${GREEN} Users   ${NC}: ${YELLOW}$USER_COUNT${NC}"
  echo -e "${CYAN}══════════════════════════════════════${NC}"
  echo -e "${YELLOW} 1${NC}) Create Account"
  echo -e "${YELLOW} 2${NC}) List Accounts"
  echo -e "${YELLOW} 3${NC}) Delete Account (Number / Password)"
  echo -e "${YELLOW} 4${NC}) Renew Account"
  echo -e "${YELLOW} 5${NC}) Restart ZIVPN"
  echo -e "${YELLOW} 6${NC}) Delete All Expired Accounts"
  echo -e "${YELLOW} 7${NC}) Check User Usage (IP Monitor)"
  echo -e "${YELLOW} 8${NC}) Change Domain"
  echo -e "${YELLOW} 9${NC}) Update Menu"
  echo -e "${YELLOW}10${NC}) Create Trial (Minutes)"
  echo -e "${YELLOW}11${NC}) Telegram Bot Setting"
  echo -e "${YELLOW}12${NC}) Backup & Restore (Google Drive)"
  echo -e "${YELLOW}13${NC}) Generate API Key"
  echo -e "${YELLOW}14${NC}) View API Key"
  echo -e "${RED} 0${NC}) Exit"
  echo -e "${CYAN}══════════════════════════════════════${NC}"
  read -rp " Select Menu : " opt
}


list_accounts() {
clear
echo "--------------------------------------------------------------------------"
printf "%-4s %-15s %-18s %-16s %-8s\n" "No" "Username" "Password" "Expired" "Limit"
echo "--------------------------------------------------------------------------"
nl -w2 -s'. ' "$DB" | while read -r n l; do
  IFS='|' read -r U P E L <<< "$l"
  [ -z "$L" ] && L="∞"
  printf "%-4s %-15s %-18s %-16s %-8s\n" "$n" "$U" "$P" "$E" "$L"
done
echo "--------------------------------------------------------------------------"
}

create_account() {

# ===== CEK USERNAME UNIK =====
while true; do
  read -rp " Username : " USER

  # validasi kosong
  [ -z "$USER" ] && echo "Username tidak boleh kosong!" && continue

  # cek apakah username sudah ada di DB
  if grep -q "^$USER|" "$DB"; then
    echo "❌ Username '$USER' sudah ada, gunakan username lain!"
    continue
  fi

  break
done

read -rp " Duration (days) : " DAYS
read -rp " IP Limit (1/2/3, 0=unlimit) : " LIMIT
[ "$LIMIT" = "0" ] && LIMIT="∞"

PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
EXP=$(date -d "$DAYS days +1 day" +"%Y-%m-%d 00:00")

# simpan ke config & DB
jq --arg pass "$PASS" '.auth.config += [$pass]' "$CONFIG" > /tmp/z.json && mv /tmp/z.json "$CONFIG"
echo "$USER|$PASS|$EXP|$LIMIT" >> "$DB"

systemctl restart zivpn

# ===== TELEGRAM NOTIFICATION =====
send_telegram "📢 *_PEMBELIAN BERHASIL_*
────────────────────
🌐 Domain        : $DOMAIN
👤 Username      : $USER
🔐 Password      : $PASS
⏳ Expired       : $EXP
📆 Aktif Selama  : $DAYS Hari
📱 IP Limit      : $LIMIT
────────────────────
✅ Type          : HARIAN"

clear
echo -e "${GREEN}ACCOUNT CREATED${NC}"
echo " Domain        : $DOMAIN"
echo " Username      : $USER"
echo " Password      : $PASS"
echo " Expired       : $EXP"
echo " Aktif Selama  : $DAYS Hari"
echo " IP Limit      : $LIMIT"
read -p "Press Enter..."
}


create_trial() {
read -rp " Trial duration (minutes): " MIN
[[ -z "$MIN" || "$MIN" -le 0 ]] && return

USER="trial$(tr -dc 0-9 </dev/urandom | head -c 4)"
PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 12)
EXP=$(date -d "+$MIN minutes" +"%Y-%m-%d %H:%M")
LIMIT=1

jq --arg pass "$PASS" '.auth.config += [$pass]' "$CONFIG" > /tmp/z.json && mv /tmp/z.json "$CONFIG"
echo "$USER|$PASS|$EXP|$LIMIT" >> "$DB"
systemctl restart zivpn

# ===== TELEGRAM NOTIFICATION =====
send_telegram "⏱ *ZIVPN TRIAL ACCOUNT*
────────────────────
🌐 Domain   : $DOMAIN
👤 Username : $USER
🔐 Password : $PASS
⏳ Expired  : $EXP
📱 IP Limit : 1
────────────────────
⚡ Type     : TRIAL (${MIN} Minutes)"

clear
echo -e "${GREEN}TRIAL CREATED${NC}"
echo " Domain   : $DOMAIN"
echo " Username : $USER"
echo " Password : $PASS"
echo " Expired  : $EXP"
echo " Limit IP : 1"
read -p "Press Enter..."
}

change_domain() {
read -rp " New Domain : " NEWDOMAIN
[ -z "$NEWDOMAIN" ] && return
echo "$NEWDOMAIN" > "$DOMAIN_FILE"

openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
-subj "/C=ID/ST=VPN/L=ZIVPN/O=ZIVPN/OU=ZIVPN/CN=$NEWDOMAIN" \
-keyout /etc/zivpn/zivpn.key \
-out /etc/zivpn/zivpn.crt 2>/dev/null

systemctl restart zivpn
DOMAIN="$NEWDOMAIN"
echo -e "${GREEN}Domain updated successfully${NC}"
sleep 2
}

ip_monitor() {
clear
echo "USER USAGE MONITOR"
echo "--------------------------------------------------"
printf "%-10s %-18s %-8s %-10s\n" "Username" "Password" "Limit" "Status"
echo "--------------------------------------------------"

# hitung total IP aktif server
TOTAL_IP=$(ss -u -n state connected '( sport = :5667 )' | wc -l)

while IFS='|' read -r U P E L; do
  [ -z "$L" ] && L="∞"

  # cek apakah ADA koneksi UDP sama sekali
  if [ "$TOTAL_IP" -gt 0 ]; then
    STATUS="ONLINE"
  else
    STATUS="OFFLINE"
  fi

  printf "%-10s %-18s %-8s %-10s\n" "$U" "$P" "$L" "$STATUS"
done < "$DB"

echo "--------------------------------------------------"
echo "Total IP Active (Server): $TOTAL_IP"
read -p "Press Enter..."
}

renew_account() {
list_accounts
echo
read -rp " Renew account number : " NUM
read -rp " Extend days : " DAYS

LINE=$(sed -n "${NUM}p" "$DB")
[ -z "$LINE" ] && echo "Invalid number" && sleep 2 && return

IFS='|' read -r U P E L <<< "$LINE"

# jika expired pakai jam, buang jam
BASE_DATE=$(echo "$E" | cut -d' ' -f1)
NEWEXP=$(date -d "$BASE_DATE +$DAYS days +1 day" +"%Y-%m-%d 00:00")

sed -i "${NUM}c\\$U|$P|$NEWEXP|$L" "$DB"
systemctl restart zivpn

echo -e "${GREEN}Account renewed successfully${NC}"
sleep 2
}

delete_all_expired() {
NOW=$(date +"%Y-%m-%d %H:%M")
TMP="/tmp/zivpn-clean.db"
> "$TMP"

while IFS='|' read -r U P E L; do
  if [[ "$E" < "$NOW" ]]; then
    jq --arg pass "$P" '.auth.config -= [$pass]' "$CONFIG" > /tmp/z.json && mv /tmp/z.json "$CONFIG"
  else
    echo "$U|$P|$E|$L" >> "$TMP"
  fi
done < "$DB"

mv "$TMP" "$DB"
systemctl restart zivpn

echo -e "${GREEN}Expired accounts deleted${NC}"
sleep 2
}

restart_zivpn() {
systemctl restart zivpn
echo -e "${GREEN}ZIVPN restarted successfully${NC}"
sleep 2
}

delete_account() {
list_accounts
echo
echo "DELETE ACCOUNT"
echo "--------------------------------------------------"
echo "• Input NUMBER (1,2,3)"
echo "• Atau input PASSWORD langsung"
echo "--------------------------------------------------"
read -rp " Input : " INPUT

# delete by number
if [[ "$INPUT" =~ ^[0-9]+$ ]]; then
  LINE=$(sed -n "${INPUT}p" "$DB")
  [ -z "$LINE" ] && echo "Invalid number" && sleep 2 && return
  PASS=$(echo "$LINE" | awk -F'|' '{print $2}')
  sed -i "${INPUT}d" "$DB"

# delete by password (AMAN)
else
  PASS="$INPUT"
  LINE_NUM=$(awk -F'|' -v p="$PASS" '$2==p {print NR}' "$DB")

  [ -z "$LINE_NUM" ] && echo "Password not found" && sleep 2 && return
  sed -i "${LINE_NUM}d" "$DB"
fi

# hapus dari config zivpn
jq --arg pass "$PASS" '.auth.config -= [$pass]' "$CONFIG" > /tmp/z.json && mv /tmp/z.json "$CONFIG"

systemctl restart zivpn
echo -e "${GREEN}Account deleted successfully${NC}"
sleep 2
}

telegram_setting() {
clear
echo "===================================="
echo "   TELEGRAM BOT NOTIFICATION SETUP"
echo "===================================="
read -rp "Input Bot Token : " BOT_TOKEN
read -rp "Input Chat ID   : " CHAT_ID

if [[ -z "$BOT_TOKEN" || -z "$CHAT_ID" ]]; then
  echo "Bot Token & Chat ID tidak boleh kosong!"
  sleep 2
  return
fi

cat > "$TG_FILE" <<EOF
BOT_TOKEN="$BOT_TOKEN"
CHAT_ID="$CHAT_ID"
EOF

chmod 600 "$TG_FILE"

echo
echo "Telegram Bot berhasil disimpan!"
echo "Bot Token : $BOT_TOKEN"
echo "Chat ID   : $CHAT_ID"
sleep 2
}

send_telegram() {
[ -z "$BOT_TOKEN" ] && return
[ -z "$CHAT_ID" ] && return

TEXT="$1"
curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
  -d chat_id="$CHAT_ID" \
  --data-urlencode "text=$TEXT" \
  --data-urlencode "parse_mode=Markdown" >/dev/null 2>&1 &
}

generate_api_key() {
  clear
  echo "─── Generate API Authentication Key ───"
  API_KEY=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 6)
  KEY_FILE="/etc/zivpn/api_auth.key"
  echo "$API_KEY" > "$KEY_FILE"
  chmod 600 "$KEY_FILE"
  
  echo "New API authentication key has been generated and saved."
  echo "Key: ${API_KEY}"
  echo "Sending API key to Telegram..."
  
  MSG="🚀 API UDP ZIVPN 🚀
🔑 Auth Key: ${API_KEY}
🌐 Server IP: ${IP}
🌍 Domain: ${DOMAIN}"

  send_telegram "$MSG"

  read -p "Press Enter..."
}

view_api_key() {
  clear
  echo "─── View API Authentication Key ───"
  KEY_FILE="/etc/zivpn/api_auth.key"
  
  if [ ! -f "$KEY_FILE" ]; then
    echo "API key not found!"
    echo "Please generate API key first."
  else
    API_KEY=$(cat "$KEY_FILE")
    echo ""
    echo "API Authentication Key:"
    echo "-----------------------"
    echo "Key: ${API_KEY}"
    echo ""
    echo "File location: $KEY_FILE"
    echo "Permission : $(stat -c %a "$KEY_FILE")"
    echo ""
  fi
  read -p "Press Enter..."
}

backup_restore_drive() {
  clear
  echo "======================================"
  echo " BACKUP & RESTORE ZIVPN"
  echo "======================================"
  echo "1) Backup sekarang"
  echo "2) Restore"
  echo "3) Aktifkan Auto Backup (03:00)"
  echo "4) Nonaktifkan Auto Backup"
  echo "5) Set Jam Auto Backup"
  echo "0) Back"
  echo "======================================"
  read -rp "Pilih: " br

  case $br in
    1) backup_zivpn_drive ;;
    2) restore_zivpn_drive ;;
    3) enable_autobackup ;;
    4) disable_autobackup ;;
    5) set_autobackup_time ;;
    0) return ;;
    *) backup_restore_drive ;;
  esac
}

enable_autobackup() {
  crontab -l 2>/dev/null | grep -v zivpn-menu > /tmp/cron.tmp
  echo "0 3 * * * /usr/bin/zivpn-menu --autobackup" >> /tmp/cron.tmp
  crontab /tmp/cron.tmp
  rm -f /tmp/cron.tmp

  echo "✅ Auto Backup diaktifkan"
  echo "⏰ Setiap hari jam 03:00 pagi"
  sleep 2
}

disable_autobackup() {
  crontab -l 2>/dev/null | grep -v zivpn-menu | crontab -
  echo "❌ Auto Backup dimatikan"
  sleep 2
}

set_autobackup_time() {
  read -rp "Masukkan JAM (0-23): " HOUR

  if ! [[ "$HOUR" =~ ^[0-9]+$ ]] || [ "$HOUR" -gt 23 ]; then
    echo "❌ Jam tidak valid"
    sleep 2
    return
  fi

  crontab -l 2>/dev/null | grep -v zivpn-menu > /tmp/cron.tmp
  echo "0 $HOUR * * * /usr/bin/zivpn-menu --autobackup" >> /tmp/cron.tmp
  crontab /tmp/cron.tmp
  rm -f /tmp/cron.tmp

  echo "✅ Auto Backup diset ke jam $HOUR:00"
  sleep 2
}


backup_zivpn_drive() {
  clear
  [ -z "$BOT_TOKEN" ] && echo "Telegram bot belum diset!" && sleep 2 && return

  DATE=$(date +%Y%m%d-%H%M)
  FILE="/root/zivpn-backup-$DATE.zip"
  REMOTE="gdrive:ZIVPN-BACKUP"

# === BUAT ZIP ===
zip -r "$FILE" \
  /etc/zivpn/users.db \
  /etc/zivpn/config.json \
  /etc/zivpn/domain.conf \
  /etc/zivpn/zivpn.crt \
  /etc/zivpn/zivpn.key \
  /root/.config/rclone/rclone.conf \
  >/dev/null 2>&1


  # === CEK RCLONE ===
DRIVE_STATUS="☁️ Drive: dilewati (belum terhubung)"

if command -v rclone >/dev/null 2>&1; then
  if rclone listremotes 2>/dev/null | grep -q "^gdrive:"; then
    rclone lsd "$REMOTE" >/dev/null 2>&1 || rclone mkdir "$REMOTE"
    rclone copy "$FILE" "$REMOTE" >/dev/null 2>&1
    DRIVE_STATUS="☁️ Drive: ZIVPN-BACKUP"
  fi
fi

  # === UPLOAD TELEGRAM ===
  TG_RESPONSE=$(curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendDocument" \
    -F chat_id="$CHAT_ID" \
    -F document=@"$FILE")

  OK=$(echo "$TG_RESPONSE" | jq -r '.ok')

  if [[ "$OK" == "true" ]]; then
    FILE_ID=$(echo "$TG_RESPONSE" | jq -r '.result.document.file_id')
    FILE_PATH=$(curl -s \
      "https://api.telegram.org/bot$BOT_TOKEN/getFile?file_id=$FILE_ID" \
      | jq -r '.result.file_path')

    MSG="✅ Backup ZIVPN selesai

📁 File: $(basename "$FILE")
$DRIVE_STATUS

🆔 File ID:
$FILE_ID

📂 File Path:
$FILE_PATH"
  else
    ERROR_DESC=$(echo "$TG_RESPONSE" | jq -r '.description')
    MSG="⚠️ Backup ZIVPN selesai

📁 File: $(basename "$FILE")
$DRIVE_STATUS

❌ Telegram upload gagal
$ERROR_DESC"
  fi

  # === KIRIM NOTIF ===
  curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
    -d chat_id="$CHAT_ID" \
    --data-urlencode "text=$MSG" >/dev/null

  rm -f "$FILE"

echo "✅ Backup selesai"
[[ "$1" != "--autobackup" ]] && read -p "Press Enter..."
}

restore_zivpn_drive() {
  clear
  echo "======================================"
  echo " RESTORE ZIVPN"
  echo "======================================"
  echo "1) Restore dari Google Drive (nama file)"
  echo "2) Restore dari Telegram (file path)"
  echo "0) Back"
  echo "======================================"
  read -rp "Pilih: " rmode

 case $rmode in
  1)
    # === CEK RCLONE DULU ===
    if ! command -v rclone >/dev/null 2>&1; then
      echo "❌ rclone tidak tersedia di VPS ini"
      echo "Restore Google Drive tidak bisa digunakan"
      sleep 2
      return
    fi

    clear
    echo "Daftar backup di Google Drive:"
    echo "----------------------------------"
    rclone ls gdrive:ZIVPN-BACKUP
    echo "----------------------------------"
    read -rp "Masukkan nama file backup: " FILE

    [ -z "$FILE" ] && echo "❌ Nama file kosong!" && sleep 2 && return

    rclone copy "gdrive:ZIVPN-BACKUP/$FILE" /root/

    if [[ ! -f "/root/$FILE" ]]; then
      echo "❌ Download gagal dari Google Drive!"
      sleep 2
      return
    fi
    ;;
  2)
    clear
    read -rp "Masukkan File Path Telegram (contoh: documents/file_18.zip): " FILE_PATH

    [ -z "$FILE_PATH" ] && echo "❌ File path kosong!" && sleep 2 && return

    FILE="/root/telegram-restore.zip"
    wget -qO "$FILE" "https://api.telegram.org/file/bot$BOT_TOKEN/$FILE_PATH"

    if [[ ! -f "$FILE" ]]; then
      echo "❌ Download dari Telegram gagal!"
      sleep 2
      return
    fi
    ;;
  0)
    return
    ;;
  *)
    restore_zivpn_drive
    ;;
  esac

  echo "🔄 Restore data..."
  unzip -o "$FILE" -d / >/dev/null 2>&1
  rm -f "$FILE"
  systemctl restart zivpn

  echo "✅ Restore selesai, ZIVPN direstart"
  read -p "Press Enter..."
}

# ===== AUTO BACKUP MODE (CRON) =====
if [[ "$1" == "--autobackup" ]]; then
  backup_zivpn_drive
  exit 0
fi


while true; do
menu
case $opt in
1) create_account ;;
2) list_accounts; read -p "Press Enter..." ;;
3) delete_account ;;
4) renew_account ;;
5) restart_zivpn ;;
6) delete_all_expired ;;
7) ip_monitor ;;
8) change_domain ;;
9)
echo "Updating ZIVPN Menu..."
TMP_FILE="/tmp/zivpn-menu-$(date +%s).sh"

curl -fsSL \
  -H "Cache-Control: no-cache" \
  -H "Pragma: no-cache" \
  "https://raw.githubusercontent.com/ndhet/udp-zivpn-ndhet/main/zivpn-menu.sh?nocache=$(date +%s)" \
  -o "$TMP_FILE"

if [ ! -s "$TMP_FILE" ]; then
  echo "❌ Update gagal! File kosong."
  sleep 2
  break
fi

chmod +x "$TMP_FILE"
mv "$TMP_FILE" /usr/bin/zivpn-menu

echo "✅ Menu berhasil di-update ke versi terbaru"
sleep 1
exec /usr/bin/zivpn-menu
;;
10) create_trial ;;
11) telegram_setting ;;
12) backup_restore_drive ;;
13) generate_api_key ;;
14) view_api_key ;;
0) exit ;;
esac
done
