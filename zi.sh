#!/bin/bash
# ZIVPN UDP Installer (REBOOT SAFE, SSH SAFE, CTRL+C SAFE)
set -e

echo "======================================"
echo "        ZIVPN UDP INSTALLER"
echo "======================================"
echo

# ===== INPUT DOMAIN =====
read -rp "Input Domain (contoh: udp.domainkamu.com): " DOMAIN
if [[ -z "$DOMAIN" ]]; then
  echo "Domain tidak boleh kosong!"
  exit 1
fi

echo
echo "[1/10] Update system & dependencies"
apt-get update -y && apt-get upgrade -y
apt-get install -y curl wget jq iptables iptables-persistent dos2unix

echo "[2/10] Detect architecture"
ARCH=$(uname -m)

if [[ "$ARCH" == "x86_64" ]]; then
  BIN_URL="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"
elif [[ "$ARCH" == "aarch64" ]]; then
  BIN_URL="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-arm64"
else
  echo "Unsupported architecture: $ARCH"
  exit 1
fi

echo "[3/10] Download ZIVPN binary"
wget -O /usr/local/bin/zivpn "$BIN_URL"
chmod +x /usr/local/bin/zivpn

echo "[4/10] Setup config, domain & certificate"
mkdir -p /etc/zivpn
echo "$DOMAIN" > /etc/zivpn/domain.conf

cat > /etc/zivpn/config.json << EOF
{
  "listen": ":5667",
  "cert": "/etc/zivpn/zivpn.crt",
  "key": "/etc/zivpn/zivpn.key",
  "obfs": "zivpn",
  "auth": {
    "mode": "passwords",
    "config": ["qwerty99"]
  }
}
EOF

openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 \
-subj "/C=ID/ST=VPN/L=ZIVPN/O=ZIVPN/OU=ZIVPN/CN=$DOMAIN" \
-keyout /etc/zivpn/zivpn.key \
-out /etc/zivpn/zivpn.crt 2>/dev/null

echo "[5/10] Enable IP Forward (PERMANENT)"
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-zivpn.conf
sysctl -p /etc/sysctl.d/99-zivpn.conf

echo "[6/10] Install systemd service"
cat > /etc/systemd/system/zivpn.service << EOF
[Unit]
Description=ZIVPN UDP Server
After=network.target

[Service]
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable zivpn
systemctl restart zivpn

echo "[7/10] Setup firewall & NAT (SSH SAFE)"
IFACE=$(ip -4 route | awk '/default/ {print $5}' | head -1)

iptables -t nat -A PREROUTING -i $IFACE -p udp --dport 6000:19999 -j DNAT --to-destination :5667
iptables -t nat -A POSTROUTING -o $IFACE -j MASQUERADE
iptables -A FORWARD -p udp --dport 5667 -j ACCEPT
iptables -A FORWARD -p udp --sport 5667 -j ACCEPT
netfilter-persistent save

echo "[8/10] Install menu"
wget -O /usr/bin/zivpn-menu https://raw.githubusercontent.com/ndhet/udp-zivpn-ndhet/main/zivpn-menu.sh
dos2unix /usr/bin/zivpn-menu
chmod +x /usr/bin/zivpn-menu

cat > /usr/bin/menu << 'EOF'
#!/bin/bash
/usr/bin/zivpn-menu
EOF
chmod +x /usr/bin/menu

echo "[9/10] Auto start menu on SSH login (CTRL+C SAFE)"
cat > /etc/profile.d/zivpn-autostart.sh << 'EOF'
#!/bin/bash
if [[ -n "$SSH_CONNECTION" ]] && [[ -t 0 ]] && [[ -z "$ZIVPN_MENU_LOADED" ]]; then
  export ZIVPN_MENU_LOADED=1
  clear
  /usr/bin/zivpn-menu
fi
EOF
chmod +x /etc/profile.d/zivpn-autostart.sh

echo "[10/10] Install AUTO DELETE expired (SAFE VERSION)"

# ===== CREATE EXPIRE SCRIPT =====
cat > /usr/local/bin/zivpn-expire.sh << 'EOF'
#!/bin/bash

# ===== CRON SAFE ENV =====
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export TZ=Asia/Jakarta
export LANG=C

CONFIG="/etc/zivpn/config.json"
DB="/etc/zivpn/users.db"
LOG="/var/log/zivpn-expire.log"

NOW_TS=$(date +%s)

[ ! -f "$DB" ] && exit 0

TMP="/tmp/zivpn-clean.db"
> "$TMP"

while IFS='|' read -r USER PASS EXP LIMIT; do

  # akun harian → expired BESOK jam 00:00 (AMAN)
  if [[ "$EXP" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    EXP=$(date -d "$EXP +1 day" +"%Y-%m-%d 00:00")
  fi

  EXP_TS=$(date -d "$EXP" +%s 2>>"$LOG")

  # jika gagal parse tanggal → jangan dihapus
  if [[ -z "$EXP_TS" ]]; then
    echo "$USER|$PASS|$EXP|$LIMIT" >> "$TMP"
    continue
  fi

  if (( EXP_TS <= NOW_TS )); then
    jq --arg pass "$PASS" '.auth.config -= [$pass]' "$CONFIG" \
      > /tmp/z.json && mv /tmp/z.json "$CONFIG"
    echo "[EXPIRED] $USER $EXP" >> "$LOG"
  else
    echo "$USER|$PASS|$EXP|$LIMIT" >> "$TMP"
  fi

done < "$DB"

mv "$TMP" "$DB"

/bin/systemctl restart zivpn
EOF

# ===== PERMISSION =====
chmod 755 /usr/local/bin/zivpn-expire.sh
chown root:root /usr/local/bin/zivpn-expire.sh

# ===== LOG FILE =====
touch /var/log/zivpn-expire.log
chmod 644 /var/log/zivpn-expire.log

# ===== INSTALL CRON =====
apt-get install -y cron
timedatectl set-timezone Asia/Jakarta
systemctl enable cron
systemctl restart cron

# ===== CLEAN OLD CRON =====
crontab -l 2>/dev/null | grep -v zivpn-expire | crontab - || true
rm -f /etc/cron.d/zivpn-expire

# ===== REGISTER ROOT CRON (SETIAP 1 JAM - AMAN) =====
cat > /etc/cron.d/zivpn-expire << 'EOF'
0 * * * * root /bin/bash /usr/local/bin/zivpn-expire.sh
EOF

chmod 644 /etc/cron.d/zivpn-expire
systemctl restart cron

echo "[11/11] Install rclone (ONE TIME ONLY)"

if ! command -v rclone >/dev/null 2>&1; then
  echo "Installing rclone (fast mode)..."

  apt-get install -y unzip >/dev/null 2>&1

  TMP_DIR=$(mktemp -d)
  cd "$TMP_DIR"

  ARCH=$(uname -m)
  if [[ "$ARCH" == "x86_64" ]]; then
    RCLONE_ZIP="rclone-current-linux-amd64.zip"
  elif [[ "$ARCH" == "aarch64" ]]; then
    RCLONE_ZIP="rclone-current-linux-arm64.zip"
  else
    echo "Unsupported architecture for rclone"
    exit 1
  fi

  wget -q "https://downloads.rclone.org/$RCLONE_ZIP"
  unzip -q "$RCLONE_ZIP"

  cp rclone-*/rclone /usr/bin/rclone
  chmod +x /usr/bin/rclone

  cd /
  rm -rf "$TMP_DIR"

  echo "✅ rclone installed successfully"
else
  echo "✅ rclone already installed"
fi

echo "[12/12] Setup Auto Reboot (04:00 WIB)"

# hapus reboot lama kalau ada
rm -f /etc/cron.d/zivpn-reboot

# buat cron reboot jam 04:00
cat > /etc/cron.d/zivpn-reboot << 'EOF'
0 4 * * * root /sbin/reboot
EOF

chmod 644 /etc/cron.d/zivpn-reboot
systemctl restart cron

echo "✅ Auto reboot aktif setiap jam 04:00 pagi"


timedatectl set-timezone Asia/Jakarta

echo "[13/13] Install Node.js API"

# Check if node is installed
if ! command -v node &> /dev/null; then
    echo "Node.js not found. Installing..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    apt-get install -y nodejs
fi

mkdir -p /etc/zivpn/zivpn-api
cd /etc/zivpn/zivpn-api

cat > package.json << 'EOF'
{
  "name": "zivpn-api",
  "version": "1.0.0",
  "description": "ZIVPN Node.js REST API",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "axios": "^1.6.0"
  }
}
EOF

cat > server.js << 'EOF'
const express = require('express');
const fs = require('fs');
const { exec } = require('child_process');
const axios = require('axios');
const app = express();
const port = 5888;

const CONFIG_FILE = '/etc/zivpn/config.json';
const DB_FILE = '/etc/zivpn/users.db';
const AUTH_KEY_FILE = '/etc/zivpn/api_auth.key';
const TELEGRAM_CONF = '/etc/zivpn/telegram.conf';

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Get system info (IP, Domain)
let SERVER_IP = '127.0.0.1';
let DOMAIN = 'localhost';

try {
    const ipFile = '/etc/zivpn/ip.txt';
    if(fs.existsSync(ipFile)) SERVER_IP = fs.readFileSync(ipFile, 'utf8').trim();
    else {
         exec('curl -s ifconfig.me', (err, stdout) => {
             if(!err && stdout) SERVER_IP = stdout.trim();
         });
    }
    
    const domainconf = '/etc/zivpn/domain.conf';
    if(fs.existsSync(domainconf)) DOMAIN = fs.readFileSync(domainconf, 'utf8').trim();
} catch(e) {}

// Helper to send Telegram notification
async function sendTelegram(message) {
    if (!fs.existsSync(TELEGRAM_CONF)) return;

    try {
        const content = fs.readFileSync(TELEGRAM_CONF, 'utf8');
        const botTokenMatch = content.match(/BOT_TOKEN="([^"]+)"/);
        const chatIdMatch = content.match(/CHAT_ID="([^"]+)"/);

        if (botTokenMatch && chatIdMatch) {
            const botToken = botTokenMatch[1];
            const chatId = chatIdMatch[1];
            
            const url = `https://api.telegram.org/bot${botToken}/sendMessage`;
            await axios.post(url, {
                chat_id: chatId,
                text: message,
                parse_mode: 'Markdown'
            });
        }
    } catch (error) {
        console.error('Failed to send Telegram notification:', error.message);
    }
}


// Middleware for authentication
app.use((req, res, next) => {
    const authKey = req.query.auth || req.body.auth;
    
    if (!fs.existsSync(AUTH_KEY_FILE)) {
        return res.status(500).json({ status: 'error', message: 'API validation key not found on server.' });
    }

    const validKey = fs.readFileSync(AUTH_KEY_FILE, 'utf8').trim();
    
    if (!authKey || authKey !== validKey) {
        return res.status(401).json({ status: 'error', message: 'Invalid authentication key.' });
    }
    
    next();
});

// Helper function to restart service
function restartService(callback) {
    exec('systemctl restart zivpn.service', (error, stdout, stderr) => {
        if (error) {
            console.error(`exec error: ${error}`);
        }
        callback();
    });
}

// Helper to update config.json
function updateConfigJson(password, action) {
    try {
        let config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
        
        if (action === 'add') {
             if (!config.auth.config.includes(password)) {
                config.auth.config.push(password);
            }
        } else if (action === 'remove') {
            config.auth.config = config.auth.config.filter(p => p !== password);
        }
        
        fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
        return true;
    } catch (err) {
        console.error("Error updating config.json:", err);
        return false;
    }
}

// 1. Create Account
app.all('/create/zivpn', async (req, res) => {
    const username = req.query.username || req.body.username;
    const days = req.query.exp || req.body.exp;
    let limit = req.query.ip_limit || req.body.ip_limit;
    
    if (!username || !days) {
        return res.status(400).json({ status: 'error', message: 'Username and exp (days) are required.' });
    }

    if (limit === "0") limit = "∞"; // Infinite limit
    if (!limit) limit = "1"; // Default limit

    if (fs.existsSync(DB_FILE)) {
        const dbContent = fs.readFileSync(DB_FILE, 'utf8');
        const lines = dbContent.split('\n');
        for (const line of lines) {
             const parts = line.split('|');
             if (parts.length >= 1 && parts[0] === username) {
                 return res.status(400).json({ status: 'error', message: `Error: Username '${username}' already exists.` });
             }
        }
    }

    // Generate random 16 char password
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let password = '';
    for (let i = 0; i < 16; i++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + parseInt(days));
    const isoDate = expiryDate.toISOString().slice(0, 10); 
    const expString = `${isoDate} 00:00`;
    
    const newLine = `${username}|${password}|${expString}|${limit}\n`;
    
    fs.appendFileSync(DB_FILE, newLine);
    updateConfigJson(password, 'add');
    
    const msg = `📢 *_PEMBELIAN BERHASIL_*
────────────────────
🌐 Domain        : ${DOMAIN}
👤 Username      : ${username}
🔐 Password      : ${password}
⏳ Expired       : ${expString}
📆 Aktif Selama  : ${days} Hari
📱 IP Limit      : ${limit}
────────────────────
✅ Type          : HARIAN
Created via API`;

    await sendTelegram(msg);

    restartService(() => {
        res.json({
            status: 'success',
            message: `Success: Account '${username}' created, Password: ${password}, expires in ${days} days.`,
            data: {
                username: username,
                password: password,
                expiry: expString,
                ip_limit: limit
            }
        });
    });
});

// 2. Delete Account
app.all('/delete/zivpn', async (req, res) => {
    const password = req.query.password || req.body.password;

    if (!password) {
        return res.status(400).json({ status: 'error', message: 'Password is required.' });
    }

    if (!fs.existsSync(DB_FILE)) {
        return res.status(400).json({ status: 'error', message: 'Database not found.' });
    }

    let dbContent = fs.readFileSync(DB_FILE, 'utf8');
    let lines = dbContent.split('\n');
    let found = false;
    let newLines = [];

    for (const line of lines) {
        if (!line.trim()) continue;
        const parts = line.split('|');
        if (parts.length >= 2 && parts[1] === password) {
            found = true;
        } else {
            newLines.push(line);
        }
    }

    if (!found) {
        return res.status(400).json({ status: 'error', message: `Error: Password '${password}' not found.` });
    }

    fs.writeFileSync(DB_FILE, newLines.join('\n') + '\n');
    updateConfigJson(password, 'remove');
    
    const msg = `❌ *_ZIVPN ACCOUNT DELETED_*
────────────────────
🌐 Domain   : ${DOMAIN}
👤 Password : ${password}
────────────────────
Deleted via API`;

    await sendTelegram(msg);

    restartService(() => {
        res.json({
            status: 'success',
            message: `Success: Account '${password}' deleted.`
        });
    });
});

// 3. Renew Account
app.all('/renew/zivpn', async (req, res) => {
    const password = req.query.password || req.body.password;
    const days = req.query.exp || req.body.exp;

    if (!password || !days) {
        return res.status(400).json({ status: 'error', message: 'Password and exp (days) are required.' });
    }

    if (!fs.existsSync(DB_FILE)) {
        return res.status(400).json({ status: 'error', message: 'Database not found.' });
    }

    let dbContent = fs.readFileSync(DB_FILE, 'utf8');
    let lines = dbContent.split('\n');
    let found = false;
    let newLines = [];
    let newExp = '';
    let user = '';

    for (const line of lines) {
        if (!line.trim()) continue;
        const parts = line.split('|');
        if (parts.length >= 3 && parts[1] === password) {
            found = true;
            user = parts[0];
            let baseDate = new Date();
            const existingDateStr = parts[2].split(' ')[0];
            const existingDate = new Date(existingDateStr);
            
            if (!isNaN(existingDate) && existingDate > baseDate) {
                baseDate = existingDate;
            }
            
            baseDate.setDate(baseDate.getDate() + parseInt(days));
            const isoDate = baseDate.toISOString().slice(0, 10);
            newExp = `${isoDate} 00:00`;
            
            parts[2] = newExp;
            newLines.push(parts.join('|'));
        } else {
            newLines.push(line);
        }
    }

    if (!found) {
        return res.status(400).json({ status: 'error', message: `Error: Account '${password}' not found.` });
    }

    fs.writeFileSync(DB_FILE, newLines.join('\n') + '\n');
    
    const msg = `✅ *_ZIVPN RENEWED_*
────────────────────
🌐 Domain   : ${DOMAIN}
👤 Username : ${user}
🔐 Password : ${password}
⏳ New Exp  : ${newExp}
📆 Added    : ${days} Days
────────────────────
Renewed via API`;

    await sendTelegram(msg);

    restartService(() => {
        res.json({
            status: 'success',
            message: `Success: Account '${password}' renewed for ${days} days.`
        });
    });
});


// 4. Create Trial
app.all('/trial/zivpn', async (req, res) => {
    const minutes = req.query.exp || req.body.exp;

    if (!minutes) {
        return res.status(400).json({ status: 'error', message: 'Error: Invalid number of minutes.' });
    }

    const randomSuffix = Math.floor(Math.random() * 9000) + 1000;
    const user = `trial${randomSuffix}`;
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let password = '';
    for ( let i = 0; i < 12; i++ ) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    const expiryDate = new Date(new Date().getTime() + parseInt(minutes) * 60000);
    const expString = expiryDate.toISOString().replace('T', ' ').slice(0, 16);
    
    const limit = "1";
    const newLine = `${user}|${password}|${expString}|${limit}\n`;

    fs.appendFileSync(DB_FILE, newLine);
    updateConfigJson(password, 'add');
    
    const msg = `⏱ *_ZIVPN TRIAL ACCOUNT_*
────────────────────
🌐 Domain   : ${DOMAIN}
👤 Username : ${user}
🔐 Password : ${password}
⏳ Expired  : ${expString}
📱 IP Limit : 1
────────────────────
⚡ Type     : TRIAL (${minutes} Minutes)
Created via API`;

    await sendTelegram(msg);

    restartService(() => {
        res.json({
            status: 'success',
            message: `Success: Trial account '${password}' created, expires in ${minutes} minutes.`
        });
    });
});

app.listen(port, () => {
    console.log(`ZIVPN API listening at http://localhost:${port}`);
});
EOF

echo "Installing API dependencies..."
npm install

echo "Setup API Service..."
cat > /etc/systemd/system/zivpn-api.service << EOF
[Unit]
Description=ZIVPN REST API Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn/zivpn-api
ExecStart=/usr/bin/npm start
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable zivpn-api
systemctl restart zivpn-api

echo "✅ ZIVPN API Installed and Started on port 5888"

echo
echo "======================================"
echo " ZIVPN UDP INSTALLED SUCCESSFULLY"
echo " Domain : $DOMAIN"
echo " AUTO DELETE : DATE + TIME"
echo " Trial menit : AMAN"
echo " SSH LOGIN → AUTO MENU"
echo " CTRL + C → BACK TO SHELL"
echo " Manual menu : menu"
echo " API Port : 5888"
echo "======================================"
