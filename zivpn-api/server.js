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
    if (fs.existsSync(ipFile)) SERVER_IP = fs.readFileSync(ipFile, 'utf8').trim();
    else {
        exec('curl -s ifconfig.me', (err, stdout) => {
            if (!err && stdout) SERVER_IP = stdout.trim();
        });
    }

    const domainconf = '/etc/zivpn/domain.conf';
    if (fs.existsSync(domainconf)) DOMAIN = fs.readFileSync(domainconf, 'utf8').trim();
} catch (e) { }

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
    const password = req.query.password || req.body.password;
    const days = req.query.exp || req.body.exp;

    if (!password || !days) {
        return res.status(400).json({ status: 'error', message: 'Password and exp (days) are required.' });
    }

    if (fs.existsSync(DB_FILE)) {
        const dbContent = fs.readFileSync(DB_FILE, 'utf8');
        const lines = dbContent.split('\n');
        for (const line of lines) {
            const parts = line.split('|');
            if (parts.length >= 2 && parts[1] === password) {
                return res.status(400).json({ status: 'error', message: `Error: Password '${password}' already exists.` });
            }
        }
    }

    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + parseInt(days));
    const isoDate = expiryDate.toISOString().slice(0, 10);
    const expString = `${isoDate} 00:00`;

    const user = password;
    const limit = "1";

    const newLine = `${user}|${password}|${expString}|${limit}\n`;

    fs.appendFileSync(DB_FILE, newLine);
    updateConfigJson(password, 'add');

    const msg = `📢 *_PEMBELIAN BERHASIL_*
────────────────────
🌐 Domain        : ${DOMAIN}
👤 Username      : ${user}
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
            message: `Success: Account '${password}' created, expires in ${days} days.`
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
    for (let i = 0; i < 12; i++) {
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
