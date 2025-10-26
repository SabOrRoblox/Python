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
const { body, validationResult, query } = require('express-validator');

require('dotenv').config({ path: '/etc/secrets/.env' });

// Логирование
const logger = require('pino')({
  transport: {
    target: 'pino-pretty',
    options: {
      colorize: true,
      translateTime: 'SYS:standard'
    }
  }
});

// Конфигурация (хэшированные значения)
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const SECRET_KEY = process.env.SECRET_KEY;
const ADMIN_PASS_HASH = process.env.ADMIN_PASS;
const ADMIN_SESSION_KEY = process.env.ADMIN_SESSION_KEY;
const SESSION_COOKIE_NAME = process.env.sskk;
const ADMIN_GAME_HASH = process.env.ADMIN_GAME;
const WEBHOOK_URLS = process.env.WEBHOOK_URLS ? process.env.WEBHOOK_URLS.split(',') : [];

function HashData(g1) {
  return createHash('sha256').update(g1).digest('hex')
}

// Supabase клиент
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// Regex паттерны
const KEY_REGEX = /^Apex_[a-f0-9]{35}$/;
const HWID_REGEX = /^[0-9A-Fa-f-]{5,}$/;

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
  contentSecurityPolicy: true // Отключаем CSP для упрощения
}));

app.use(cors({
  origin: ["https://www.roblox.com", "https://*.robloxlabs.com"],
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  name: SESSION_COOKIE_NAME || 'session',
  secret: ADMIN_SESSION_KEY || 'fallback-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Поставь true в продакшене
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000
  }
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: 'Too many requests',
  handler: (req, res) => {
    logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({ error: 'Too many requests' });
  }
});

const adminLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  message: 'Too many admin requests'
});

app.use('/api/', limiter);
app.use('/user/admin', adminLimiter);

// Кэширование
const cache = new NodeCache({ stdTTL: 21600 });

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
        .catch((error) => {
          logger.error(`Webhook error for ${url}: ${error.message}`);
        })
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
      
    const files = fs.readdirSync(backupDir)  
      .filter(f => f.startsWith('backup_'))  
      .sort();  
          
    for (let i = 0; i < files.length - 10; i++) {  
      fs.unlinkSync(path.join(backupDir, files[i]));  
    }  
      
    logger.info(`Backup created: ${filename}`);  
      
  } catch (error) {  
    logger.error(`Backup error: ${error.message}`);  
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
  
  const report = {  
    date: yesterdayStr,  
    dailyUsers,  
    dailyVerifications,  
    dailyErrors,  
    apiCalls: statsData.apiCalls.get(yesterdayStr) || 0  
  };  
  
  logger.info(report, 'Daily report');
}

async function cleanupOldKeysAndUsers() {
  while (true) {
    try {
      const threshold = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

      const { data: oldKeys, error } = await supabase  
        .from('keys')  
        .select('*')  
        .lt('created_at', threshold);  
              
      if (error) {  
        logger.error(`Failed to fetch old keys: ${error.message}`);  
        await new Promise(resolve => setTimeout(resolve, 86400000));  
        continue;  
      }  
          
      for (const keyEntry of oldKeys || []) {  
        try {  
          const { error: deleteKeyError } = await supabase  
            .from('keys')  
            .delete()  
            .eq('key', keyEntry.key);  
                  
          if (!deleteKeyError) {  
            logger.info(`Deleted key ${keyEntry.key}`);  
                      
            const { error: deleteUserError } = await supabase  
              .from('users')  
              .delete()  
              .eq('key', keyEntry.key);  
                          
            if (!deleteUserError) {  
              logger.info(`Deleted users with key ${keyEntry.key}`);  
            }  
          }  
        } catch (e) {  
          logger.error(`Error deleting key: ${e.message}`);  
        }  
      }  
          
    } catch (error) {  
      logger.error(`Cleanup error: ${error.message}`);  
      updateStats('error', { error: error.message, endpoint: 'cleanup' });  
    }  
      
    await new Promise(resolve => setTimeout(resolve, 24 * 60 * 60 * 1000));  
  }
}

async function scheduledTasks() {
  while (true) {
    try {
      const now = new Date();

      if (now.getHours() === 2 && now.getMinutes() === 0) {  
        await backupDatabase();  
      }  
          
      if (now.getHours() === 9 && now.getMinutes() === 0) {  
        sendDailyReport();  
      }  
          
      await new Promise(resolve => setTimeout(resolve, 60 * 1000));  
          
    } catch (error) {  
      logger.error(`Scheduled task error: ${error.message}`);  
      await new Promise(resolve => setTimeout(resolve, 5 * 60 * 1000));  
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
    logger.error(`Save key error: ${error.message}`);  
  }  
  return null;
}

// ----------------------
// Middleware для админки
// ----------------------
function requireAdmin(req, res, next) {
  // Проверяем сессию ИЛИ секретный ключ через query параметр
  if (req.session.admin_authenticated || req.query.d === SECRET_KEY) {
    return next();
  }
  
  // Если нет доступа, показываем форму логина
  if (req.method === 'GET' && !req.query.d) {
    return res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Admin Login</title>
        <style>
          body { 
            font-family: Arial; 
            background: #1a1a1a; 
            color: white; 
            display: flex; 
            justify-content: center; 
            align-items: center; 
            height: 100vh;
            margin: 0;
          }
          .login-form { 
            background: #2d2d2d; 
            padding: 30px; 
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
          }
          input { 
            padding: 12px; 
            margin: 10px 0; 
            width: 250px; 
            border: 1px solid #444;
            border-radius: 4px;
            background: #1a1a1a;
            color: white;
          }
          button { 
            padding: 12px 20px; 
            background: #007bff; 
            color: white; 
            border: none; 
            border-radius: 4px; 
            cursor: pointer;
            width: 100%;
            margin-top: 10px;
          }
          button:hover {
            background: #0056b3;
          }
          h2 {
            text-align: center;
            margin-bottom: 20px;
          }
        </style>
      </head>
      <body>
        <div class="login-form">
          <h2>Admin Login</h2>
          <form method="POST" action="/user/admin">
            <input type="password" name="passwrd" placeholder="Password" required>
            <button type="submit">Login</button>
          </form>
        </div>
      </body>
      </html>
    `);
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

// Валидаторы
const keyValidation = [
  query('key')
    .isLength({ min: 10, max: 100 })
    .matches(KEY_REGEX)
    .withMessage('Invalid key format')
];

const userValidation = [
  body('hwid')
    .isLength({ min: 5, max: 100 })
    .matches(HWID_REGEX)
    .withMessage('Invalid HWID format'),
  body('cookies')
    .optional()
    .isLength({ max: 5000 })
    .withMessage('Cookies too long'),
  body('key')
    .optional()
    .matches(KEY_REGEX)
    .withMessage('Invalid key format')
];

// ----------------------
// API Routes
// ----------------------
app.get('/api/health', async (req, res) => {
  try {
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
      active_connections: 0,  
      uptime: (Date.now() - appStartTime) / 1000  
    };  
      
    res.json(status);  
  } catch (error) {  
    logger.error(`Health check failed: ${error.message}`);  
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

app.post('/api/clean_old_keys', requireAdmin, [
  body('days').isInt({ min: 1, max: 365 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

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
        logger.error(`Error deleting key: ${e.message}`);  
      }  
    }  
      
    res.json({ deleted: deletedCount });  
  } catch (error) {  
    logger.error(`Clean old keys error: ${error.message}`);  
    res.status(500).json({ error: ERR_DB_FAIL });  
  }
});

app.get('/api/verify_key', keyValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  updateStats('api_call', { endpoint: 'verify_key' });  
  
  const key = req.query.key;  
  
  // Проверка админского ключа через хэш  
  if (key && HashData(key) === ADMIN_GAME_HASH) {  
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
    logger.error(`Verify key error: ${error.message}`);  
    res.type('text/plain').send('error');  
  }
});

app.post('/api/save_user', userValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  updateStats('api_call', { endpoint: 'save_user' });  
  
  const data = req.body || {};  
  let remote_ip = req.ip || 'unknown_ip';  
  
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
      logger.error(`Query user error: ${queryError.message}`);  
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
      logger.error(`Save user error: ${insertError.message}`);  
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
    logger.error(`Save user error: ${error.message}`);  
    res.status(500).json({ error: 'Failed to save user' });  
  }
});

// ----------------------
// Static Routes
// ----------------------
app.use(express.static(__dirname));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/style.css', (req, res) => {
  res.sendFile(path.join(__dirname, 'style.css'));
});

// ----------------------
// Admin Panel Routes
// ----------------------
app.get('/user/admin', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'ad_index.html'));
});

app.post('/user/admin', [
  body('passwrd').isLength({ min: 1 }).withMessage('Password required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).send("Invalid password");
  }

  if (req.session.admin_authenticated) {
    return res.sendFile(path.join(__dirname, 'ad_index.html'));
  }
  
  const password = req.body.passwrd;
  
  // Проверяем хэш пароля
  const hashedInput = HashData(password);
  
  if (hashedInput === ADMIN_PASS_HASH) {
    req.session.admin_authenticated = true;
    req.session.role = 'admin';
    logger.info(`Admin login from IP: ${req.ip}`);
    return res.sendFile(path.join(__dirname, 'ad_index.html'));
  } else {
    logger.warn(`Failed admin login attempt from IP: ${req.ip}`);
    return res.status(403).send("Неверный пароль!");
  }
});

// API для админ панели
app.get('/api/admin/data', requireAdmin, async (req, res) => {
  try {
    const { data: keysData, error: keysError } = await supabase
      .from('keys')
      .select('*');

    const { data: usersData, error: usersError } = await supabase  
      .from('users')  
      .select('*');  
          
    if (keysError || usersError) {  
      logger.error(`Admin panel data fetch error: ${keysError || usersError}`);  
      return res.status(500).json({ error: 'Failed to fetch data' });  
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
      
    res.json({  
      keys: keysData || [],  
      users: usersData || [],  
      stats: stats  
    });  
      
  } catch (error) {  
    logger.error(`Admin panel API error: ${error.message}`);  
    res.status(500).json({ error: 'Failed to fetch data' });  
  }
});

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

app.post('/api/delete_key', requireAdmin, [
  body('key').matches(KEY_REGEX).withMessage('Invalid key format')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const key = req.body.key;  
  
  try {  
    const { error } = await supabase  
      .from('keys')  
      .delete()  
      .eq('key', key);  
          
    if (error) {  
      return res.status(500).send(ERR_DB_FAIL);  
    }  
    logger.info(`Key deleted: ${key}`);  
    res.send('Key deleted');  
  } catch (error) {  
    logger.error(`Delete key error: ${error.message}`);  
    res.status(500).send(ERR_DB_FAIL);  
  }
});

app.post('/api/delete_user', requireAdmin, [
  body('hwid').matches(HWID_REGEX).withMessage('Invalid HWID format')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const hwid = req.body.hwid;  
  
  try {  
    const { error } = await supabase  
      .from('users')  
      .delete()  
      .eq('hwid', hwid);  
          
    if (error) {  
      return res.status(500).send(ERR_DB_FAIL);  
    }  
    logger.info(`User deleted with HWID: ${hwid}`);  
    res.send('User deleted');  
  } catch (error) {  
    logger.error(`Delete user error: ${error.message}`);  
    res.status(500).send(ERR_DB_FAIL);  
  }
});

// Выход из админки
app.post('/user/admin/logout', requireAdmin, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      logger.error('Logout error:', err);
      return res.status(500).send('Logout failed');
    }
    res.redirect('/user/admin');
  });
});

// Обработчик ошибок
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  res.status(500).send('Something broke!');
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
  logger.info(`Server running on port ${PORT}`);
  console.log(`Server is running on http://localhost:${PORT}`);
});

module.exports = app;
