const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const CryptoJS = require('crypto-js');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();

// ================= CORS跨域 =================
const allowedOrigins = [
  'http://localhost:3000',
  'capacitor://localhost',
  'http://localhost'
];
app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('不允许的跨域请求'), false);
    }
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// ================= 接口限流 =================
const globalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 60,
  message: { success: false, message: '请求过于频繁，请稍后再试' },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

const authLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 10,
  message: { success: false, message: '操作过于频繁，请1分钟后再试' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(express.static('public'));
app.use(express.json({ limit: '1mb' }));

// ================= 数据库配置 =================
const dbConfig = {
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  acquireTimeout: 10000,
  timeout: 10000
};

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const AES_KEY = process.env.AES_KEY;
const pool = mysql.createPool(dbConfig);

// ================= 激活码配置 =================
const CODE_EXPIRE_DAYS = 30;

// ================= AES加解密函数 =================
const DECODE_MAP = {
    'KA': 'a', 'KB': 'b', 'KC': 'c', 'KD': 'd', 'KE': 'e',
    'KF': 'f', 'KG': 'g', 'KH': 'h', 'KI': 'i', 'KJ': 'j',
    'KK': 'k', 'KL': 'l', 'KM': 'm', 'KN': 'n', 'KO': 'o',
    'KP': 'p', 'KQ': 'q', 'KR': 'r', 'KS': 's', 'KT': 't',
    'KU': 'u', 'KV': 'v', 'KW': 'w', 'KX': 'x', 'KY': 'y',
    'KZ': 'z', 'LA': '+', 'LB': '/', 'LC': '='
};

function aesDecrypt(encryptedText) {
  try {
    let processedText = encryptedText.replace(/-/g, '');
    for (const [key, value] of Object.entries(DECODE_MAP).sort((a, b) => b[0].length - a[0].length)) {
        processedText = processedText.split(key).join(value);
    }
    const decipher = crypto.createDecipheriv('aes-128-ecb', Buffer.from(AES_KEY, 'utf8'), null);
    decipher.setAutoPadding(true);
    let decrypted = decipher.update(processedText, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) {
    console.error('❌ 解密失败：', e.message);
    return null;
  }
}

function parseActivateCode(code) {
  const plainText = aesDecrypt(code);
  if (!plainText) {
    return { success: false, error: '激活码格式错误，解密失败' };
  }
  const parts = plainText.split('|');
  if (parts.length !== 5) {
    return { success: false, error: '激活码格式无效' };
  }
  const [userId, deviceFingerprint, days, timestamp, randomSalt] = parts;
  const generateTime = new Date(parseInt(timestamp) * 1000);
  const expireTime = new Date(generateTime.getTime() + CODE_EXPIRE_DAYS * 24 * 60 * 60 * 1000);
  if (new Date() > expireTime) {
    return { success: false, error: '激活码已过期' };
  }
  return {
    success: true,
    userId: parseInt(userId),
    deviceFingerprint,
    days: parseInt(days),
    generateTime
  };
}

// ================= 初始化数据库 =================
async function initDB() {
  const connection = await pool.getConnection();
  try {
    console.log('🔧 正在检查并更新数据库结构...');

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        is_premium BOOLEAN DEFAULT FALSE,
        premium_expiry DATETIME NULL,
        security_question VARCHAR(255) NULL,
        security_answer VARCHAR(255) NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS items (
        id VARCHAR(100) PRIMARY KEY,
        user_id INT NOT NULL,
        name VARCHAR(255) NOT NULL,
        price DECIMAL(20,2) NOT NULL,
        purchase_date BIGINT NOT NULL,
        category_name VARCHAR(100),
        icon_code INT,
        expect_use_years INT NULL,
        residual_rate DECIMAL(5,4) NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS category_mappings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        keyword VARCHAR(100) NOT NULL,
        category_name VARCHAR(100) NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE KEY unique_keyword_per_user (user_id, keyword)
      )
    `);

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS used_codes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        activate_code VARCHAR(500) NOT NULL UNIQUE,
        user_id INT NOT NULL,
        device_fingerprint VARCHAR(200) NOT NULL,
        days INT NOT NULL,
        used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    await connection.execute(`
      CREATE TABLE IF NOT EXISTS unbind_applications (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        username VARCHAR(50) NOT NULL,
        old_device_fingerprint VARCHAR(200) NOT NULL,
        new_device_fingerprint VARCHAR(200) NOT NULL,
        status TINYINT DEFAULT 0 COMMENT '0待审核 1已通过 2已拒绝',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        handle_at DATETIME NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    try {
      await connection.execute('SELECT * FROM user_checkin LIMIT 1');
      console.log('ℹ️ 打卡数据表已存在，跳过');
    } catch (e) {
      console.log('🔧 正在创建打卡数据表...');
      await connection.execute(`
        CREATE TABLE user_checkin (
          id INT AUTO_INCREMENT PRIMARY KEY,
          user_id INT NOT NULL UNIQUE,
          consecutive_check_in_days INT DEFAULT 0,
          total_check_in_days INT DEFAULT 0,
          longest_streak INT DEFAULT 0,
          re_sign_cards INT DEFAULT 0,
          last_check_in_date DATETIME NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
      `);
      console.log('✅ 打卡数据表创建成功！');
    }

    console.log('✅ 数据库结构检查完成！');
  } catch (err) {
    console.error('❌ 数据库初始化失败:', err);
  } finally {
    connection.release();
  }
}

// ================= Token验证中间件 =================
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: '请先登录' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: '登录已过期，请重新登录' });
    req.user = user;
    next();
  });
}

// ================= 错误统一处理 =================
function handleServerError(res, err, customMessage = '服务器错误') {
  console.error('❌ 服务异常:', err);
  return res.status(500).json({ success: false, message: customMessage });
}

// ================= API接口 =================
// ✅ 注册：直接存储明文密码（无加密）
app.post('/api/register', authLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, message: '用户名和密码不能为空' });
  if (username.length < 4 || username.length > 16) return res.status(400).json({ success: false, message: '用户名长度需在4-16位之间' });
  if (password.length < 8) return res.status(400).json({ success: false, message: '密码至少8位' });

  try {
    // 直接存明文密码
    await pool.execute('INSERT INTO users (username, password) VALUES (?, ?)', [username, password]);
    res.json({ success: true, message: '注册成功' });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ success: false, message: '用户名已存在' });
    return handleServerError(res, err, '注册失败，请稍后再试');
  }
});

// ✅ 登录：直接对比明文密码（无加密）
app.post('/api/login', authLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ success: false, message: '用户名和密码不能为空' });

  try {
    const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) return res.status(400).json({ success: false, message: '用户名或密码错误' });

    const user = rows[0];
    // 直接明文对比密码
    const isPasswordValid = password === user.password;
    if (!isPasswordValid) return res.status(400).json({ success: false, message: '用户名或密码错误' });

    let isPremium = user.is_premium;
    if (user.premium_expiry && new Date() > new Date(user.premium_expiry)) isPremium = false;

    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );
    res.json({
      success: true,
      token: token,
      userId: user.id,
      username: user.username,
      isPremium: !!isPremium,
      expiryDate: user.premium_expiry ? user.premium_expiry.toISOString() : null,
      securityQuestion: user.security_question
    });
  } catch (err) {
    return handleServerError(res, err, '登录失败，请稍后再试');
  }
});

// 同步数据接口（不变）
app.post('/api/sync', authenticateToken, async (req, res) => {
  const { items, mappings } = req.body;
  const userId = req.user.userId;
  const connection = await pool.getConnection();
  
  try {
    await connection.beginTransaction();
    await connection.execute('DELETE FROM items WHERE user_id = ?', [userId]);
    await connection.execute('DELETE FROM category_mappings WHERE user_id = ?', [userId]);

    if (items && Array.isArray(items) && items.length > 0) {
      for (const item of items) {
        try {
          const price = parseFloat(item.price) || 0;
          const purchaseDate = parseInt(item.purchaseDateMillis) || Date.now();
          const expectUseYears = item.expectUseYears ? parseInt(item.expectUseYears) : null;
          const residualRate = item.residualRate ? parseFloat(item.residualRate) : null;
          
          await connection.execute(
            'INSERT INTO items (id, user_id, name, price, purchase_date, category_name, icon_code, expect_use_years, residual_rate) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [item.id, userId, item.name || '未命名', price, purchaseDate, item.customCategoryName || null, item.customIconCodePoint || null, expectUseYears, residualRate]
          );
        } catch (e) { 
          console.log('跳过物品:', item.name, e.message); 
        }
      }
    }

    if (mappings && Array.isArray(mappings) && mappings.length > 0) {
      for (const m of mappings) {
        try {
          await connection.execute(
            'INSERT INTO category_mappings (user_id, keyword, category_name) VALUES (?, ?, ?)',
            [userId, m.keyword, m.categoryName]
          );
        } catch (e) { 
          console.log('跳过关键词:', m.keyword); 
        }
      }
    }

    await connection.commit();
    res.json({ success: true, message: '同步成功' });
  } catch (err) {
    await connection.rollback();
    console.error('同步失败:', err);
    res.status(500).json({ success: false, message: '同步失败' });
  } finally {
    connection.release();
  }
});

app.get('/api/sync', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  try {
    const [itemRows] = await pool.execute('SELECT * FROM items WHERE user_id = ?', [userId]);
    const [mappingRows] = await pool.execute('SELECT keyword, category_name FROM category_mappings WHERE user_id = ?', [userId]);
    const [userRows] = await pool.execute('SELECT is_premium, premium_expiry, security_question FROM users WHERE id = ?', [userId]);

    if (userRows.length === 0) {
      return res.status(400).json({
        success: false,
        message: '用户不存在，请重新登录',
        items: [],
        mappings: []
      });
    }

    res.json({
      success: true,
      items: itemRows,
      mappings: mappingRows,
      isPremium: !!userRows[0].is_premium,
      premiumExpiryDate: userRows[0].premium_expiry ? userRows[0].premium_expiry.toISOString() : null,
      securityQuestion: userRows[0].security_question
    });
  } catch (err) {
    console.error('获取数据失败：', err);
    res.status(500).json({
      success: false,
      message: '获取数据失败，服务器内部错误',
      items: [],
      mappings: []
    });
  }
});

// 激活会员（不变）
app.post('/api/pay/activate', authenticateToken, async (req, res) => {
  const { activateCode, deviceFingerprint } = req.body;
  const userId = req.user.userId;
  const connection = await pool.getConnection();

  try {
    await connection.beginTransaction();
    const codeInfo = parseActivateCode(activateCode);
    if (!codeInfo.success) {
      await connection.rollback();
      return res.status(400).json({ success: false, message: codeInfo.error });
    }

    if (codeInfo.userId !== userId) {
      await connection.rollback();
      return res.status(400).json({ success: false, message: '激活码不属于当前账号' });
    }

    const shortDeviceFingerprint = deviceFingerprint.substring(0, 16);
    if (codeInfo.deviceFingerprint !== shortDeviceFingerprint) {
      await connection.rollback();
      return res.status(400).json({ success: false, message: '激活码与当前设备不匹配' });
    }

    const [usedRows] = await connection.execute('SELECT * FROM used_codes WHERE activate_code = ?', [activateCode]);
    if (usedRows.length > 0) {
      await connection.rollback();
      return res.status(400).json({ success: false, message: '该激活码已被使用' });
    }

    const [userRows] = await pool.execute('SELECT * FROM users WHERE id = ?', [userId]);
    const user = userRows[0];
    let newExpiry = new Date();
    if (user.is_premium && user.premium_expiry && new Date(user.premium_expiry) > new Date()) {
      newExpiry = new Date(user.premium_expiry);
    }
    newExpiry.setDate(newExpiry.getDate() + codeInfo.days);

    await connection.execute(
      'UPDATE users SET is_premium = 1, premium_expiry = ? WHERE id = ?',
      [newExpiry, userId]
    );

    await connection.execute(
      'INSERT INTO used_codes (activate_code, user_id, device_fingerprint, days) VALUES (?, ?, ?, ?)',
      [activateCode, userId, deviceFingerprint, codeInfo.days]
    );

    await connection.commit();
    res.json({
      success: true,
      message: `激活成功！会员已延长${codeInfo.days}天`,
      expiryDate: newExpiry.toISOString(),
      days: codeInfo.days
    });
  } catch (err) {
    await connection.rollback();
    console.error('❌ 激活失败:', err);
    res.status(500).json({ success: false, message: '激活失败' });
  } finally {
    connection.release();
  }
});

// 设备解绑（不变）
app.post('/api/device/unbind', authenticateToken, async (req, res) => {
  const { newDeviceFingerprint } = req.body;
  const userId = req.user.userId;
  const username = req.user.username;

  try {
    const [codeRows] = await pool.execute(
      'SELECT device_fingerprint FROM used_codes WHERE user_id = ? ORDER BY used_at DESC LIMIT 1',
      [userId]
    );
    if (codeRows.length === 0) {
      return res.status(400).json({ success: false, message: '未找到设备绑定记录' });
    }
    const oldDeviceFingerprint = codeRows[0].device_fingerprint;

    await pool.execute(
      'INSERT INTO unbind_applications (user_id, username, old_device_fingerprint, new_device_fingerprint) VALUES (?, ?, ?, ?)',
      [userId, username, oldDeviceFingerprint, newDeviceFingerprint]
    );
    res.json({ success: true, message: '解绑申请已提交' });
  } catch (err) {
    return handleServerError(res, err, '提交失败，请稍后再试');
  }
});

// 管理员接口（不变）
const adminLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 20,
  message: { success: false, message: '操作过于频繁，请稍后再试' },
});
app.get('/api/admin/unbind/list', adminLimiter, async (req, res) => {
  const adminPassword = req.headers['admin-password'];
  if (!adminPassword || adminPassword !== ADMIN_PASSWORD) {
    return res.status(403).json({ success: false, message: '无权访问' });
  }
  try {
    const [rows] = await pool.execute('SELECT * FROM unbind_applications ORDER BY created_at DESC');
    res.json({ success: true, data: rows });
  } catch (err) {
    return handleServerError(res, err, '查询失败');
  }
});

app.post('/api/admin/unbind/handle', adminLimiter, async (req, res) => {
  const adminPassword = req.headers['admin-password'];
  if (!adminPassword || adminPassword !== ADMIN_PASSWORD) {
    return res.status(403).json({ success: false, message: '无权访问' });
  }
  const { id, status } = req.body;
  try {
    await pool.execute(
      'UPDATE unbind_applications SET status = ?, handle_at = NOW() WHERE id = ?',
      [status, id]
    );
    if (status === 1) {
      const [apply] = await pool.execute('SELECT user_id FROM unbind_applications WHERE id = ?', [id]);
      const userId = apply[0].user_id;
      await pool.execute('DELETE FROM used_codes WHERE user_id = ?', [userId]);
    }
    res.json({ success: true, message: '审核完成' });
  } catch (err) {
    return handleServerError(res, err, '操作失败');
  }
});

// 用户状态（不变）
app.get('/api/user/status', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  try {
    const [rows] = await pool.execute('SELECT * FROM users WHERE id = ?', [userId]);
    if (rows.length === 0) {
      return res.status(400).json({ success: false, message: '用户不存在' });
    }

    const user = rows[0];
    let isPremium = user.is_premium;
    if (user.premium_expiry && new Date() > new Date(user.premium_expiry)) {
      isPremium = false;
    }

    res.json({
      success: true,
      userId: user.id,
      username: user.username,
      isPremium: !!isPremium,
      expiryDate: user.premium_expiry ? user.premium_expiry.toISOString() : null,
      securityQuestion: user.security_question
    });
  } catch (err) {
    return handleServerError(res, err, '服务器错误');
  }
});

// 修改用户名（不变）
app.post('/api/user/change-username', authenticateToken, async (req, res) => {
  const { newUsername } = req.body;
  const userId = req.user.userId;

  if (!newUsername || newUsername.length < 4 || newUsername.length > 16) {
    return res.status(400).json({ success: false, message: '用户名长度需在4-16位之间' });
  }

  try {
    const [existing] = await pool.execute('SELECT id FROM users WHERE username = ? AND id != ?', [newUsername, userId]);
    if (existing.length > 0) {
      return res.status(400).json({ success: false, message: '用户名已被占用' });
    }

    await pool.execute('UPDATE users SET username = ? WHERE id = ?', [newUsername, userId]);
    res.json({ success: true, message: '用户名修改成功', newUsername });
  } catch (err) {
    return handleServerError(res, err, '服务器错误');
  }
});

// ✅ 修改密码：明文存储
app.post('/api/user/change-password', authenticateToken, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const userId = req.user.userId;

  if (!oldPassword || !newPassword) {
    return res.status(400).json({ success: false, message: '请填写完整信息' });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ success: false, message: '新密码至少8位' });
  }

  try {
    const [rows] = await pool.execute('SELECT password FROM users WHERE id = ?', [userId]);
    if (rows.length === 0) {
      return res.status(400).json({ success: false, message: '用户不存在' });
    }

    const currentPassword = rows[0].password;
    // 明文对比旧密码
    const isPasswordValid = oldPassword === currentPassword;
    if (!isPasswordValid) {
      return res.status(400).json({ success: false, message: '原密码错误' });
    }

    // 明文存储新密码
    await pool.execute('UPDATE users SET password = ? WHERE id = ?', [newPassword, userId]);
    res.json({ success: true, message: '密码修改成功，请重新登录' });
  } catch (err) {
    return handleServerError(res, err, '服务器错误');
  }
});

// ✅ 密保问题：明文存储答案
app.post('/api/user/security-question', authenticateToken, async (req, res) => {
  const { question, answer } = req.body;
  const userId = req.user.userId;

  if (!question || !answer) {
    return res.status(400).json({ success: false, message: '请填写完整信息' });
  }

  try {
    // 明文存储密保答案
    await pool.execute(
      'UPDATE users SET security_question = ?, security_answer = ? WHERE id = ?',
      [question, answer, userId]
    );
    res.json({ success: true, message: '密保问题设置成功' });
  } catch (err) {
    return handleServerError(res, err, '服务器错误');
  }
});

// ✅ 重置密码：明文对比+明文存储
app.post('/api/user/reset-password', authLimiter, async (req, res) => {
  const { username, answer, newPassword } = req.body;

  if (!username || !answer || !newPassword) {
    return res.status(400).json({ success: false, message: '请填写完整信息' });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ success: false, message: '新密码至少8位' });
  }

  try {
    const [rows] = await pool.execute('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) {
      return res.status(400).json({ success: false, message: '用户不存在' });
    }

    const user = rows[0];
    if (!user.security_question) {
      return res.status(400).json({ success: false, message: '未设置密保问题' });
    }

    // 明文对比密保答案
    const isAnswerValid = answer === user.security_answer;
    if (!isAnswerValid) {
      return res.status(400).json({ success: false, message: '密保答案错误' });
    }

    // 明文存储新密码
    await pool.execute('UPDATE users SET password = ? WHERE id = ?', [newPassword, user.id]);
    res.json({ success: true, message: '密码重置成功，请登录' });
  } catch (err) {
    return handleServerError(res, err, '服务器错误');
  }
});

// 版本检查（不变）
app.get('/api/version/check', (req, res) => {
  res.json({
    success: true,
    latestVersion: process.env.LATEST_VERSION || "1.0.2",
    forceUpdate: process.env.FORCE_UPDATE === 'true' || false,
    downloadUrl: process.env.DOWNLOAD_URL || "https://www.lanzouy.com/xxxxxxx",
    updateDesc: process.env.UPDATE_DESC || "1. 新增账号安全中心\n2. 新增隐私模式\n3. 修复已知问题",
  });
});

// 获取密保问题（不变）
app.get('/api/user/security-question/:username', async (req, res) => {
  const { username } = req.params;
  try {
    const [rows] = await pool.execute('SELECT security_question FROM users WHERE username = ?', [username]);
    
    if (rows.length === 0) {
      return res.status(400).json({ success: false, message: '用户不存在' });
    }

    const user = rows[0];
    if (!user.security_question) {
      return res.status(400).json({ success: false, message: '该用户未设置密保问题' });
    }

    res.json({
      success: true,
      securityQuestion: user.security_question
    });
  } catch (err) {
    return handleServerError(res, err, '服务器错误');
  }
});

// 打卡接口（不变）
app.get('/api/user/checkin', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  try {
    const [userRows] = await pool.execute('SELECT is_premium FROM users WHERE id = ?', [userId]);
    if (userRows.length === 0 || !userRows[0].is_premium) {
      return res.status(403).json({ success: false, message: '仅限会员使用' });
    }

    const [rows] = await pool.execute('SELECT * FROM user_checkin WHERE user_id = ?', [userId]);
    if (rows.length === 0) {
      return res.json({ success: true, data: null });
    }

    res.json({
      success: true,
      data: {
        consecutiveCheckInDays: rows[0].consecutive_check_in_days,
        totalCheckInDays: rows[0].total_check_in_days,
        longestStreak: rows[0].longest_streak,
        reSignCards: rows[0].re_sign_cards,
        lastCheckInDate: rows[0].last_check_in_date ? rows[0].last_check_in_date.toISOString() : null
      }
    });
  } catch (err) {
    return handleServerError(res, err, '服务器错误');
  }
});

app.post('/api/user/checkin', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const { consecutiveCheckInDays, totalCheckInDays, longestStreak, reSignCards, lastCheckInDate } = req.body;

  try {
    const [userRows] = await pool.execute('SELECT is_premium FROM users WHERE id = ?', [userId]);
    if (userRows.length === 0 || !userRows[0].is_premium) {
      return res.status(403).json({ success: false, message: '仅限会员使用' });
    }

    const [existing] = await pool.execute('SELECT id FROM user_checkin WHERE user_id = ?', [userId]);
    
    if (existing.length > 0) {
      await pool.execute(`
        UPDATE user_checkin 
        SET consecutive_check_in_days = ?, total_check_in_days = ?, longest_streak = ?, re_sign_cards = ?, last_check_in_date = ?
        WHERE user_id = ?
      `, [consecutiveCheckInDays || 0, totalCheckInDays || 0, longestStreak || 0, reSignCards || 0, lastCheckInDate ? new Date(lastCheckInDate) : null, userId]);
    } else {
      await pool.execute(`
        INSERT INTO user_checkin (user_id, consecutive_check_in_days, total_check_in_days, longest_streak, re_sign_cards, last_check_in_date)
        VALUES (?, ?, ?, ?, ?, ?)
      `, [userId, consecutiveCheckInDays || 0, totalCheckInDays || 0, longestStreak || 0, reSignCards || 0, lastCheckInDate ? new Date(lastCheckInDate) : null]);
    }

    res.json({ success: true, message: '打卡数据同步成功' });
  } catch (err) {
    return handleServerError(res, err, '服务器错误');
  }
});

app.use((req, res) => {
  res.status(404).json({ success: false, message: '接口不存在' });
});

app.use((err, req, res, next) => {
  console.error('全局异常:', err);
  if (err.message === '不允许的跨域请求') {
    return res.status(403).json({ success: false, message: err.message });
  }
  res.status(500).json({ success: false, message: '服务器内部错误' });
});

// 启动服务器
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', async () => {
  console.log(`🚀 服务器运行在 http://localhost:${PORT}`);
  await initDB();
});
