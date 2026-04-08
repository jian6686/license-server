const { kv } = require('@vercel/kv');

const ADMIN_SECRET = process.env.ADMIN_SECRET;

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(res, data, status = 200) {
  Object.entries(CORS_HEADERS).forEach(([k, v]) => res.setHeader(k, v));
  res.setHeader('Content-Type', 'application/json');
  return res.status(status).json(data);
}

function isAdmin(secret) {
  return secret && secret === ADMIN_SECRET;
}

async function handleRegister(body) {
  if (!isAdmin(body.secret)) {
    return { error: '管理员密码错误' };
  }
  const keys = body.keys || (body.key ? [body.key] : []);
  if (keys.length === 0) {
    return { error: '未提供密钥' };
  }
  let registered = 0;
  for (const key of keys) {
    const existing = await kv.get(`license:${key}`);
    if (!existing) {
      const record = {
        status: 'valid',
        created_at: new Date().toISOString(),
        used_at: null,
      };
      await kv.set(`license:${key}`, JSON.stringify(record));
      await kv.sadd('license:all_keys', key);
      registered++;
    }
  }
  return { success: true, registered, total: keys.length };
}

async function handleActivate(body) {
  if (!body.key) {
    return { valid: false, reason: '未提供密钥' };
  }
  const raw = await kv.get(`license:${body.key}`);
  if (!raw) {
    return { valid: false, reason: '密钥不存在或未注册' };
  }
  const record = typeof raw === 'string' ? JSON.parse(raw) : raw;
  if (record.status === 'used') {
    return { valid: false, reason: '该密钥已被使用，无法再次激活' };
  }
  if (record.status === 'revoked') {
    return { valid: false, reason: '该密钥已被管理员撤销' };
  }
  if (record.status !== 'valid') {
    return { valid: false, reason: `密钥状态异常: ${record.status}` };
  }
  record.status = 'used';
  record.used_at = new Date().toISOString();
  await kv.set(`license:${body.key}`, JSON.stringify(record));
  return { valid: true };
}

async function handleCheck(body) {
  if (!body.key) {
    return { valid: false, status: 'not_found' };
  }
  const raw = await kv.get(`license:${body.key}`);
  if (!raw) {
    return { valid: false, status: 'not_found' };
  }
  const record = typeof raw === 'string' ? JSON.parse(raw) : raw;
  return { valid: record.status === 'used', status: record.status };
}

async function handleList(body) {
  if (!isAdmin(body.secret)) {
    return { error: '管理员密码错误' };
  }
  const allKeys = await kv.smembers('license:all_keys');
  const keys = [];
  for (const key of allKeys) {
    const raw = await kv.get(`license:${key}`);
    if (raw) {
      const record = typeof raw === 'string' ? JSON.parse(raw) : raw;
      keys.push({
        key,
        status: record.status,
        created_at: record.created_at,
        used_at: record.used_at,
      });
    }
  }
  return { keys };
}

async function handleRevoke(body) {
  if (!isAdmin(body.secret)) {
    return { error: '管理员密码错误' };
  }
  if (!body.key) {
    return { error: '未提供密钥' };
  }
  const raw = await kv.get(`license:${body.key}`);
  if (!raw) {
    return { error: '密钥不存在' };
  }
  const record = typeof raw === 'string' ? JSON.parse(raw) : raw;
  record.status = 'revoked';
  record.used_at = new Date().toISOString();
  await kv.set(`license:${body.key}`, JSON.stringify(record));
  return { success: true, key: body.key, status: 'revoked' };
}

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    Object.entries(CORS_HEADERS).forEach(([k, v]) => res.setHeader(k, v));
    return res.status(204).end();
  }
  if (req.method === 'GET') {
    return json(res, { status: 'ok', service: 'Nanobanana License Server' });
  }
  if (req.method === 'POST') {
    let body;
    try {
      if (typeof req.body === 'string') {
        body = JSON.parse(req.body);
      } else if (req.body && typeof req.body === 'object') {
        body = req.body;
      } else {
        return json(res, { error: 'Invalid request body' }, 400);
      }
    } catch (e) {
      return json(res, { error: 'Invalid JSON in request body' }, 400);
    }
    const { action } = body;
    try {
      switch (action) {
        case 'register': return json(res, await handleRegister(body));
        case 'activate': return json(res, await handleActivate(body));
        case 'check':    return json(res, await handleCheck(body));
        case 'list':     return json(res, await handleList(body));
        case 'revoke':   return json(res, await handleRevoke(body));
        default:
          return json(res, { error: '未知操作' }, 400);
      }
    } catch (e) {
      console.error('Action error:', e);
      return json(res, { error: '服务器内部错误' }, 500);
    }
  }
  return json(res, { error: 'Method not allowed' }, 405);
};
