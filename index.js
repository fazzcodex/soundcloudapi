// server.js - SoundCloud Scraper API Server dengan Anti-DDoS
const express = require('express')
const cors = require('cors')
const path = require('path')
const fs = require('fs')
const axios = require('axios')
const rateLimit = require('express-rate-limit')
const slowDown = require('express-slow-down')
const helmet = require('helmet')
const hpp = require('hpp')
const { v4: uuidv4 } = require('uuid')

// Import SoundCloud scraper
const soundcloudScraper = require('./api/soundcloud')

const app = express()
const PORT = process.env.PORT || 3000

// ==================== ANTI-DDoS CONFIGURATION ====================

// Blacklist untuk IP yang terdeteksi DDoS
let blacklistedIPs = new Set()
let requestLogs = new Map() // IP -> { count, firstRequest, lastRequest, blockedUntil }
let suspiciousIPs = new Map()

// Konfigurasi threshold
const CONFIG = {
  // Rate limiting per IP
  WINDOW_MS: 60 * 1000, // 1 menit
  MAX_REQUESTS_PER_WINDOW: 30, // Maks 30 request per menit
  MAX_REQUESTS_PER_SECOND: 5, // Maks 5 request per detik
  
  // Slow Down
  DELAY_AFTER: 20, // Setelah 20 request, mulai delay
  DELAY_MS: 500, // Delay 500ms per request
  
  // Blocking
  BLOCK_DURATION: 15 * 60 * 1000, // Block 15 menit
  SUSPICIOUS_THRESHOLD: 50, // 50 request per menit = suspicious
  BLACKLIST_THRESHOLD: 100, // 100 request per menit = blacklist
  
  // Global rate limiting
  GLOBAL_MAX_REQUESTS: 1000, // Maks 1000 request per menit global
  GLOBAL_WINDOW_MS: 60 * 1000
}

// ==================== MIDDLEWARE ANTI-DDOS ====================

// 1. Security Headers (Helmet)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:", "http:"],
      connectSrc: ["'self'", "https://api-mobi.soundcloud.com", "https://cf-hls-media.sndcdn.com"],
    },
  },
}))

// 2. Prevent HTTP Parameter Pollution
app.use(hpp())

// 3. Trust proxy (jika di belakang reverse proxy seperti Nginx/Cloudflare)
app.set('trust proxy', 1)

// 4. Get real IP address (support proxy)
function getClientIP(req) {
  return req.ip || 
         req.connection.remoteAddress || 
         req.socket.remoteAddress || 
         req.headers['x-forwarded-for']?.split(',')[0] || 
         'unknown'
}

// 5. Clean expired logs periodically
setInterval(() => {
  const now = Date.now()
  for (const [ip, data] of requestLogs) {
    if (now - data.lastRequest > CONFIG.WINDOW_MS * 2) {
      requestLogs.delete(ip)
    }
  }
  
  // Clean expired blacklist
  for (const [ip, blockedUntil] of blacklistedIPs) {
    if (now > blockedUntil) {
      blacklistedIPs.delete(ip)
    }
  }
  
  // Clean suspicious IPs
  for (const [ip, data] of suspiciousIPs) {
    if (now - data.lastAlert > CONFIG.WINDOW_MS * 5) {
      suspiciousIPs.delete(ip)
    }
  }
}, CONFIG.WINDOW_MS)

// 6. Blacklist check middleware
function isBlacklisted(req, res, next) {
  const ip = getClientIP(req)
  const blockedUntil = blacklistedIPs.get(ip)
  
  if (blockedUntil && Date.now() < blockedUntil) {
    const remainingMinutes = Math.ceil((blockedUntil - Date.now()) / 60000)
    return res.status(429).json({
      status: false,
      error: 'RATE_LIMIT_EXCEEDED',
      message: `IP Anda telah diblokir karena aktivitas mencurigakan. Coba lagi dalam ${remainingMinutes} menit.`,
      blocked_until: new Date(blockedUntil).toISOString(),
      retry_after: Math.ceil((blockedUntil - Date.now()) / 1000)
    })
  } else if (blockedUntil) {
    blacklistedIPs.delete(ip)
  }
  
  next()
}

// 7. Per-second rate limiting
const perSecondLimiter = (req, res, next) => {
  const ip = getClientIP(req)
  const now = Date.now()
  const currentSecond = Math.floor(now / 1000)
  
  if (!requestLogs.has(ip)) {
    requestLogs.set(ip, { count: 0, firstRequest: now, lastRequest: now, perSecondCount: 0, lastSecond: currentSecond })
  }
  
  const log = requestLogs.get(ip)
  
  // Reset per-second counter jika detik berbeda
  if (log.lastSecond !== currentSecond) {
    log.perSecondCount = 0
    log.lastSecond = currentSecond
  }
  
  log.perSecondCount++
  
  if (log.perSecondCount > CONFIG.MAX_REQUESTS_PER_SECOND) {
    // Detect DDoS - terlalu banyak request per detik
    if (log.perSecondCount > CONFIG.MAX_REQUESTS_PER_SECOND * 2) {
      // Block IP immediately
      blacklistedIPs.set(ip, Date.now() + CONFIG.BLOCK_DURATION)
      console.warn(`⚠️ DDoS detected! IP ${ip} blocked for ${CONFIG.BLOCK_DURATION / 60000} minutes (${log.perSecondCount} req/sec)`)
      
      // Log ke file
      logDDoSAttempt(ip, log.perSecondCount, 'per_second')
    }
    
    return res.status(429).json({
      status: false,
      error: 'TOO_MANY_REQUESTS',
      message: `Terlalu banyak request! Maksimal ${CONFIG.MAX_REQUESTS_PER_SECOND} request per detik.`,
      retry_after: 1
    })
  }
  
  next()
}

// 8. Main rate limiter
const limiter = rateLimit({
  windowMs: CONFIG.WINDOW_MS,
  max: CONFIG.MAX_REQUESTS_PER_WINDOW,
  keyGenerator: (req) => getClientIP(req),
  handler: (req, res) => {
    const ip = getClientIP(req)
    const log = requestLogs.get(ip)
    
    if (log) {
      log.count = (log.count || 0) + 1
      
      // Check if suspicious
      if (log.count >= CONFIG.SUSPICIOUS_THRESHOLD) {
        if (!suspiciousIPs.has(ip)) {
          suspiciousIPs.set(ip, { count: log.count, lastAlert: Date.now() })
          console.warn(`⚠️ Suspicious activity from IP ${ip}: ${log.count} requests in ${CONFIG.WINDOW_MS / 1000}s`)
          logDDoSAttempt(ip, log.count, 'suspicious')
        }
      }
      
      // Check if should be blacklisted
      if (log.count >= CONFIG.BLACKLIST_THRESHOLD) {
        blacklistedIPs.set(ip, Date.now() + CONFIG.BLOCK_DURATION)
        console.error(`🔥 DDoS attack detected! IP ${ip} BLACKLISTED for ${CONFIG.BLOCK_DURATION / 60000} minutes (${log.count} requests)`)
        logDDoSAttempt(ip, log.count, 'blacklist')
      }
    }
    
    res.status(429).json({
      status: false,
      error: 'RATE_LIMIT_EXCEEDED',
      message: `Terlalu banyak request! Maksimal ${CONFIG.MAX_REQUESTS_PER_WINDOW} request per ${CONFIG.WINDOW_MS / 1000} detik.`,
      retry_after: Math.ceil(CONFIG.WINDOW_MS / 1000)
    })
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Skip rate limiting untuk admin endpoint dengan master key
    const masterKey = req.headers['x-master-key']
    return masterKey === process.env.MASTER_KEY
  }
})

// 9. Slow down middleware (gradual response slowing)
const speedLimiter = slowDown({
  windowMs: CONFIG.WINDOW_MS,
  delayAfter: CONFIG.DELAY_AFTER,
  delayMs: (hits) => Math.min(CONFIG.DELAY_MS * Math.floor(hits / CONFIG.DELAY_AFTER), 5000),
  keyGenerator: (req) => getClientIP(req),
  skip: (req) => {
    const masterKey = req.headers['x-master-key']
    return masterKey === process.env.MASTER_KEY
  }
})

// 10. Global rate limiter (semua IP combined)
let globalRequestCount = 0
let globalResetTime = Date.now() + CONFIG.GLOBAL_WINDOW_MS

setInterval(() => {
  globalRequestCount = 0
  globalResetTime = Date.now() + CONFIG.GLOBAL_WINDOW_MS
}, CONFIG.GLOBAL_WINDOW_MS)

function globalLimiter(req, res, next) {
  if (Date.now() > globalResetTime) {
    globalRequestCount = 0
    globalResetTime = Date.now() + CONFIG.GLOBAL_WINDOW_MS
  }
  
  globalRequestCount++
  
  if (globalRequestCount > CONFIG.GLOBAL_MAX_REQUESTS) {
    return res.status(503).json({
      status: false,
      error: 'SERVICE_OVERLOAD',
      message: 'Server sedang padat. Silakan coba lagi nanti.',
      retry_after: Math.ceil((globalResetTime - Date.now()) / 1000)
    })
  }
  
  next()
}

// 11. Request size limiter (prevent large payload attacks)
app.use(express.json({ limit: '1mb' }))
app.use(express.urlencoded({ extended: true, limit: '1mb' }))

// 12. DDoS logging function
function logDDoSAttempt(ip, requestCount, type) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    ip: ip,
    request_count: requestCount,
    type: type,
    user_agent: null // Will be filled later
  }
  
  const logDir = path.join(__dirname, 'logs')
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true })
  }
  
  const logFile = path.join(logDir, 'ddos-attacks.log')
  fs.appendFileSync(logFile, JSON.stringify(logEntry) + '\n')
}

// 13. Request logger middleware (optional, untuk monitoring)
function requestLogger(req, res, next) {
  const ip = getClientIP(req)
  const start = Date.now()
  
  res.on('finish', () => {
    const duration = Date.now() - start
    const log = requestLogs.get(ip)
    if (log) {
      log.count = (log.count || 0) + 1
      log.lastRequest = Date.now()
      requestLogs.set(ip, log)
    } else {
      requestLogs.set(ip, { count: 1, firstRequest: Date.now(), lastRequest: Date.now() })
    }
    
    // Log slow responses (>3 seconds)
    if (duration > 3000) {
      console.warn(`⚠️ Slow response: ${req.method} ${req.path} from ${ip} took ${duration}ms`)
    }
  })
  
  next()
}

// 14. Apply all anti-DDoS middlewares
app.use(requestLogger)
app.use(globalLimiter)
app.use(isBlacklisted)
app.use(perSecondLimiter)
app.use(speedLimiter)
app.use(limiter)

// ==================== API KEY CONFIGURATION ====================

const API_KEYS_URL = process.env.API_KEYS_URL || 'https://raw.githubusercontent.com/fazzcode/api-keys/main/soundcloud-keys.json'
let validApiKeys = new Set()
let keyLastUpdate = 0
const KEY_CACHE_DURATION = 5 * 60 * 1000

// Function to fetch API keys from GitHub
async function fetchApiKeys() {
  try {
    console.log('📡 Fetching API keys from GitHub...')
    const response = await axios.get(API_KEYS_URL, {
      timeout: 10000,
      headers: { 'User-Agent': 'SoundCloud-Scraper-API' }
    })
    
    let keys = []
    if (Array.isArray(response.data)) {
      keys = response.data
    } else if (response.data.keys && Array.isArray(response.data.keys)) {
      keys = response.data.keys
    } else if (typeof response.data === 'object') {
      keys = Object.values(response.data)
    }
    
    const newKeys = keys.filter(k => k && typeof k === 'string' && k.trim().length > 0)
    
    if (newKeys.length > 0) {
      validApiKeys.clear()
      newKeys.forEach(k => validApiKeys.add(k.trim()))
      keyLastUpdate = Date.now()
      console.log(`✅ Loaded ${validApiKeys.size} API keys from GitHub`)
      return true
    } else {
      console.warn('⚠️ No valid API keys found in GitHub response')
      return false
    }
  } catch (error) {
    console.error('❌ Failed to fetch API keys:', error.message)
    return false
  }
}

// Validate API key middleware
async function validateApiKey(req, res, next) {
  if (Date.now() - keyLastUpdate > KEY_CACHE_DURATION && validApiKeys.size > 0) {
    console.log('🔄 Refreshing API keys cache...')
    fetchApiKeys().catch(console.error)
  }
  
  const apiKey = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '') || req.query.api_key
  
  if (!apiKey) {
    return res.status(401).json({
      status: false,
      error: 'UNAUTHORIZED',
      message: 'API key required. Please provide X-API-Key header or api_key parameter.',
      documentation: '/docs'
    })
  }
  
  if (validApiKeys.size === 0) {
    await fetchApiKeys()
  }
  
  if (!validApiKeys.has(apiKey)) {
    const ip = getClientIP(req)
    console.warn(`⚠️ Invalid API key attempt from IP ${ip}: ${apiKey.substring(0, 10)}...`)
    return res.status(403).json({
      status: false,
      error: 'FORBIDDEN',
      message: 'Invalid API key. Please check your key.',
      valid_keys_count: validApiKeys.size
    })
  }
  
  req.apiKey = apiKey
  req.apiKeyValid = true
  next()
}

// ==================== ROUTES ====================

// Public routes (limited rate)
const publicLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  keyGenerator: (req) => getClientIP(req),
  handler: (req, res) => {
    res.status(429).json({
      status: false,
      message: 'Too many requests to public endpoints'
    })
  }
})

app.get('/health', publicLimiter, (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    api_keys_loaded: validApiKeys.size,
    active_ips: requestLogs.size,
    blacklisted_ips: blacklistedIPs.size,
    suspicious_ips: suspiciousIPs.size
  })
})

// Update server.js - tambahkan route untuk docs page
// Tambahkan ini di server.js sebelum route lainnya

// Serve docs page
app.get('/docs', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'docs.html'))
})

// API documentation in JSON format (untuk developer)
app.get('/api/docs', (req, res) => {
  res.json({
    name: 'SoundCloud Scraper API',
    version: '1.0.0',
    base_url: 'https://music.fazzcode.qzz.io',
    authentication: {
      required: true,
      methods: ['X-API-Key header', 'Authorization: Bearer <key>', 'api_key query parameter']
    },
    endpoints: {
      homepage: {
        method: ['GET', 'POST'],
        path: '/api/soundcloud',
        params: { action: 'homepage', limit: 'optional (default: 20)' }
      },
      search: {
        method: ['GET', 'POST'],
        path: '/api/soundcloud',
        params: { action: 'search', query: 'required', limit: 'optional' }
      },
      track: {
        method: ['GET', 'POST'],
        path: '/api/soundcloud',
        params: { action: 'track', track_id: 'required' }
      },
      playlist: {
        method: ['GET', 'POST'],
        path: '/api/soundcloud',
        params: { action: 'playlist', playlist_id: 'required' }
      }
    }
  })
})

// Admin endpoint untuk melihat stats DDoS
app.get('/admin/stats', validateApiKey, async (req, res) => {
  const masterKey = req.headers['x-master-key']
  if (masterKey !== process.env.MASTER_KEY) {
    return res.status(403).json({ status: false, message: 'Master key required' })
  }
  
  const stats = {
    timestamp: new Date().toISOString(),
    active_ips: requestLogs.size,
    blacklisted_ips: Array.from(blacklistedIPs.keys()).map(ip => ({
      ip: ip,
      blocked_until: new Date(blacklistedIPs.get(ip)).toISOString()
    })),
    suspicious_ips: Array.from(suspiciousIPs.keys()).map(ip => ({
      ip: ip,
      request_count: suspiciousIPs.get(ip).count,
      last_alert: new Date(suspiciousIPs.get(ip).lastAlert).toISOString()
    })),
    top_ips: Array.from(requestLogs.entries())
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 10)
      .map(([ip, data]) => ({
        ip: ip,
        request_count: data.count,
        last_request: new Date(data.lastRequest).toISOString()
      })),
    config: {
      window_ms: CONFIG.WINDOW_MS,
      max_requests_per_window: CONFIG.MAX_REQUESTS_PER_WINDOW,
      max_requests_per_second: CONFIG.MAX_REQUESTS_PER_SECOND,
      suspicious_threshold: CONFIG.SUSPICIOUS_THRESHOLD,
      blacklist_threshold: CONFIG.BLACKLIST_THRESHOLD,
      block_duration_minutes: CONFIG.BLOCK_DURATION / 60000
    }
  }
  
  res.json(stats)
})

// Admin endpoint untuk unblock IP
app.post('/admin/unblock', validateApiKey, async (req, res) => {
  const masterKey = req.headers['x-master-key']
  const ipToUnblock = req.body.ip || req.query.ip
  
  if (masterKey !== process.env.MASTER_KEY) {
    return res.status(403).json({ status: false, message: 'Master key required' })
  }
  
  if (!ipToUnblock) {
    return res.status(400).json({ status: false, message: 'IP parameter required' })
  }
  
  if (blacklistedIPs.has(ipToUnblock)) {
    blacklistedIPs.delete(ipToUnblock)
    res.json({ status: true, message: `IP ${ipToUnblock} unblocked successfully` })
  } else {
    res.json({ status: false, message: `IP ${ipToUnblock} not found in blacklist` })
  }
})

// API routes (require API key)
app.use('/api', validateApiKey)
app.use(cors())
app.use(express.static(path.join(__dirname, 'public')))

// Web interface
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
})

// SoundCloud API endpoint
app.all('/api/soundcloud', async (req, res) => {
  const method = req.method
  const params = method === 'GET' ? req.query : req.body
  
  delete params.api_key
  
  const mockReq = { query: params, body: params, method }
  const mockRes = {
    status: (code) => {
      mockRes.statusCode = code
      return mockRes
    },
    json: (data) => {
      mockRes.data = data
      return mockRes
    },
    statusCode: 200,
    data: null
  }
  
  await soundcloudScraper.handler(mockReq, mockRes)
  
  const response = mockRes.data
  if (response && typeof response === 'object') {
    response.api_metadata = {
      key_used: req.apiKey ? `${req.apiKey.slice(0, 8)}...${req.apiKey.slice(-4)}` : null,
      rate_limit: `${CONFIG.MAX_REQUESTS_PER_WINDOW} requests per ${CONFIG.WINDOW_MS / 1000}s`,
      timestamp: new Date().toISOString()
    }
  }
  
  res.status(mockRes.statusCode).json(response)
})

// Admin endpoint to refresh API keys
app.post('/admin/refresh-keys', validateApiKey, async (req, res) => {
  const masterKey = req.headers['x-master-key']
  
  if (masterKey !== process.env.MASTER_KEY) {
    return res.status(403).json({ status: false, message: 'Invalid master key' })
  }
  
  const success = await fetchApiKeys()
  if (success) {
    res.json({
      status: true,
      message: `API keys refreshed successfully. ${validApiKeys.size} keys loaded.`,
      last_update: new Date(keyLastUpdate).toISOString()
    })
  } else {
    res.status(500).json({ status: false, message: 'Failed to refresh API keys' })
  }
})

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    status: false,
    error: 'NOT_FOUND',
    message: 'Endpoint not found'
  })
})

// Error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err)
  res.status(500).json({
    status: false,
    error: 'INTERNAL_SERVER_ERROR',
    message: 'Something went wrong'
  })
})

// Initialize
async function init() {
  await fetchApiKeys()
  
  setInterval(async () => {
    if (validApiKeys.size > 0) {
      await fetchApiKeys()
    }
  }, KEY_CACHE_DURATION)
  
  app.listen(PORT, () => {
    console.log(`\n🚀 SoundCloud Scraper API running on port ${PORT}`)
    console.log(`📱 Web interface: http://localhost:${PORT}`)
    console.log(`📖 API docs: http://localhost:${PORT}/docs`)
    console.log(`🔑 API keys loaded: ${validApiKeys.size}`)
    console.log(`\n🛡️ ANTI-DDOS CONFIGURATION:`)
    console.log(`   ├─ Max requests per IP: ${CONFIG.MAX_REQUESTS_PER_WINDOW} / ${CONFIG.WINDOW_MS / 1000}s`)
    console.log(`   ├─ Max requests per second: ${CONFIG.MAX_REQUESTS_PER_SECOND}`)
    console.log(`   ├─ Suspicious threshold: ${CONFIG.SUSPICIOUS_THRESHOLD} req/min`)
    console.log(`   ├─ Blacklist threshold: ${CONFIG.BLACKLIST_THRESHOLD} req/min`)
    console.log(`   ├─ Block duration: ${CONFIG.BLOCK_DURATION / 60000} minutes`)
    console.log(`   └─ Global limit: ${CONFIG.GLOBAL_MAX_REQUESTS} req/min\n`)
  })
}

init()

module.exports = app
