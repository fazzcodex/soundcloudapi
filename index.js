// server.js - SoundCloud API dengan Anti-DDoS
const express = require('express')
const cors = require('cors')
const path = require('path')
const fs = require('fs')
const rateLimit = require('express-rate-limit')
const slowDown = require('express-slow-down')
const helmet = require('helmet')
const hpp = require('hpp')

// Import SoundCloud handler
const { handleSoundCloud } = require('./api/soundcloud')

const app = express()
const PORT = process.env.PORT || 3000

// ==================== ANTI-DDoS CONFIGURATION ====================

// Blacklist dan tracking
let blacklistedIPs = new Map() // IP -> blockedUntil
let requestLogs = new Map() // IP -> request count
let suspiciousIPs = new Map() // IP -> suspicion count

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
  
  // Global
  GLOBAL_MAX_REQUESTS: 1000, // Maks 1000 request per menit global
  GLOBAL_WINDOW_MS: 60 * 1000
}

// ==================== HELPER FUNCTIONS ====================

// Get real IP address
function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || 
         req.socket.remoteAddress || 
         req.ip || 
         'unknown'
}

// Log DDoS attempt
function logDDoSAttempt(ip, requestCount, type, userAgent = null) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    ip: ip,
    request_count: requestCount,
    type: type,
    user_agent: userAgent
  }
  
  const logDir = path.join(__dirname, 'logs')
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true })
  }
  
  const logFile = path.join(logDir, 'ddos-attacks.log')
  fs.appendFileSync(logFile, JSON.stringify(logEntry) + '\n')
  console.warn(`⚠️ DDoS ${type}: ${ip} - ${requestCount} requests`)
}

// Clean expired logs periodically
setInterval(() => {
  const now = Date.now()
  
  // Clean expired blacklist
  for (const [ip, blockedUntil] of blacklistedIPs) {
    if (now > blockedUntil) {
      blacklistedIPs.delete(ip)
    }
  }
  
  // Clean old request logs
  for (const [ip, data] of requestLogs) {
    if (now - data.lastRequest > CONFIG.WINDOW_MS * 2) {
      requestLogs.delete(ip)
    }
  }
  
  // Clean suspicious IPs
  for (const [ip, data] of suspiciousIPs) {
    if (now - data.lastAlert > CONFIG.WINDOW_MS * 5) {
      suspiciousIPs.delete(ip)
    }
  }
}, CONFIG.WINDOW_MS)

// ==================== MIDDLEWARE ANTI-DDOS ====================

// 1. Security Headers (Helmet)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https:", "http:"],
      connectSrc: ["'self'", "https://api-mobi.soundcloud.com", "https://cf-hls-media.sndcdn.com"],
    },
  },
}))

// 2. Prevent HTTP Parameter Pollution
app.use(hpp())

// 3. Trust proxy (untuk Cloudflare/Nginx)
app.set('trust proxy', 1)

// 4. Request size limiter
app.use(express.json({ limit: '1mb' }))
app.use(express.urlencoded({ extended: true, limit: '1mb' }))

// 5. CORS
app.use(cors())

// 6. Static files
app.use(express.static(path.join(__dirname, 'public')))

// 7. Blacklist check middleware
function isBlacklisted(req, res, next) {
  const ip = getClientIP(req)
  const blockedUntil = blacklistedIPs.get(ip)
  
  if (blockedUntil && Date.now() < blockedUntil) {
    const remainingMinutes = Math.ceil((blockedUntil - Date.now()) / 60000)
    return res.status(429).json({
      status: false,
      error: 'IP_BLOCKED',
      message: `IP Anda telah diblokir karena aktivitas mencurigakan. Coba lagi dalam ${remainingMinutes} menit.`,
      blocked_until: new Date(blockedUntil).toISOString(),
      retry_after: Math.ceil((blockedUntil - Date.now()) / 1000)
    })
  } else if (blockedUntil) {
    blacklistedIPs.delete(ip)
  }
  next()
}

// 8. Per-second rate limiting
const perSecondLimiter = (req, res, next) => {
  const ip = getClientIP(req)
  const now = Date.now()
  const currentSecond = Math.floor(now / 1000)
  
  if (!requestLogs.has(ip)) {
    requestLogs.set(ip, { 
      count: 0, 
      firstRequest: now, 
      lastRequest: now, 
      perSecondCount: 0, 
      lastSecond: currentSecond 
    })
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
      blacklistedIPs.set(ip, Date.now() + CONFIG.BLOCK_DURATION)
      logDDoSAttempt(ip, log.perSecondCount, 'per_second_blacklist', req.headers['user-agent'])
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

// 9. Main rate limiter
const limiter = rateLimit({
  windowMs: CONFIG.WINDOW_MS,
  max: CONFIG.MAX_REQUESTS_PER_WINDOW,
  keyGenerator: getClientIP,
  handler: (req, res) => {
    const ip = getClientIP(req)
    const log = requestLogs.get(ip)
    
    if (log) {
      log.count = (log.count || 0) + 1
      
      // Check if suspicious
      if (log.count >= CONFIG.SUSPICIOUS_THRESHOLD && !suspiciousIPs.has(ip)) {
        suspiciousIPs.set(ip, { count: log.count, lastAlert: Date.now() })
        logDDoSAttempt(ip, log.count, 'suspicious', req.headers['user-agent'])
      }
      
      // Check if should be blacklisted
      if (log.count >= CONFIG.BLACKLIST_THRESHOLD && !blacklistedIPs.has(ip)) {
        blacklistedIPs.set(ip, Date.now() + CONFIG.BLOCK_DURATION)
        logDDoSAttempt(ip, log.count, 'blacklist', req.headers['user-agent'])
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
  legacyHeaders: false
})

// 10. Slow down middleware
const speedLimiter = slowDown({
  windowMs: CONFIG.WINDOW_MS,
  delayAfter: CONFIG.DELAY_AFTER,
  delayMs: (hits) => Math.min(CONFIG.DELAY_MS * Math.floor(hits / CONFIG.DELAY_AFTER), 5000),
  keyGenerator: getClientIP,
  skip: (req) => {
    // Skip untuk endpoint tertentu jika perlu
    return req.path === '/health'
  }
})

// 11. Global rate limiter
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

// 12. Request logger
function requestLogger(req, res, next) {
  const ip = getClientIP(req)
  const start = Date.now()
  
  res.on('finish', () => {
    const duration = Date.now() - start
    const log = requestLogs.get(ip)
    if (log) {
      log.count = (log.count || 0) + 1
      log.lastRequest = Date.now()
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

// 13. Apply all anti-DDoS middlewares (urutan penting!)
app.use(requestLogger)
app.use(globalLimiter)
app.use(isBlacklisted)
app.use(perSecondLimiter)
app.use(speedLimiter)
app.use(limiter)

// ==================== ROUTES ====================

// Public routes (rate limit lebih longgar)
const publicLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  keyGenerator: getClientIP
})

app.get('/health', publicLimiter, (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    stats: {
      active_ips: requestLogs.size,
      blacklisted_ips: blacklistedIPs.size,
      suspicious_ips: suspiciousIPs.size
    }
  })
})

app.get('/docs', publicLimiter, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'docs.html'))
})

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
})

// Admin endpoint untuk melihat stats (dengan master key)
app.get('/admin/stats', (req, res) => {
  const masterKey = req.headers['x-master-key']
  if (masterKey !== process.env.MASTER_KEY && masterKey !== 'fazzcode_admin_2024') {
    return res.status(403).json({ status: false, message: 'Master key required' })
  }
  
  res.json({
    timestamp: new Date().toISOString(),
    active_ips: requestLogs.size,
    blacklisted_ips: Array.from(blacklistedIPs.keys()).map(ip => ({
      ip: ip,
      blocked_until: new Date(blacklistedIPs.get(ip)).toISOString()
    })),
    suspicious_ips: Array.from(suspiciousIPs.keys()).map(ip => ({
      ip: ip,
      data: suspiciousIPs.get(ip)
    })),
    top_ips: Array.from(requestLogs.entries())
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 10)
      .map(([ip, data]) => ({
        ip: ip,
        request_count: data.count,
        last_request: new Date(data.lastRequest).toISOString()
      })),
    config: CONFIG
  })
})

// Admin endpoint untuk unblock IP
app.post('/admin/unblock', express.json(), (req, res) => {
  const masterKey = req.headers['x-master-key']
  if (masterKey !== process.env.MASTER_KEY && masterKey !== 'fazzcode_admin_2024') {
    return res.status(403).json({ status: false, message: 'Master key required' })
  }
  
  const ipToUnblock = req.body.ip || req.query.ip
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

// SoundCloud API endpoint
app.all('/api/soundcloud', handleSoundCloud)

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
    message: err.message || 'Something went wrong'
  })
})

// Start server
app.listen(PORT, () => {
  console.log(`\n🚀 SoundCloud API running on port ${PORT}`)
  console.log(`📍 http://localhost:${PORT}`)
  console.log(`📖 Docs: http://localhost:${PORT}/docs`)
  console.log(`🔒 Health: http://localhost:${PORT}/health`)
  console.log(`\n🛡️ ANTI-DDOS CONFIGURATION:`)
  console.log(`   ├─ Max requests per IP: ${CONFIG.MAX_REQUESTS_PER_WINDOW} / ${CONFIG.WINDOW_MS / 1000}s`)
  console.log(`   ├─ Max requests per second: ${CONFIG.MAX_REQUESTS_PER_SECOND}`)
  console.log(`   ├─ Suspicious threshold: ${CONFIG.SUSPICIOUS_THRESHOLD} req/min`)
  console.log(`   ├─ Blacklist threshold: ${CONFIG.BLACKLIST_THRESHOLD} req/min`)
  console.log(`   ├─ Block duration: ${CONFIG.BLOCK_DURATION / 60000} minutes`)
  console.log(`   └─ Global limit: ${CONFIG.GLOBAL_MAX_REQUESTS} req/min\n`)
})

module.exports = app
