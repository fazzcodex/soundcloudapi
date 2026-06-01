// server.js - SoundCloud Scraper API Server dengan API Key
const express = require('express')
const cors = require('cors')
const path = require('path')
const fs = require('fs')
const axios = require('axios')

// Import SoundCloud scraper
const soundcloudScraper = require('./soundcloud')

const app = express()
const PORT = process.env.PORT || 3000

// API Key configuration
const API_KEYS_URL = process.env.API_KEYS_URL || 'https://raw.githubusercontent.com/fazzcode/api-keys/main/soundcloud-keys.json'
let validApiKeys = new Set()
let keyLastUpdate = 0
const KEY_CACHE_DURATION = 5 * 60 * 1000 // 5 menit

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
    
    // Filter valid keys (non-empty strings)
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
  // Check if keys need refresh
  if (Date.now() - keyLastUpdate > KEY_CACHE_DURATION && validApiKeys.size > 0) {
    console.log('🔄 Refreshing API keys cache...')
    fetchApiKeys().catch(console.error)
  }
  
  // Get API key from header or query
  const apiKey = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '') || req.query.api_key
  
  if (!apiKey) {
    return res.status(401).json({
      status: false,
      error: 'UNAUTHORIZED',
      message: 'API key required. Please provide X-API-Key header or api_key parameter.',
      documentation: '/docs'
    })
  }
  
  // If keys haven't been loaded yet, try to fetch
  if (validApiKeys.size === 0) {
    await fetchApiKeys()
  }
  
  // Validate key
  if (!validApiKeys.has(apiKey)) {
    return res.status(403).json({
      status: false,
      error: 'FORBIDDEN',
      message: 'Invalid API key. Please check your key.',
      valid_keys_count: validApiKeys.size
    })
  }
  
  // Add API key info to request
  req.apiKey = apiKey
  req.apiKeyValid = true
  next()
}

// Public routes (no API key required)
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    api_keys_loaded: validApiKeys.size,
    key_cache_expiry: new Date(keyLastUpdate + KEY_CACHE_DURATION).toISOString()
  })
})

app.get('/docs', (req, res) => {
  res.json({
    name: 'SoundCloud Scraper API',
    version: '1.0.0',
    authentication: {
      required: true,
      methods: [
        'X-API-Key header',
        'Authorization: Bearer <key>',
        'api_key query parameter'
      ],
      get_key: 'https://raw.githubusercontent.com/fazzcode/api-keys/main/soundcloud-keys.json'
    },
    base_url: 'https://api.fazzcode.qzz.io',
    endpoints: {
      '/api/soundcloud': {
        methods: ['GET', 'POST'],
        authentication: 'Required',
        actions: ['homepage', 'search', 'track', 'playlist'],
        parameters: {
          action: { type: 'string', required: true, description: 'Action type' },
          query: { type: 'string', required: false, description: 'Search keyword (action=search)' },
          track_id: { type: 'number', required: false, description: 'Track ID (action=track)' },
          playlist_id: { type: 'number', required: false, description: 'Playlist ID (action=playlist)' },
          limit: { type: 'number', required: false, description: 'Limit results (default: 20, max: 50)' },
          api_key: { type: 'string', required: true, description: 'Your API key' }
        },
        examples: {
          homepage: '/api/soundcloud?action=homepage&limit=10&api_key=YOUR_KEY',
          search: '/api/soundcloud?action=search&query=iqro&limit=10&api_key=YOUR_KEY',
          track: '/api/soundcloud?action=track&track_id=2258880134&api_key=YOUR_KEY',
          playlist: '/api/soundcloud?action=playlist&playlist_id=1734880683&api_key=YOUR_KEY'
        },
        curl_examples: {
          homepage: `curl -X GET "https://api.fazzcode.qzz.io/api/soundcloud?action=homepage&limit=10" -H "X-API-Key: YOUR_KEY"`,
          search: `curl -X GET "https://api.fazzcode.qzz.io/api/soundcloud?action=search&query=iqro&limit=10" -H "X-API-Key: YOUR_KEY"`,
          track: `curl -X GET "https://api.fazzcode.qzz.io/api/soundcloud?action=track&track_id=2258880134" -H "Authorization: Bearer YOUR_KEY"`
        }
      }
    }
  })
})

// API routes (require API key)
app.use('/api', validateApiKey)
app.use(cors())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static(path.join(__dirname, 'public')))

// Web interface (no API key required for viewing)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'))
})

// SoundCloud API endpoint
app.all('/api/soundcloud', async (req, res) => {
  const method = req.method
  const params = method === 'GET' ? req.query : req.body
  
  // Remove api_key from params to avoid passing to scraper
  delete params.api_key
  
  // Forward to scraper handler
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
  
  // Add API metadata to response
  const response = mockRes.data
  if (response && typeof response === 'object') {
    response.api_metadata = {
      key_used: req.apiKey ? `${req.apiKey.slice(0, 8)}...${req.apiKey.slice(-4)}` : null,
      rate_limit: 'Unlimited for now',
      timestamp: new Date().toISOString()
    }
  }
  
  res.status(mockRes.statusCode).json(response)
})

// Admin endpoint to refresh API keys (protected with master key)
app.post('/admin/refresh-keys', validateApiKey, async (req, res) => {
  const masterKey = req.headers['x-master-key'] || req.query.master_key
  
  // Master key validation (hardcoded or from env)
  const validMasterKey = process.env.MASTER_KEY || 'fazzcode_admin_2024'
  
  if (masterKey !== validMasterKey) {
    return res.status(403).json({
      status: false,
      message: 'Invalid master key'
    })
  }
  
  const success = await fetchApiKeys()
  if (success) {
    res.json({
      status: true,
      message: `API keys refreshed successfully. ${validApiKeys.size} keys loaded.`,
      last_update: new Date(keyLastUpdate).toISOString(),
      valid_keys_count: validApiKeys.size
    })
  } else {
    res.status(500).json({
      status: false,
      message: 'Failed to refresh API keys'
    })
  }
})

// Initialize API keys on startup
async function init() {
  await fetchApiKeys()
  
  // Refresh keys periodically
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
    console.log(`🔄 Key cache duration: ${KEY_CACHE_DURATION / 1000} seconds\n`)
  })
}

init()

module.exports = app
