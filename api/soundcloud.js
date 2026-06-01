// soundcloud.js - SoundCloud music scraper untuk Express
const axios = require('axios')

const BASE_API = 'https://api-mobi.soundcloud.com'
const CLIENT_ID = 'KKzJxmw11tYpCs6T24P4uUYhqmjalG6M'
const UA = 'Mozilla/5.0 (Android 15; Mobile; rv:151.0) Gecko/151.0 Firefox/151.0'
const ANON_ID = '674609-115801-841304-416340'
const APP_VERSION = '1780038778'

const headers = {
  'Accept': 'application/json, text/javascript, */*; q=0.1',
  'Content-Type': 'application/json',
  'User-Agent': UA,
  'Referer': 'https://m.soundcloud.com/'
}

function formatDuration(ms) {
  if (!ms) return null
  const minutes = Math.floor(ms / 60000)
  const seconds = Math.floor((ms % 60000) / 1000)
  return `${minutes}:${seconds.toString().padStart(2, '0')}`
}

function formatDate(dateStr) {
  if (!dateStr) return null
  return new Date(dateStr).toISOString().split('T')[0]
}

async function fetchJson(url) {
  const { data } = await axios.get(url, { headers, timeout: 30000 })
  return data
}

async function postJson(url, body) {
  const { data } = await axios.post(url, body, { headers, timeout: 30000 })
  return data
}

async function sendAnalytics() {
  const analyticsData = {
    events: [
      {
        event: "click",
        version: "v1.27.27",
        payload: {
          chapter: "", context: "", level: "homepage:main",
          click_name: "authentication::dismiss", click_attributes: {},
          event_name: "Sign-up Dismissed", page_name: "homepage:main",
          referrer_properties: {}, anonymous_id: ANON_ID, client_id: 65097,
          ts: Date.now(), url: "https://m.soundcloud.com/", app_version: APP_VERSION
        }
      },
      {
        event: "click",
        version: "v1.27.27",
        payload: {
          chapter: "", context: "", level: "homepage:main",
          click_name: "performance_consent", click_attributes: { consent_setting: "consent" },
          event_name: "Performance Consent Retrieved", page_name: "homepage:main",
          referrer_properties: {}, anonymous_id: ANON_ID, client_id: 65097,
          ts: Date.now() + 1000, url: "https://m.soundcloud.com/", app_version: APP_VERSION
        }
      }
    ],
    sent_at: new Date().toISOString()
  }
  try { await postJson(`${BASE_API}/me?client_id=${CLIENT_ID}&stage=`, analyticsData) } catch(e) {}
}

async function sendPageview() {
  const pageviewData = {
    events: [
      {
        event: "pageview", version: "v1.27.27",
        payload: {
          level: "homepage:main", chapter: "", event_name: "Home Viewed",
          page_name: "homepage:main", referrer_properties: {}, locale: "en",
          navigation_type: "initial", currently_playing: false,
          anonymous_id: ANON_ID, client_id: 65097, ts: Date.now(),
          url: "https://m.soundcloud.com/", app_version: APP_VERSION
        }
      },
      {
        event: "impression", version: "v1.27.27",
        payload: {
          impression_name: "upsell_banner", impression_attributes: {},
          page_name: "homepage:main", referrer_properties: {}, page_context: "",
          anonymous_id: ANON_ID, client_id: 65097, ts: Date.now() + 100,
          url: "https://m.soundcloud.com/", app_version: APP_VERSION
        }
      },
      {
        event: "appload", version: "v1.27.27",
        payload: {
          latency: 2618, level: "homepage:main", page_name: "homepage:main",
          anonymous_id: ANON_ID, client_id: 65097, ts: Date.now() + 300,
          url: "https://m.soundcloud.com/", app_version: APP_VERSION
        }
      }
    ],
    sent_at: new Date().toISOString()
  }
  try { await postJson(`${BASE_API}/me?client_id=${CLIENT_ID}&stage=`, pageviewData) } catch(e) {}
}

async function getMixedSelections() {
  return await fetchJson(`${BASE_API}/mixed-selections?meOrAnonymousUserUrn=soundcloud%3Ausers%3Aanonymous&app_locale=en&client_id=${CLIENT_ID}&stage=`)
}

async function getPlaylist(playlistId) {
  return await fetchJson(`${BASE_API}/playlists/${playlistId}?client_id=${CLIENT_ID}&stage=`)
}

async function getTrack(trackId) {
  return await fetchJson(`${BASE_API}/tracks/${trackId}?client_id=${CLIENT_ID}&stage=`)
}

async function getRelatedTracks(trackId, limit = 10) {
  return await fetchJson(`${BASE_API}/tracks/${trackId}/related?anon_user_id=${ANON_ID}&user_id=${ANON_ID}&app_version=${APP_VERSION}&client_id=${CLIENT_ID}&linked_partitioning=1&limit=${limit}&stage=`)
}

async function getTrackComments(trackId, limit = 50) {
  let allComments = []
  let url = `${BASE_API}/tracks/${trackId}/comments?threaded=0&filter_replies=1&limit=50&client_id=${CLIENT_ID}&stage=`
  
  while (url && allComments.length < limit) {
    const data = await fetchJson(url)
    const comments = data.collection || []
    allComments = allComments.concat(comments)
    url = data.next_href
    if (url && allComments.length < limit) await new Promise(r => setTimeout(r, 100))
  }
  return allComments.slice(0, limit)
}

async function getStreamingUrl(mediaInfo, trackAuth) {
  if (!mediaInfo?.url) return null
  const { data } = await axios.get(`${mediaInfo.url}?client_id=${CLIENT_ID}&track_authorization=${trackAuth}&stage=`, { headers, timeout: 30000 })
  return data?.url || null
}

async function searchSuggestions(query, limit = 5) {
  return await fetchJson(`${BASE_API}/search/queries?q=${encodeURIComponent(query)}&limit=${limit}&client_id=${CLIENT_ID}&stage=`)
}

async function searchTracks(query, limit = 20) {
  const data = await fetchJson(`${BASE_API}/search?q=${encodeURIComponent(query)}&client_id=${CLIENT_ID}&stage=`)
  const tracks = (data.collection || []).filter(item => item.kind === 'track').slice(0, limit)
  return { total_results: data.total_results || 0, tracks, next_href: data.next_href }
}

function parseTrack(track, includeMedia = false) {
  const result = {
    id: track.id,
    title: track.title,
    artist: track.user?.username,
    artist_verified: track.user?.verified || false,
    duration: formatDuration(track.duration),
    full_duration: formatDuration(track.full_duration),
    likes: track.likes_count || 0,
    plays: track.playback_count || 0,
    comments: track.comment_count || 0,
    reposts: track.reposts_count || 0,
    genre: track.genre || null,
    release_date: formatDate(track.release_date),
    created_at: formatDate(track.created_at),
    url: track.permalink_url,
    artwork: track.artwork_url,
    waveform: track.waveform_url,
    explicit: track.publisher_metadata?.explicit || false,
    policy: track.policy,
    streamable: track.streamable || false,
    downloadable: track.downloadable || false
  }
  
  if (includeMedia && track.media?.transcodings?.length) {
    const preview = track.media.transcodings.find(t => t.preset === 'mp3_1_0' || t.format?.protocol === 'progressive')
    result.preview_url = preview ? `${preview.url}?client_id=${CLIENT_ID}&track_authorization=${track.track_authorization}&stage=` : null
  }
  
  return result
}

function parsePlaylist(playlist, includeTracks = true) {
  const result = {
    id: playlist.id,
    title: playlist.title,
    description: playlist.description || null,
    user: playlist.user?.username,
    user_verified: playlist.user?.verified || false,
    track_count: playlist.track_count,
    likes: playlist.likes_count || 0,
    reposts: playlist.reposts_count || 0,
    duration: formatDuration(playlist.duration),
    genre: playlist.genre || null,
    created_at: formatDate(playlist.created_at),
    last_modified: formatDate(playlist.last_modified),
    url: playlist.permalink_url,
    artwork: playlist.artwork_url
  }
  
  if (includeTracks && playlist.tracks) {
    result.tracks = playlist.tracks.filter(t => t.id).map(t => parseTrack(t, false))
  }
  
  return result
}

async function getHomepage(limit = 20) {
  await sendAnalytics()
  await sendPageview()
  
  const selections = await getMixedSelections()
  const playlists = []
  
  for (const selection of selections.collection || []) {
    if (selection.items?.collection) {
      for (const item of selection.items.collection.slice(0, limit)) {
        if (item.kind === 'playlist' && item.id) {
          try {
            const playlist = await getPlaylist(item.id)
            playlists.push({
              category: selection.title,
              ...parsePlaylist(playlist, false)
            })
          } catch(e) {}
          await new Promise(r => setTimeout(r, 200))
        }
      }
    }
  }
  
  return playlists
}

async function getTrackDetail(trackId) {
  const track = await getTrack(trackId)
  if (!track || !track.id) throw new Error('Track tidak ditemukan')
  
  const [related, comments] = await Promise.all([
    getRelatedTracks(trackId, 10),
    getTrackComments(trackId, 20)
  ])
  
  let streamingUrl = null
  const previewTranscoding = track.media?.transcodings?.find(
    t => t.preset === 'mp3_1_0' || t.format?.protocol === 'progressive'
  )
  if (previewTranscoding && track.track_authorization) {
    streamingUrl = await getStreamingUrl(previewTranscoding, track.track_authorization)
  }
  
  return {
    track: parseTrack(track, true),
    streaming_url: streamingUrl,
    related_tracks: (related.collection || []).slice(0, 10).map(t => parseTrack(t, false)),
    comments: comments.map(c => ({
      id: c.id,
      body: c.body,
      created_at: formatDate(c.created_at),
      timestamp: c.timestamp,
      user: c.user?.username,
      user_avatar: c.user?.avatar_url
    }))
  }
}

async function getPlaylistDetail(playlistId) {
  const playlist = await getPlaylist(playlistId)
  if (!playlist || !playlist.id) throw new Error('Playlist tidak ditemukan')
  return parsePlaylist(playlist, true)
}

// Handler untuk Express
async function handleSoundCloud(req, res) {
  const action = req.query.action || req.body.action || 'homepage'
  const query = req.query.query || req.body.query || req.query.q || req.body.q || ''
  const trackId = parseInt(req.query.track_id || req.body.track_id || '0')
  const playlistId = parseInt(req.query.playlist_id || req.body.playlist_id || '0')
  const limit = Math.min(50, parseInt(req.query.limit || req.body.limit || 20))

  try {
    // Action: homepage - get trending/homepage playlists
    if (action === 'homepage') {
      const results = await getHomepage(limit)
      return res.json({
        status: true,
        message: `${results.length} playlist trending`,
        results
      })
    }
    
    // Action: search - search tracks by keyword
    if (action === 'search') {
      if (!query) {
        return res.status(400).json({
          status: false,
          message: 'Parameter "query" wajib diisi'
        })
      }
      
      const suggestions = await searchSuggestions(query, 5)
      const searchResult = await searchTracks(query, limit)
      
      return res.json({
        status: true,
        query,
        suggestions: (suggestions.collection || []).slice(0, 5).map(s => s.output),
        total_results: searchResult.total_results,
        results: searchResult.tracks.map(t => parseTrack(t, false))
      })
    }
    
    // Action: track - get track details, related tracks, comments, and streaming URL
    if (action === 'track') {
      if (!trackId || isNaN(trackId)) {
        return res.status(400).json({
          status: false,
          message: 'Parameter "track_id" wajib diisi (angka)'
        })
      }
      
      const detail = await getTrackDetail(trackId)
      return res.json({
        status: true,
        detail
      })
    }
    
    // Action: playlist - get playlist details with tracks
    if (action === 'playlist') {
      if (!playlistId || isNaN(playlistId)) {
        return res.status(400).json({
          status: false,
          message: 'Parameter "playlist_id" wajib diisi (angka)'
        })
      }
      
      const playlist = await getPlaylistDetail(playlistId)
      return res.json({
        status: true,
        playlist
      })
    }
    
    // Invalid action
    return res.status(400).json({
      status: false,
      message: 'Action tidak valid',
      actions: ['homepage', 'search', 'track', 'playlist'],
      examples: [
        '/api/soundcloud?action=homepage&limit=10',
        '/api/soundcloud?action=search&query=iqro&limit=10',
        '/api/soundcloud?action=track&track_id=2258880134',
        '/api/soundcloud?action=playlist&playlist_id=1734880683'
      ]
    })
    
  } catch (error) {
    console.error('SoundCloud scraper error:', error.message)
    return res.status(500).json({
      status: false,
      message: error.message
    })
  }
}

module.exports = {
  handleSoundCloud,
  getHomepage,
  getTrackDetail,
  getPlaylistDetail,
  searchTracks,
  searchSuggestions
}
