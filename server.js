// server.js — PRODUCTION READY FOR manamingle.site
const MAX_USERS = 300; // Maximum concurrent users
const MAX_QUEUE_SIZE = 100; // Maximum users in queue
const RATE_LIMIT_WINDOW = 60000; // 1 minute in milliseconds
const RATE_LIMIT_MAX = 100; // Max requests per window
const MESSAGE_HISTORY_SIZE = 50; // Store last 50 messages per room
const MAX_TEXT_USERS = 6;
const MAX_VIDEO_USERS = 4;

const express = require("express");
const http = require("http");
const cors = require("cors");
const path = require("path");
const helmet = require("helmet");
const { Server } = require("socket.io");
const fs = require("fs").promises;
const rateLimit = require("express-rate-limit");
const compression = require("compression");
const geoip = require("geoip-lite");
require("dotenv").config();

const app = express();
app.set('trust proxy', 1);

/* ================= CONFIG ================= */
const PORT = process.env.PORT || 3000;
const HOST = "0.0.0.0";
const NODE_ENV = process.env.NODE_ENV || "development";
const DOMAIN = process.env.DOMAIN || "manamingle.site";

// Admin credentials from environment variables (production: required, dev: safe fallbacks)
const ADMIN_CREDENTIALS = {
  // Accept multiple aliases to avoid deploy env mismatch
  username: process.env.ADMIN_USERNAME || process.env.ADMIN_USER || (NODE_ENV !== "production" ? "admin" : ""),
  password: process.env.ADMIN_PASSWORD || process.env.ADMIN_PASS || (NODE_ENV !== "production" ? "ChangeMe123!" : ""),
  adminKey: process.env.ADMIN_SECRET_KEY || process.env.ADMIN_KEY || process.env.ADMIN_SECRET || (NODE_ENV !== "production" ? "dev-admin-key" : "")
};

// Ad System Configuration
const AD_CONFIG_FILE = path.join(__dirname, "ad-config.json");
let adConfig = {
  enabled: false,
  frequency: 10, // minutes
  type: "placeholder", // 'placeholder' or 'adsense'
  placeholderContent: "<h3>Advertisement</h3><p>Support us by disabling adblock!</p>",
  adsenseClientId: "",
  adsenseSlotId: ""
};

// Load Ad Config
async function loadAdConfig() {
  try {
    const data = await fs.readFile(AD_CONFIG_FILE, "utf8");
    adConfig = { ...adConfig, ...JSON.parse(data) };
    console.log("📢 Ad configuration loaded");
  } catch (error) {
    console.log("ℹ️ No ad config found, using defaults");
  }
}
loadAdConfig();

async function saveAdConfig(newConfig) {
  adConfig = { ...adConfig, ...newConfig };
  await fs.writeFile(AD_CONFIG_FILE, JSON.stringify(adConfig, null, 2));
  return adConfig;
}

// Validate required environment variables
if (NODE_ENV === "production") {
  const required = [
    { names: ["ADMIN_USERNAME", "ADMIN_USER"], value: ADMIN_CREDENTIALS.username },
    { names: ["ADMIN_PASSWORD", "ADMIN_PASS"], value: ADMIN_CREDENTIALS.password },
    { names: ["ADMIN_SECRET_KEY", "ADMIN_KEY", "ADMIN_SECRET"], value: ADMIN_CREDENTIALS.adminKey }
  ];
  for (const r of required) {
    if (!r.value) {
      console.error(`❌ ERROR: Missing required admin env. Set one of: ${r.names.join(", ")}`);
      process.exit(1);
    }
  }
}

/* ================= PATHS ================= */
const publicPath = path.join(__dirname, "public");
const logsPath = path.join(__dirname, "logs");
const backupPath = path.join(__dirname, "backups");

/* ================= LOGGING SETUP ================= */
async function setupLogging() {
  try {
    await fs.mkdir(logsPath, { recursive: true });
    await fs.mkdir(backupPath, { recursive: true });
    console.log("✅ Logs and backups directories ready");
  } catch (error) {
    console.error("❌ Failed to create directories:", error);
  }
}

async function logToFile(filename, data) {
  try {
    const logFile = path.join(logsPath, filename);
    const timestamp = new Date().toISOString();
    const logEntry = `${timestamp} - ${JSON.stringify(data)}\n`;
    await fs.appendFile(logFile, logEntry);
  } catch (error) {
    console.error("Failed to write log:", error);
  }
}

/* ================= BACKUP SYSTEM ================= */
async function backupState() {
  try {
    const backupData = {
      timestamp: Date.now(),
      rooms: Array.from(state.rooms.entries()),
      users: Array.from(state.users.entries()),
      reports: state.reports,
      blockedUsers: Array.from(state.blockedUsers),
      blockedIPs: Array.from(state.blockedIPs),
      blockedTokens: Array.from(state.blockedTokens)
    };
    
    const backupFile = path.join(backupPath, `backup_${Date.now()}.json`);
    await fs.writeFile(backupFile, JSON.stringify(backupData, null, 2));
    
    // Keep only last 10 backups
    const files = await fs.readdir(backupPath);
    if (files.length > 10) {
      const sortedFiles = files.sort();
      const filesToDelete = sortedFiles.slice(0, files.length - 10);
      for (const file of filesToDelete) {
        await fs.unlink(path.join(backupPath, file));
      }
    }
  } catch (error) {
    console.error("Backup failed:", error);
  }
}

/* ================= MIDDLEWARE ================= */
// Security headers
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://cdn.socket.io",
          "https://cdn.jsdelivr.net"
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://fonts.googleapis.com",
          "https://cdnjs.cloudflare.com"
        ],
        fontSrc: [
          "'self'",
          "https://fonts.gstatic.com",
          "https://cdnjs.cloudflare.com"
        ],
        imgSrc: [
          "'self'",
          "data:",
          "blob:",
          "https:"
        ],
        mediaSrc: [
          "'self'",
          "blob:",
          "mediastream:"
        ],
        connectSrc: [
          "'self'",
          "wss:",
          "ws:",
          "https:"
        ]
      }
    },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" }
  })
);

// Rate limiting for API endpoints
const apiLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW,
  max: RATE_LIMIT_MAX,
  message: { error: "Too many requests, please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

// IP-based rate limiting
const ipLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  message: { error: "Too many requests from this IP." },
  keyGenerator: (req) => req.ip
});

// CORS configuration
const corsOptions = {
  origin: NODE_ENV === "production" 
    ? [`https://${DOMAIN}`, `https://www.${DOMAIN}`]
    : true,
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"]
};

app.use(cors(corsOptions));
app.use(compression());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(express.static(publicPath, { 
  maxAge: NODE_ENV === "production" ? "1d" : "0",
  setHeaders: (res, path) => {
    if (path.endsWith(".html")) {
      res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    }
  }
}));
app.use(ipLimiter);

/* ================= ADMIN AUTH MIDDLEWARE ================= */
function authenticateAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Authentication required" });
  }
  
  const token = authHeader.substring(7);
  if (token !== ADMIN_CREDENTIALS.adminKey) {
    return res.status(403).json({ error: "Invalid admin key" });
  }
  
  next();
}

/* ================= ROUTES ================= */
// ICE / TURN ENDPOINT
app.get("/api/turn", (req, res) => {
  if (!process.env.TURN_USERNAME || !process.env.TURN_PASSWORD) {
    return res.json({
      iceServers: [
        { urls: "stun:stun.l.google.com:19302" },
        { urls: "stun:stun1.l.google.com:19302" },
        { urls: "stun:stun2.l.google.com:19302" },
        { urls: "stun:stun3.l.google.com:19302" },
        { urls: "stun:stun4.l.google.com:19302" }
      ]
    });
  }

  res.json({
    iceServers: [
      { urls: "stun:stun.l.google.com:19302" },
      {
        urls: "turn:global.relay.metered.ca:443",
        username: process.env.TURN_USERNAME,
        credential: process.env.TURN_PASSWORD
      },
      {
        urls: "turns:global.relay.metered.ca:443?transport=tcp",
        username: process.env.TURN_USERNAME,
        credential: process.env.TURN_PASSWORD
      }
    ]
  });
});

app.post("/api/translate", express.json(), async (req, res) => {
  try {
    const body = req.body || {};
    const text = String(body.text || "").trim().slice(0, 2000);
    const source = String(body.source || "auto");
    const target = String(body.target || "").toLowerCase();
    if (!text || !target) return res.status(400).json({ error: "bad_request" });
    const url = process.env.TRANSLATE_URL || "https://libretranslate.com/translate";
    const payload = { q: text, source: source, target: target, format: "text" };
    if (process.env.TRANSLATE_API_KEY) payload.api_key = process.env.TRANSLATE_API_KEY;
    const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    if (!r.ok) return res.status(502).json({ error: "translate_failed" });
    const data = await r.json();
    const translated = data.translatedText || data.text || "";
    res.json({ text: translated });
  } catch (e) {
    res.status(500).json({ error: "translate_error" });
  }
});

// Health check endpoint
app.get("/health", (req, res) => {
  const memoryUsage = process.memoryUsage();
  const rooms = Array.from(state.rooms.values());
  
  res.json({
    status: "healthy",
    uptime: process.uptime(),
    timestamp: Date.now(),
    memory: {
      heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024) + "MB",
      heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024) + "MB",
      rss: Math.round(memoryUsage.rss / 1024 / 1024) + "MB"
    },
    connections: {
      users: state.users.size,
      queue: state.connectionQueue.length,
      rooms: rooms.length,
      activeRooms: rooms.filter(r => r.status === 'active').length
    },
    environment: NODE_ENV,
    version: "1.0.0"
  });
});

app.post("/api/report-user", apiLimiter, (req, res) => {
  try {
    const { reportedUserId, reason, description, category, details, evidence, email } = req.body || {};
    const report = {
      id: `rep_${Date.now()}_${Math.random().toString(36).slice(2)}`,
      reporterEmail: String(email || "").slice(0, 120) || null,
      reportedUserId: String(reportedUserId || "").slice(0, 120) || null,
      reason: String(reason || category || "").slice(0, 120) || "unspecified",
      description: String(description || details || "").slice(0, 4000),
      evidence: String(evidence || "").slice(0, 4000) || null,
      roomId: null,
      timestamp: Date.now(),
      status: "pending",
      type: "external"
    };
    state.reports.push(report);
    io.to("admins").emit("new-report", report);
    io.to("admins").emit("admin-state", getPublicStateForAdmin());
    res.json({ success: true, id: report.id });
  } catch (e) {
    res.status(500).json({ success: false, error: "report_error" });
  }
});

app.post("/api/contact-support", apiLimiter, (req, res) => {
  try {
    const { subject, message, email } = req.body || {};
    const contact = {
      id: `cnt_${Date.now()}_${Math.random().toString(36).slice(2)}`,
      subject: String(subject || "").slice(0, 200) || "Support",
      message: String(message || "").slice(0, 4000),
      email: String(email || "").slice(0, 120) || null,
      timestamp: Date.now(),
      status: "new"
    };
    state.contacts.push(contact);
    io.to("admins").emit("new-contact", contact);
    res.json({ success: true, id: contact.id });
  } catch (e) {
    res.status(500).json({ success: false, error: "contact_error" });
  }
});

// Admin panel
app.get("/admin", (req, res) => {
  res.sendFile(path.join(publicPath, "admin.html"));
});

// Admin login endpoint
app.post("/admin/login", apiLimiter, (req, res) => {
  const { username, password, adminKey } = req.body;

  // Log attempt (without sensitive data)
  console.log(`🔐 Admin login attempt from ${req.ip}: User=${username}`);

  // Check username and password first
  if (username !== ADMIN_CREDENTIALS.username || password !== ADMIN_CREDENTIALS.password) {
    console.log(`❌ Admin login failed: Invalid Credentials for ${username}`);
    return res.status(401).json({ 
      success: false, 
      error: "Invalid credentials" 
    });
  }

  // Check admin key
  if (!adminKey || adminKey !== ADMIN_CREDENTIALS.adminKey) {
     console.log(`❌ Admin login failed: Invalid Key for ${username}`);
     return res.status(401).json({ 
       success: false, 
       error: "Invalid Security Key" 
     });
  }

  console.log(`✅ Admin login success for ${username}`);
  res.json({ 
    success: true, 
    token: ADMIN_CREDENTIALS.adminKey,
    expiresIn: "24h"
  });
});

// Admin API endpoints (protected)
app.get("/admin/stats", authenticateAdmin, (req, res) => {
  res.json(getPublicStateForAdmin());
});

app.post("/admin/ban", authenticateAdmin, apiLimiter, (req, res) => {
  const { type, value, reason, duration } = req.body;
  
  if (!type || !value) {
    return res.status(400).json({ error: "Missing type or value" });
  }
  
  const banData = {
    type,
    value,
    reason: reason || "No reason provided",
    bannedAt: Date.now(),
    bannedBy: req.ip,
    duration: duration || null,
    expiresAt: duration ? Date.now() + (duration * 1000) : null
  };
  
  switch (type) {
    case "user":
      state.blockedUsers.set(value, banData);
      break;
    case "ip":
      state.blockedIPs.set(value, banData);
      break;
    case "token":
      state.blockedTokens.set(value, banData);
      break;
    default:
      return res.status(400).json({ error: "Invalid ban type" });
  }
  
  logAdminAction(req.ip, "BAN_ADDED", banData);
  res.json({ success: true, message: `Banned ${type}: ${value}`, data: banData });
});

// Ad System Endpoints
app.get("/api/ads/config", (req, res) => {
  // Public endpoint to get ad config (sanitized if needed, but here we send all for simplicity)
  res.json(adConfig);
});

app.post("/api/admin/ads/config", authenticateAdmin, async (req, res) => {
  try {
    const updatedConfig = await saveAdConfig(req.body);
    // Notify all connected clients to update their ad settings immediately
    io.emit("ad_config_update", updatedConfig);
    logAdminAction(req.ip, "AD_CONFIG_UPDATE", updatedConfig);
    res.json({ success: true, config: updatedConfig });
  } catch (error) {
    res.status(500).json({ error: "Failed to save ad config" });
  }
});

app.delete("/admin/ban/:type/:value", authenticateAdmin, (req, res) => {
  const { type, value } = req.params;
  
  let success = false;
  switch (type) {
    case "user":
      success = state.blockedUsers.delete(value);
      break;
    case "ip":
      success = state.blockedIPs.delete(value);
      break;
    case "token":
      success = state.blockedTokens.delete(value);
      break;
    default:
      return res.status(400).json({ error: "Invalid ban type" });
  }
  
  if (success) {
    logAdminAction(req.ip, "BAN_REMOVED", { type, value });
    res.json({ success: true, message: `Unbanned ${type}: ${value}` });
  } else {
    res.status(404).json({ error: `${type} not found in ban list` });
  }
});

// Debug endpoint for room status
app.get("/debug/room/:roomId", authenticateAdmin, (req, res) => {
  const roomId = req.params.roomId;
  const room = state.rooms.get(roomId);
  
  if (!room) {
    return res.status(404).json({ error: "Room not found" });
  }
  
  const socketStatus = Array.from(room.users).map(socketId => {
    const socket = io.sockets.sockets.get(socketId);
    const userData = state.users.get(socketId);
    return {
      socketId,
      connected: socket?.connected || false,
      userId: userData?.id,
      userName: userData?.name,
      userAgent: userData?.userAgent,
      ip: userData?.ip
    };
  });
  
  res.json({
    roomId,
    mode: room.mode,
    status: room.status,
    users: socketStatus,
    totalUsers: room.users.size,
    maxSize: ROOM_MAX_SIZE[room.mode],
    createdAt: room.createdAt,
    lastActivity: room.lastActivity,
    messages: room.messages?.length || 0,
    isBanned: room.isBanned
  });
});

// Load testing endpoint (admin only)
app.post("/admin/load-test", authenticateAdmin, (req, res) => {
  const { action, count = 10 } = req.body;
  
  if (action === "simulate") {
    const stats = {
      before: {
        users: state.users.size,
        rooms: state.rooms.size,
        memory: process.memoryUsage().heapUsed
      },
      simulated: count
    };
    
    for (let i = 0; i < Math.min(count, 50); i++) {
      const roomId = `test_${Date.now()}_${i}`;
      state.rooms.set(roomId, {
        id: roomId,
        mode: 'text',
        users: new Set(),
        participants: [],
        tags: ['test'],
        createdAt: Date.now(),
        lastActivity: Date.now(),
        status: "active",
        isBanned: false
      });
    }
    
    stats.after = {
      users: state.users.size,
      rooms: state.rooms.size,
      memory: process.memoryUsage().heapUsed
    };
    
    res.json({ success: true, stats });
  } else {
    res.json({ error: "Invalid action" });
  }
});

// Video chat endpoint
app.get("/video", (req, res) => {
  res.sendFile(path.join(publicPath, "video.html"));
});

// Main page
app.get("/", (req, res) => {
  res.sendFile(path.join(publicPath, "index.html"));
});

// 404 handler
app.use((req, res) => {
  res.status(404).sendFile(path.join(publicPath, "404.html"));
});

// Error handler
app.use((err, req, res, next) => {
  console.error("Server error:", err);
  logToFile("server-errors.log", {
    error: err.message,
    stack: err.stack,
    timestamp: Date.now(),
    url: req.url,
    ip: req.ip
  });
  
  res.status(500).json({ 
    error: NODE_ENV === "production" ? "Internal server error" : err.message 
  });
});

/* ================= SERVER SETUP ================= */
const server = http.createServer(app);

const io = new Server(server, {
  transports: ["websocket", "polling"],
  pingInterval: 25000,
  pingTimeout: 20000,
  connectTimeout: 30000,
  maxHttpBufferSize: 10e6,
  cors: corsOptions,
  allowEIO3: true,
  serveClient: false,
  connectionStateRecovery: {
    maxDisconnectionDuration: 2 * 60 * 1000,
    skipMiddlewares: true
  }
});

/* ================= GLOBAL STATE ================= */
const state = {
  waiting: {
    text: new Map(),
    video: new Map(),
    audio: new Map(),
    group_text: new Map(),
    group_video: new Map()
  },
  
  rooms: new Map(),
  users: new Map(),
  reports: [],
  contacts: [],
  
  blockedUsers: new Map(),
  blockedIPs: new Map(),
  blockedTokens: new Map(),
  
  admins: new Set(),
  securityLogs: [],
  
  socketRateLimits: new Map(),
  connectionQueue: [],
  messageHistory: new Map()
};

// Room size limits
const ROOM_MAX_SIZE = {
  text: 2,
  video: 2,
  audio: 2,
  group_text: MAX_TEXT_USERS,
  group_video: MAX_VIDEO_USERS
};

// Room timeout configurations
const ROOM_TIMEOUTS = {
  text: 30 * 60 * 1000,
  video: 60 * 60 * 1000,
  audio: 60 * 60 * 1000,
  group_text: 120 * 60 * 1000,
  group_video: 90 * 60 * 1000
};

/* ================= HELPER FUNCTIONS ================= */
function generateRoomId() {
  return `room_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
}

function generateUserId() {
  return `usr_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
}

function getUserIP(socket) {
  const forwardedFor = socket.handshake.headers['x-forwarded-for'];
  return forwardedFor 
    ? forwardedFor.split(',')[0].trim() 
    : socket.handshake.address;
}

function getUserCountry(ip) {
  try {
    const geo = geoip.lookup(ip);
    return geo ? geo.country : null;
  } catch (e) {
    return null;
  }
}

function isRateLimited(socketId, type = "message") {
  const now = Date.now();
  const userLimits = state.socketRateLimits.get(socketId) || {};
  
  if (!userLimits[type]) {
    userLimits[type] = { count: 1, firstRequest: now, lastRequest: now };
    state.socketRateLimits.set(socketId, userLimits);
    return false;
  }
  
  const limit = userLimits[type];
  
  if (now - limit.firstRequest > 60000) {
    limit.count = 1;
    limit.firstRequest = now;
    limit.lastRequest = now;
    return false;
  }
  
  const maxRequests = {
    message: 60,
    join: 10,
    skip: 20,
    signal: 200,
    typing: 30,
    media: 500,
    report: 5,
    ai_flag: 60
  };
  
  limit.count++;
  limit.lastRequest = now;
  
  if (limit.count > (maxRequests[type] || 30)) {
    logSecurityEvent('RATE_LIMIT_EXCEEDED', { socketId, type, count: limit.count });
    return true;
  }
  
  return false;
}

function logSecurityEvent(event, details = {}) {
  const log = {
    timestamp: Date.now(),
    event,
    ...details,
    environment: NODE_ENV
  };
  
  state.securityLogs.unshift(log);
  
  if (state.securityLogs.length > 2000) {
    state.securityLogs.pop();
  }
  
  if (NODE_ENV === "production") {
    logToFile("security.log", log);
  }
  
  console.log(`🔒 ${event}`, Object.keys(details).length > 0 ? details : "");
}

function logAdminAction(adminId, action, details = {}) {
  const log = {
    timestamp: Date.now(),
    adminId,
    action,
    ...details
  };
  
  console.log(`👮 ADMIN: ${action} by ${adminId}`);
  
  io.to('admins').emit('admin-action-log', log);
  logToFile("admin.log", log);
}

function isUserBlocked(userId, ip, token) {
  if (state.blockedUsers.has(userId)) {
    const ban = state.blockedUsers.get(userId);
    if (ban.expiresAt && Date.now() > ban.expiresAt) {
      state.blockedUsers.delete(userId);
      return false;
    }
    return true;
  }
  
  if (state.blockedIPs.has(ip)) {
    const ban = state.blockedIPs.get(ip);
    if (ban.expiresAt && Date.now() > ban.expiresAt) {
      state.blockedIPs.delete(ip);
      return false;
    }
    return true;
  }
  
  if (token && state.blockedTokens.has(token)) {
    const ban = state.blockedTokens.get(token);
    if (ban.expiresAt && Date.now() > ban.expiresAt) {
      state.blockedTokens.delete(token);
      return false;
    }
    return true;
  }
  
  return false;
}

function normalizeTag(s) { return String(s || '').toLowerCase().trim(); }
function levenshtein(a, b) {
  a = normalizeTag(a); b = normalizeTag(b);
  const m = a.length, n = b.length;
  if (!m) return n; if (!n) return m;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}
function similarity(a, b) {
  const len = Math.max(String(a || '').length, String(b || '').length);
  if (len === 0) return 0;
  return 1 - (levenshtein(a, b) / len);
}
const synonyms = {
  music: ['songs','pop','rock','hip hop','rap','classical','edm'],
  movies: ['film','cinema','hollywood','bollywood'],
  gaming: ['games','video games','gamer','console','pc gaming'],
  travel: ['tourism','vacation','trip'],
  fitness: ['gym','workout','exercise'],
  food: ['cooking','cuisine','restaurant','chef'],
  technology: ['tech','programming','coding','software','hardware'],
  art: ['painting','drawing','design','creative'],
  sports: ['football','soccer','basketball','cricket','tennis']
};
function expandTags(tags) {
  const out = new Set();
  for (const t of tags || []) {
    const base = normalizeTag(t);
    if (!base) continue;
    out.add(base);
    const syns = synonyms[base];
    if (syns) syns.forEach(s => out.add(normalizeTag(s)));
  }
  return out;
}
function findMatchForUser(selfSocketId, mode, userTags = []) {
  const waitingUsers = Array.from(state.waiting[mode].entries());
  
  if (waitingUsers.length === 0) {
    return null;
  }
  
  let bestInterestMatch = null;
  let bestInterestScore = -1;
  let randomMatch = null;
  
  for (const [socketId, userData] of waitingUsers) {
    if (socketId === selfSocketId) continue;
    if (userTags.length > 0 && userData.tags && userData.tags.length > 0) {
      const userTagSet = expandTags(userTags);
      const otherTagSet = expandTags(userData.tags);
      let matchScore = 0;
      for (const tag of userTagSet) {
        if (otherTagSet.has(tag)) matchScore += 2;
        else {
          let bestSim = 0;
          for (const ot of otherTagSet) {
            const sim = similarity(tag, ot);
            if (sim > bestSim) bestSim = sim;
          }
          if (bestSim >= 0.8) matchScore += 2;
          else if (bestSim >= 0.6) matchScore += 1;
        }
      }
      if (matchScore > 0 && matchScore > bestInterestScore) {
        bestInterestScore = matchScore;
        bestInterestMatch = { 
          socketId, 
          userData: { ...userData },
          matchScore 
        };
      }
    }
    
    if (!randomMatch) {
      randomMatch = { socketId, userData };
    }
  }
  
  if (bestInterestMatch && bestInterestScore > 0) {
    return bestInterestMatch;
  }
  
  return randomMatch;
}

function createRoom(mode, creatorSocketId, creatorData, ...otherUsers) {
  const roomId = generateRoomId();
  const allUsers = [{ socketId: creatorSocketId, data: creatorData }, ...otherUsers];
  
  const allTags = [];
  const allTokens = [];
  const participants = [];
  
  for (const user of allUsers) {
    allTags.push(...(user.data.tags || []));
    if (user.data.token) allTokens.push(user.data.token);
    
    participants.push({
      id: user.socketId,
      userId: user.data.id,
      name: user.data.name || 'Anonymous',
      tags: user.data.tags || [],
      joinedAt: Date.now(),
      ip: user.data.ip,
      country: getUserCountry(user.data.ip)
    });
  }
  
  const roomTags = [...new Set(allTags)];
  
  const room = {
    id: roomId,
    mode: mode,
    users: new Set(allUsers.map(u => u.socketId)),
    participants: participants,
    tags: roomTags,
    tokens: allTokens,
    createdAt: Date.now(),
    lastActivity: Date.now(),
    status: "active",
    isBanned: false,
    messages: [],

    timeout: setTimeout(() => {
      endRoom(roomId, "timeout");
    }, ROOM_TIMEOUTS[mode] || 3600000)
  };
  
  state.rooms.set(roomId, room);
  state.messageHistory.set(roomId, []);
  
  return roomId;
}

function addUserToRoom(socketId, roomId, userData) {
  const room = state.rooms.get(roomId);
  if (!room) return false;
  
  const maxSize = ROOM_MAX_SIZE[room.mode];
  if (room.users.size >= maxSize) {
    return false;
  }
  
  room.users.add(socketId);
  room.participants.push({
    id: socketId,
    userId: userData.id,
    name: userData.name || 'Anonymous',
    tags: userData.tags || [],
    joinedAt: Date.now(),
    ip: userData.ip,
    country: getUserCountry(userData.ip)
  });
  
  if (userData.token) room.tokens.push(userData.token);
  room.lastActivity = Date.now();
  
  return true;
}

function removeUserFromRoom(socketId, roomId, reason = "left") {
  const room = state.rooms.get(roomId);
  if (!room) return false;

  room.users.delete(socketId);

  const participantIndex = room.participants.findIndex(p => p.id === socketId);
  if (participantIndex !== -1) {
    room.participants.splice(participantIndex, 1);
  }

  const remainingUsers = Array.from(room.users);
  if (remainingUsers.length > 0) {
    remainingUsers.forEach(remainingSocketId => {
      io.to(remainingSocketId).emit("partner-disconnected", {
        peerId: socketId,
        roomId,
        reason,
        remainingCount: remainingUsers.length
      });
      const leftUser = state.users.get(socketId);
      io.to(remainingSocketId).emit('user-left', {
        roomId,
        userId: leftUser?.id,
        participantCount: remainingUsers.length
      });
    });
  }

  if (room.users.size === 0) {
    endRoom(roomId, reason);
  }

  room.lastActivity = Date.now();
  return true;
}

function endRoom(roomId, reason = "ended") {
  const room = state.rooms.get(roomId);
  if (!room) return;

  if (room.timeout) {
    clearTimeout(room.timeout);
  }

  room.status = 'ended';
  room.endedAt = Date.now();
  room.endReason = reason;
  
  const history = state.messageHistory.get(roomId) || [];

  setTimeout(() => {
    state.rooms.delete(roomId);
    state.messageHistory.delete(roomId);
  }, 10000);

  const roomSockets = io.in(roomId);
  roomSockets.emit("room-ended", { reason, roomId });
  roomSockets.socketsLeave(roomId);

  logSecurityEvent('ROOM_ENDED', {
    roomId,
    mode: room.mode,
    reason,
    participantCount: room.participants.length,
    duration: room.endedAt - room.createdAt,
    messageCount: room.messages?.length || 0
  });
}

function getRoomStats() {
  const stats = {
    total: state.rooms.size,
    active: 0,
    text: 0,
    video: 0,
    audio: 0,
    group_text: 0,
    group_video: 0,
    banned: 0,
    ended: 0,
    waiting: {
      text: state.waiting.text.size,
      video: state.waiting.video.size,
      audio: state.waiting.audio.size,
      group_text: state.waiting.group_text.size,
      group_video: state.waiting.group_video.size
    }
  };
  
  for (const room of state.rooms.values()) {
    if (room.status === 'active') stats.active++;
    if (room.status === 'ended') stats.ended++;
    if (room.isBanned) stats.banned++;
    
    stats[room.mode] = (stats[room.mode] || 0) + 1;
  }
  
  return stats;
}

function getPublicStateForAdmin() {
  const roomsArray = [];
  
  for (const [roomId, room] of state.rooms) {
    roomsArray.push({
      id: roomId,
      mode: room.mode,
      status: room.status,
      isBanned: room.isBanned,
      participants: room.participants,
      userCount: room.users.size,
      maxSize: ROOM_MAX_SIZE[room.mode],
      tags: room.tags,
      tokens: room.tokens.length,
      createdAt: room.createdAt,
      lastActivity: room.lastActivity,
      endedAt: room.endedAt,
      duration: room.endedAt 
        ? room.endedAt - room.createdAt 
        : Date.now() - room.createdAt,
      messageCount: room.messages?.length || 0
    });
  }
  
  roomsArray.sort((a, b) => b.createdAt - a.createdAt);
  
  const blockedUsers = Array.from(state.blockedUsers.entries()).map(([id, data]) => ({ id, ...data }));
  const blockedIPs = Array.from(state.blockedIPs.entries()).map(([ip, data]) => ({ ip, ...data }));
  const blockedTokens = Array.from(state.blockedTokens.entries()).map(([token, data]) => ({ token, ...data }));
  
  return {
    serverInfo: {
      domain: DOMAIN,
      environment: NODE_ENV,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      nodeVersion: process.version,
      timestamp: Date.now()
    },
    rooms: roomsArray.slice(0, 100),
    reports: state.reports.slice(0, 50),
    online: state.users.size,
    stats: getRoomStats(),
    blocked: {
      users: blockedUsers,
      ips: blockedIPs,
      tokens: blockedTokens
    },
    waiting: getRoomStats().waiting,
    securityLogs: state.securityLogs.slice(0, 50),
    queue: {
      size: state.connectionQueue.length,
      users: state.connectionQueue.map(s => ({ 
        id: s.id, 
        connected: s.connected 
      }))
    }
  };
}

/* ================= QUEUE MANAGEMENT ================= */
function processQueue() {
  while (state.connectionQueue.length > 0 && state.users.size < MAX_USERS) {
    const queuedSocket = state.connectionQueue.shift();
    
    if (queuedSocket && queuedSocket.connected && !state.users.has(queuedSocket.id)) {
      acceptConnection(queuedSocket);
    }
  }
  
  state.connectionQueue.forEach((queuedSocket, index) => {
    if (queuedSocket && queuedSocket.connected) {
      queuedSocket.emit("queue-position", {
        position: index + 1,
        totalInQueue: state.connectionQueue.length,
        estimatedWait: Math.ceil((index + 1) * 2)
      });
    }
  });
}

function acceptConnection(socket) {
  state.connectionQueue = state.connectionQueue.filter(s => s.id !== socket.id);

  const wasQueued = Boolean(socket.queued);
  socket.queued = false;
  socket.queuedAt = null;

  const userIP = getUserIP(socket);
  const userId = generateUserId();

  state.users.set(socket.id, {
    id: userId,
    ip: userIP,
    name: 'Anonymous',
    nickname: 'Anonymous',
    mode: null,
    tags: [],
    token: null,
    coins: 0,
    badges: null,
    isAdmin: false,
    isCreator: false,
    rooms: new Set(),
    connectedAt: Date.now(),
    userAgent: socket.handshake.headers['user-agent'],
    queuedAt: null,
    country: getUserCountry(userIP),
    lastActivity: Date.now()
  });

  socket.emit("queue-accepted", {
    message: "You're now connected!",
    userId,
  });

  io.emit("online_count", { count: state.users.size });

  logSecurityEvent('USER_CONNECTED', { 
    socketId: socket.id, 
    userId, 
    ip: userIP,
    country: getUserCountry(userIP),
    userAgent: socket.handshake.headers['user-agent'],
    wasQueued
  });
}

/* ================= SOCKET.IO EVENT HANDLERS ================= */
io.on('connection', (socket) => {
  console.log(`New connection: ${socket.id}`);
  
  // 🚦 USER LIMIT ENFORCEMENT WITH QUEUE
  if (state.users.size >= MAX_USERS) {
    if (state.connectionQueue.length >= MAX_QUEUE_SIZE) {
      socket.emit("server-full", {
        max: MAX_USERS,
        queueFull: true,
        message: "Server and queue are full. Please try again later."
      });
      socket.disconnect(true);
      return;
    }
  
    const queuePosition = state.connectionQueue.length + 1;
    
    socket.queued = true;
    socket.queuedAt = Date.now();
    state.connectionQueue.push(socket);
  
    socket.emit("server-full", {
      max: MAX_USERS,
      queued: true,
      position: queuePosition,
      totalInQueue: state.connectionQueue.length,
      estimatedWait: Math.ceil(queuePosition * 2),
      message: `Server is full. You are #${queuePosition} in queue.`
    });
  
    logSecurityEvent('USER_QUEUED', {
      socketId: socket.id,
      position: queuePosition,
      totalInQueue: state.connectionQueue.length
    });
  
    socket.on('disconnect', () => {
      state.connectionQueue = state.connectionQueue.filter(s => s.id !== socket.id);
      processQueue();
    });
  
    return;
  }
  
  acceptConnection(socket);
  state.connectionQueue = state.connectionQueue.filter(s => s.id !== socket.id);

  /* ===== ADMIN AUTH & COMMANDS ===== */
  socket.on('admin-auth', (data) => {
    const { username, key } = data;
    
    // Check against admin key from environment
    if (key === ADMIN_CREDENTIALS.adminKey) {
        socket.join('admins');
        
        // Mark session as admin
        let userData = state.users.get(socket.id);
        if (!userData) {
            // Create minimal session for admin if not already existing
            userData = {
                id: `admin_${Date.now()}`,
                name: username || 'Admin',
                isAdmin: true,
                ip: getUserIP(socket),
                connectedAt: Date.now(),
                rooms: new Set(),
                userAgent: socket.handshake.headers['user-agent']
            };
            state.users.set(socket.id, userData);
        } else {
            userData.isAdmin = true;
            userData.name = username || 'Admin';
        }
        
        // Add to admin set for easier tracking
        if (!state.admins) state.admins = new Set();
        state.admins.add(socket.id);
        
        socket.emit('admin-auth-success', { 
            message: 'Authenticated as admin',
            username: userData.name
        });
        
        // Send initial full state
        socket.emit('admin-state', getPublicStateForAdmin());
        
        logSecurityEvent('ADMIN_CONNECTED', {
            socketId: socket.id,
            username: userData.name,
            ip: userData.ip
        });
    } else {
        socket.emit('admin-auth-failed', { error: 'Invalid security key' });
        logSecurityEvent('ADMIN_AUTH_FAILED', {
            socketId: socket.id,
            ip: getUserIP(socket)
        });
    }
  });

  socket.on('admin-command', (data) => {
      const userData = state.users.get(socket.id);
      if (!userData || !userData.isAdmin) {
          return socket.emit('error', { message: 'Unauthorized: Admin access required' });
      }
      
      const { command } = data;
      handleAdminCommand(socket, command, data);
  });

  /* ===== JOIN VIDEO CHAT ===== */
  socket.on("join_video_chat", (data) => {
    const userData = state.users.get(socket.id);
    if (!userData) {
      socket.emit('error', { message: 'User session not found' });
      return;
    }
    
    if (userData.mode) {
      return;
    }
    
    const { nickname, tags = [], token, userAgent } = data;
    const mode = 'video';
    
    const userIP = userData.ip;
    const userId = userData.id;
    
    if (isUserBlocked(userId, userIP, token)) {
      socket.emit('error', { 
        message: 'Your account has been blocked. Contact support if you believe this is an error.' 
      });
      socket.disconnect();
      return;
    }
    
    const cleanNickname = (nickname || 'Anonymous')
      .toString()
      .slice(0, 30)
      .replace(/[<>]/g, '');
    
    const cleanTags = Array.isArray(tags) 
      ? tags.slice(0, 10).map(tag => tag.toString().slice(0, 20).toLowerCase())
      : [];
    
    userData.name = cleanNickname;
    userData.nickname = cleanNickname;
    userData.tags = cleanTags;
    userData.token = token;
    userData.mode = mode;
    userData.userAgent = userAgent;
    userData.lastActivity = Date.now();
    
    for (const m of ['text', 'video', 'audio', 'group_text', 'group_video']) {
      state.waiting[m].delete(socket.id);
    }
    
    handleVideoChatJoin(socket, mode, userData);
    
    io.to('admins').emit('admin-state', getPublicStateForAdmin());
  });
  
  function handleVideoChatJoin(socket, mode, userData) {
    const match = findMatchForUser(socket.id, mode, userData.tags);
  
    if (match) {
      const matchedUserData = match.userData;
      const isInterestMatch = match.matchScore > 0;

      const roomId = createRoom(mode, socket.id, userData, {
        socketId: match.socketId,
        data: matchedUserData
      });

      state.waiting[mode].delete(socket.id);
      state.waiting[mode].delete(match.socketId);

      userData.rooms.add(roomId);
      const matchedUser = state.users.get(match.socketId);
      if (matchedUser) {
        matchedUser.rooms.add(roomId);
      }

      socket.join(roomId);
      const matchedSocket = io.sockets.sockets.get(match.socketId);
      if (matchedSocket) {
        matchedSocket.join(roomId);
      }

      const userCountry = userData.country;
      const partnerCountry = matchedUserData.country;

      socket.emit("matched", {
        roomId,
        partner: matchedUserData.name,
        partnerName: matchedUserData.name,
        partnerId: matchedUserData.id,
        mode,
        tags: matchedUserData.tags || [],
        partnerTags: matchedUserData.tags || [],
        matchType: isInterestMatch ? "interest" : "random",
        partnerCountry,
        isInitiator: true,
      });

      if (matchedSocket) {
        matchedSocket.emit("matched", {
          roomId,
          partner: userData.name,
          partnerName: userData.name,
          partnerId: userData.id,
          mode,
          tags: userData.tags || [],
          partnerTags: userData.tags || [],
          matchType: isInterestMatch ? "interest" : "random",
          partnerCountry: userCountry,
          isInitiator: false,
        });
      }

      logSecurityEvent("USERS_MATCHED", {
        roomId,
        user1: { id: userData.id, name: userData.name },
        user2: { id: matchedUserData.id, name: matchedUserData.name },
        mode,
        isInterestMatch
      });

    } else {
      state.waiting[mode].set(socket.id, userData);
      userData.waitingSince = Date.now();

      socket.emit("waiting", {
        mode,
        estimatedWait: Math.max(2, state.waiting[mode].size * 1),
      });

      logSecurityEvent("USER_WAITING", {
        userId: userData.id,
        mode,
        name: userData.name,
        waitingCount: state.waiting[mode].size
      });
    }
  }

  /* ===== WEBRTC SIGNALING ===== */
  socket.on("signal", (data) => {
    if (isRateLimited(socket.id, "signal")) {
      console.warn(`Signal rate limited: ${socket.id}`);
      return;
    }

    const { room, roomId, to, sdp, candidate, type } = data;
    const targetRoom = room || roomId;

    const userData = state.users.get(socket.id);
    if (!userData) return;

    if (sdp && !["offer", "answer"].includes(sdp.type)) {
      console.warn(`Invalid SDP type: ${sdp.type}`);
      return;
    }

    if (targetRoom) {
      const roomData = state.rooms.get(targetRoom);
      if (!roomData || !roomData.users.has(socket.id)) {
        console.warn(`User ${socket.id} not in room ${targetRoom}`);
        return;
      }
      roomData.lastActivity = Date.now();
    }

    if (to) {
      const targetSocket = io.sockets.sockets.get(to);
      if (targetSocket && targetSocket.connected) {
        targetSocket.emit("signal", {
          from: socket.id,
          roomId: targetRoom,
          sdp,
          candidate,
          type: type || "webrtc",
          timestamp: Date.now()
        });
      }
      return;
    }

    if (targetRoom) {
      const roomData = state.rooms.get(targetRoom);
      if (!roomData) return;

      for (const peerSocketId of roomData.users) {
        if (peerSocketId !== socket.id) {
          const peerSocket = io.sockets.sockets.get(peerSocketId);
          if (peerSocket && peerSocket.connected) {
            peerSocket.emit("signal", {
              from: socket.id,
              roomId: targetRoom,
              sdp,
              candidate,
              type: type || "webrtc",
              timestamp: Date.now()
            });
          }
        }
      }
    }
  });

  /* ===== MESSAGE HANDLING ===== */
  socket.on("message", (data) => {
    if (isRateLimited(socket.id, "message")) return;

    const { room, message } = data;
    const userData = state.users.get(socket.id);

    if (!room || !message || !userData) return;

    const roomData = state.rooms.get(room);
    if (!roomData || !roomData.users.has(socket.id)) return;

    let cleanMessage = String(message).trim().slice(0, 2000);
    const toxicPattern = /(fuck|shit|bitch|asshole|cunt|nigger|fag|slut|whore|porn)/gi;
    if (toxicPattern.test(cleanMessage)) {
      logSecurityEvent('TOXIC_MESSAGE', {
        roomId: room,
        userId: userData.id,
        message: cleanMessage.slice(0, 200)
      });
      cleanMessage = cleanMessage.replace(toxicPattern, '***');
    }
    if (!cleanMessage) return;

    const messageData = {
      message: cleanMessage,
      senderId: userData.id,
      senderName: userData.nickname || userData.name,
      roomId: room,
      type: "text",
      timestamp: Date.now()
    };

    const history = state.messageHistory.get(room) || [];
    history.push(messageData);
    if (history.length > MESSAGE_HISTORY_SIZE) history.shift();
    state.messageHistory.set(room, history);

    socket.to(room).emit("message", messageData);
    socket.emit("message", { ...messageData, self: true });
  });

  /* ===== MODERATION HANDLERS ===== */
  socket.on("report_user", (data) => {
    if (isRateLimited(socket.id, "report")) return;

    const { reportedUserId, reason, roomId } = data;
    const reporterData = state.users.get(socket.id);

    if (!reporterData || !reportedUserId) return;

    const report = {
      id: `rep_${Date.now()}_${Math.random().toString(36).slice(2)}`,
      reporterId: reporterData.id,
      reporterIp: reporterData.ip,
      reportedUserId,
      reason,
      roomId,
      timestamp: Date.now(),
      status: 'pending'
    };

    state.reports.push(report);
    
    logSecurityEvent('USER_REPORTED', report);
    io.to('admins').emit('new-report', report);

    const recentReports = state.reports.filter(r => 
      r.reportedUserId === reportedUserId && 
      Date.now() - r.timestamp < 24 * 60 * 60 * 1000
    );

    if (recentReports.length >= 3) {
      for (const [sId, uData] of state.users.entries()) {
        if (uData.id === reportedUserId) {
             const banData = {
                type: 'user',
                value: reportedUserId,
                reason: 'Multiple reports received',
                bannedAt: Date.now(),
                expiresAt: Date.now() + 24 * 60 * 60 * 1000
             };
             state.blockedUsers.set(reportedUserId, banData);
             
             const reportedSocket = io.sockets.sockets.get(sId);
             if (reportedSocket) {
               reportedSocket.emit('banned', { reason: 'Multiple user reports' });
               reportedSocket.disconnect();
             }
             break;
        }
      }
    }
    
    socket.emit('report_submitted', { success: true, message: 'Report received. Thank you.' });
  });

  socket.on("ai_moderation_flag", (data) => {
      const { probability, className, roomId } = data;
      const userData = state.users.get(socket.id);
      
      if (!userData) return;
      if (isRateLimited(socket.id, "ai_flag")) return;

      logSecurityEvent('AI_FLAG', { 
          userId: userData.id, 
          socketId: socket.id, 
          className, 
          probability 
      });

      if (['Porn', 'Hentai'].includes(className) && probability > 0.90) {
           const banData = {
                type: 'user',
                value: userData.id,
                reason: `AI Detection: ${className} (${Math.round(probability*100)}%)`,
                bannedAt: Date.now(),
                expiresAt: Date.now() + 1 * 60 * 60 * 1000
             };
             state.blockedUsers.set(userData.id, banData);
             
             socket.emit('banned', { reason: 'Inappropriate content detected' });
             socket.disconnect();
      }
  });

  /* ===== SKIP/LEAVE ===== */
  socket.on("skip", (data) => {
    if (isRateLimited(socket.id, "skip")) {
      socket.emit('error', { 
        message: 'Too many skips. Please wait a moment.' 
      });
      return;
    }
    
    const userData = state.users.get(socket.id);
    if (!userData) return;
    
    const mode = data?.mode || userData.mode || 'video';
    const tags = data?.tags || userData.tags || [];
    
    userData.rooms.forEach(roomId => {
      const roomData = state.rooms.get(roomId);
      if (roomData) {
        socket.to(roomId).emit("partner-disconnected", {
          partnerId: userData.id,
          partnerName: userData.name,
          roomId: roomId
        });
        
        removeUserFromRoom(socket.id, roomId, "skipped");
        socket.leave(roomId);
      }
    });
    
    userData.rooms.clear();
    
    for (const modeKey in state.waiting) {
      state.waiting[modeKey].delete(socket.id);
    }
    
    if (mode && userData) {
      userData.mode = mode;
      userData.tags = tags;
      userData.lastActivity = Date.now();
      handleVideoChatJoin(socket, mode, userData);
    } else {
      socket.emit("waiting");
    }
    
    logSecurityEvent('USER_SKIPPED', {
      userId: userData.id,
      name: userData.name,
      mode: mode
    });
    
    io.to('admins').emit('admin-state', getPublicStateForAdmin());
  });

  /* ===== LEAVE QUEUE ===== */
  socket.on('leave_queue', () => {
    for (const m of ['text', 'video', 'audio', 'group_text', 'group_video']) {
      state.waiting[m].delete(socket.id);
    }
    const userData = state.users.get(socket.id);
    if (userData) {
      userData.mode = null;
      userData.lastActivity = Date.now();
    }
    socket.emit('queue_left', { success: true });
  });

  /* ===== JOIN TEXT CHAT ===== */
  socket.on('join_chat', (data) => {
    const userData = state.users.get(socket.id);
    if (!userData) {
      socket.emit('error', { message: 'User session not found' });
      return;
    }

    const { nickname, tags = [], token, userAgent } = data || {};
    const mode = 'text';

    const cleanNickname = (nickname || 'Anonymous')
      .toString()
      .slice(0, 30)
      .replace(/[<>]/g, '');

    const cleanTags = Array.isArray(tags)
      ? tags.slice(0, 10).map(tag => tag.toString().slice(0, 20).toLowerCase())
      : [];

    userData.name = cleanNickname;
    userData.nickname = cleanNickname;
    userData.tags = cleanTags;
    userData.token = token;
    userData.mode = mode;
    userData.userAgent = userAgent || userData.userAgent;
    userData.lastActivity = Date.now();

    for (const m of ['text', 'video', 'audio', 'group_text', 'group_video']) {
      state.waiting[m].delete(socket.id);
    }

    handleVideoChatJoin(socket, mode, userData);
    io.to('admins').emit('admin-state', getPublicStateForAdmin());
  });

  /* ===== TEXT CHAT SKIP PARTNER ===== */
  socket.on('skip_partner', (data) => {
    const userData = state.users.get(socket.id);
    if (!userData) return;

    const currentRooms = Array.from(userData.rooms);
    currentRooms.forEach(roomId => {
      const roomData = state.rooms.get(roomId);
      if (roomData) {
        socket.to(roomId).emit('partner-disconnected', {
          partnerId: userData.id,
          partnerName: userData.name,
          roomId
        });
        removeUserFromRoom(socket.id, roomId, 'skipped');
        socket.leave(roomId);
      }
    });
    userData.rooms.clear();

    for (const m of ['text', 'video', 'audio', 'group_text', 'group_video']) {
      state.waiting[m].delete(socket.id);
    }

    const tags = data?.tags || userData.tags || [];
    userData.mode = 'text';
    userData.tags = tags;
    userData.lastActivity = Date.now();
    handleVideoChatJoin(socket, 'text', userData);
  });

  /* ===== TEXT CHAT END ===== */
  socket.on('end_chat', (data) => {
    const userData = state.users.get(socket.id);
    if (!userData) return;
    const { roomId } = data || {};
    if (!roomId) return;
    removeUserFromRoom(socket.id, roomId, 'ended');
    socket.leave(roomId);
    userData.rooms.delete(roomId);
    userData.mode = null;
    userData.lastActivity = Date.now();
    socket.emit('chat_ended', { roomId });
  });

  /* ===== COIN UPDATES ===== */
  socket.on("coin-update", (data) => {
    const userData = state.users.get(socket.id);
    if (!userData) return;

    const change = Number(data?.change || 0);
    const type = String(data?.type || 'update');
    const safeAmount = Math.min(Math.max(change, -100), 100);

    if (type === 'award' && safeAmount > 0) {
      userData.coins = (userData.coins || 0) + safeAmount;
    } else if (type === 'spend' && safeAmount > 0) {
      userData.coins = Math.max(0, (userData.coins || 0) - safeAmount);
    }

    userData.lastActivity = Date.now();

    socket.emit("coin-update", {
      userId: userData.id,
      coins: userData.coins,
      change: safeAmount,
      type
    });

    if (data.roomId) {
      socket.to(data.roomId).emit("user-data-update", {
        userId: userData.id,
        coins: userData.coins
      });
    }
  });

  socket.on('coin-transfer', (data) => {
    const { roomId, fromUserId, toUserId, amount, type } = data || {};
    const amt = Number(amount || 0);
    if (!roomId || !fromUserId || !toUserId || !(amt > 0 && amt <= 100)) return;

    const room = state.rooms.get(roomId);
    if (!room) return;

    let fromSocketId = null;
    let toSocketId = null;
    for (const [sId, u] of state.users.entries()) {
      if (u.id === fromUserId) fromSocketId = sId;
      if (u.id === toUserId) toSocketId = sId;
      if (fromSocketId && toSocketId) break;
    }

    if (!fromSocketId || !toSocketId) return;
    if (!room.users.has(fromSocketId) || !room.users.has(toSocketId)) return;

    const fromUser = state.users.get(fromSocketId);
    const toUser = state.users.get(toSocketId);
    if (!fromUser || !toUser) return;

    if ((fromUser.coins || 0) < amt) return;

    fromUser.coins = (fromUser.coins || 0) - amt;
    toUser.coins = (toUser.coins || 0) + amt;
    fromUser.lastActivity = Date.now();
    toUser.lastActivity = Date.now();

    const fromSocket = io.sockets.sockets.get(fromSocketId);
    const toSocket = io.sockets.sockets.get(toSocketId);

    if (fromSocket) {
      fromSocket.emit('coin-update', { userId: fromUser.id, coins: fromUser.coins, change: -amt, type: 'transfer_out' });
    }
    if (toSocket) {
      toSocket.emit('coin-update', { userId: toUser.id, coins: toUser.coins, change: amt, type: 'transfer_in' });
      toSocket.emit('coin-transfer', { roomId, fromUserId, toUserId, amount: amt, type: type || 'transfer' });
    }

    io.to(roomId).emit('special_emoji', { roomId, fromUserId, toUserId, amount: amt, emoji: data?.emoji || null, type: type || 'special_emoji' });

    io.to(roomId).emit('user-data-update', { userId: fromUser.id, coins: fromUser.coins });
    io.to(roomId).emit('user-data-update', { userId: toUser.id, coins: toUser.coins });
  });

  /* ===== REQUEST PEER LIST ===== */
  socket.on("request-peers", (data) => {
    const { roomId } = data;
    const userData = state.users.get(socket.id);
    
    if (!userData || !roomId) return;
    
    const room = state.rooms.get(roomId);
    if (!room || !room.users.has(socket.id)) return;
    
    const peers = Array.from(room.users)
      .filter(id => id !== socket.id)
      .map(peerId => {
        const peerData = state.users.get(peerId);
        return {
          socketId: peerId,
          userId: peerData?.id,
          nickname: peerData?.nickname || 'Anonymous',
          coins: peerData?.coins || 0,
          badges: peerData?.badges || null,
          isAdmin: peerData?.isAdmin || false,
          isCreator: peerData?.isCreator || false,
          country: peerData?.country
        };
      });
    
    socket.emit("existing-peers", {
      roomId,
      peers,
      total: peers.length,
    });
  });

  socket.on('create-group', (data) => {
    const userData = state.users.get(socket.id);
    if (!userData) return;
    const mode = data?.mode === 'group_video' ? 'group_video' : 'group_text';
    userData.name = String(data?.nickname || userData.name || 'Anonymous').slice(0,30).replace(/[<>]/g,'');
    userData.coins = Number.isFinite(data?.coins) ? data.coins : (userData.coins||0);
    userData.badges = data?.badges || userData.badges || null;
    userData.lastActivity = Date.now();
    userData.mode = mode;

    const roomId = createRoom(mode, socket.id, userData);
    userData.rooms.add(roomId);
    socket.join(roomId);

    socket.emit('group-joined', {
      roomId,
      mode,
      isAdmin: Boolean(userData.isAdmin),
      isCreator: Boolean(data?.isCreator),
      participantCount: state.rooms.get(roomId)?.users.size || 1
    });
  });

  socket.on('join-group', (data) => {
    const userData = state.users.get(socket.id);
    if (!userData) return;
    const roomId = String(data?.roomId || '');
    const mode = data?.mode === 'group_video' ? 'group_video' : 'group_text';

    const room = state.rooms.get(roomId);
    if (!room || room.mode !== mode || room.status !== 'active') return;

    const maxSize = ROOM_MAX_SIZE[room.mode];
    if (room.users.size >= maxSize) {
      socket.emit('room-full', { roomId, max: maxSize });
      return;
    }

    userData.name = String(data?.nickname || userData.name || 'Anonymous').slice(0,30).replace(/[<>]/g,'');
    userData.coins = Number.isFinite(data?.coins) ? data.coins : (userData.coins||0);
    userData.badges = data?.badges || userData.badges || null;
    userData.mode = mode;
    userData.lastActivity = Date.now();

    addUserToRoom(socket.id, roomId, userData);
    userData.rooms.add(roomId);
    socket.join(roomId);

    socket.emit('group-joined', {
      roomId,
      mode,
      isAdmin: Boolean(userData.isAdmin),
      isCreator: false,
      participantCount: room.users.size
    });

    socket.to(roomId).emit('user-joined', {
      roomId,
      userId: userData.id,
      nickname: userData.name,
      coins: userData.coins || 0,
      badges: userData.badges || null,
      isAdmin: Boolean(userData.isAdmin),
      isCreator: Boolean(userData.isCreator),
      participantCount: room.users.size
    });
  });

  // Group message (text mode) handling
  socket.on('send_message', (data) => {
    const roomId = String(data?.roomId || '');
    let message = String(data?.message || '').trim().slice(0, 2000);
    const userData = state.users.get(socket.id);
    if (!roomId || !message || !userData) return;
    const room = state.rooms.get(roomId);
    if (!room || !room.users.has(socket.id)) return;
    room.lastActivity = Date.now();

    const toxicPattern = /(fuck|shit|bitch|asshole|cunt|nigger|fag|slut|whore|porn)/gi;
    if (toxicPattern.test(message)) {
      logSecurityEvent('TOXIC_MESSAGE', {
        roomId: roomId,
        userId: userData.id,
        message: message.slice(0, 200)
      });
      message = message.replace(toxicPattern, '***');
    }

    const payload = {
      roomId,
      message,
      senderId: userData.id,
      nickname: userData.nickname || userData.name,
      messageId: String(data?.messageId || `${userData.id}_${Date.now()}`),
      timestamp: Date.now()
    };

    socket.to(roomId).emit('receive_message', payload);
    socket.emit('receive_message', { ...payload });
  });

  socket.on('media_chunk', (data) => {
    const roomId = String(data?.roomId || '');
    const userData = state.users.get(socket.id);
    if (!userData || !roomId) return;
    const room = state.rooms.get(roomId);
    if (!room || !room.users.has(socket.id)) return;
    room.lastActivity = Date.now();

    const totalChunks = Number(data?.totalChunks || 0);
    const chunkIndex = Number(data?.chunkIndex || 0);
    if (!(totalChunks > 0) || chunkIndex < 0 || chunkIndex >= totalChunks) return;

    const payload = {
      roomId,
      mediaId: String(data?.mediaId || `${userData.id}_${Date.now()}`),
      chunkIndex,
      totalChunks,
      chunk: data?.chunk,
      mediaType: data?.mediaType,
      fileName: String(data?.fileName || ''),
      fileSize: Number(data?.fileSize || 0),
      senderId: userData.id,
      nickname: userData.nickname || userData.name,
      cost: Number(data?.cost || 0)
    };

    socket.to(roomId).emit('receive_media', payload);
  });

  // Message reactions
  socket.on('message_reaction', (data) => {
    const roomId = String(data?.roomId || '');
    const userData = state.users.get(socket.id);
    if (!userData || !roomId) return;
    const room = state.rooms.get(roomId);
    if (!room || !room.users.has(socket.id)) return;
    room.lastActivity = Date.now();

    const payload = {
      roomId,
      messageId: String(data?.messageId || ''),
      emoji: String(data?.emoji || ''),
      reactorId: userData.id,
      reactorName: userData.nickname || userData.name,
      timestamp: Date.now()
    };

    socket.to(roomId).emit('receive_reaction', payload);
    socket.emit('receive_reaction', { ...payload });
  });

  socket.on('user-data', (data) => {
    const roomId = String(data?.roomId || '');
    const userData = state.users.get(socket.id);
    if (!userData || !roomId) return;
    const room = state.rooms.get(roomId);
    if (!room || !room.users.has(socket.id)) return;
    userData.coins = Number.isFinite(data?.coins) ? data.coins : (userData.coins||0);
    userData.badges = data?.badges || userData.badges || null;
    userData.nickname = String(data?.nickname || userData.name).slice(0,30).replace(/[<>]/g,'');
    userData.lastActivity = Date.now();
    socket.to(roomId).emit('user-data-update', {
      userId: userData.id,
      coins: userData.coins,
      nickname: userData.nickname,
      badges: userData.badges || null
    });
  });

  /* ===== TYPING INDICATOR ===== */
  socket.on("typing", (data) => {
    if (isRateLimited(socket.id, "typing")) return;
    
    const { room, isTyping } = data;
    const roomId = room;
    const userData = state.users.get(socket.id);
    
    if (!roomId || !userData) return;
    
    const roomData = state.rooms.get(roomId);
    if (!roomData || !roomData.users.has(socket.id)) return;
    
    socket.to(roomId).emit("user-typing", {
      userId: socket.id,
      userName: userData.name,
      isTyping: Boolean(isTyping)
    });
  });

  /* ===== PING/PONG ===== */
  socket.on("ping", () => {
    const userData = state.users.get(socket.id);
    if (userData) {
      userData.lastActivity = Date.now();
    }
    socket.emit("pong", { timestamp: Date.now() });
  });

  /* ===== DISCONNECT HANDLER ===== */
  socket.on("disconnect", (reason) => {
    const userData = state.users.get(socket.id);
    
    if (userData) {
      userData.rooms.forEach(roomId => {
        const roomData = state.rooms.get(roomId);
        if (roomData) {
          socket.to(roomId).emit("partner-disconnected", {
            partnerId: userData.id,
            partnerName: userData.name,
            roomId: roomId,
            reason: reason
          });
          
          removeUserFromRoom(socket.id, roomId, "disconnected");
        }
      });
      
      for (const mode in state.waiting) {
        state.waiting[mode].delete(socket.id);
      }
      
      if (state.admins.has(socket.id)) {
        state.admins.delete(socket.id);
        socket.leave('admins');
        logAdminAction(socket.id, "ADMIN_LOGOUT", { reason });
      }
      
      state.socketRateLimits.delete(socket.id);
      state.users.delete(socket.id);
      
      logSecurityEvent('USER_DISCONNECTED', {
        userId: userData.id,
        socketId: socket.id,
        ip: userData.ip,
        reason: reason,
        duration: Date.now() - userData.connectedAt,
        rooms: Array.from(userData.rooms)
      });
    }
    
    state.connectionQueue = state.connectionQueue.filter(s => s.id !== socket.id);
    
    io.emit("online_count", { count: state.users.size });
    io.to('admins').emit('admin-state', getPublicStateForAdmin());
    
    if (state.users.size < MAX_USERS) {
      processQueue();
    }
  });
});

/* ================= ADMIN HELPERS ================= */
function getPublicStateForAdmin() {
  const usersList = [];
  for (const [socketId, user] of state.users.entries()) {
    usersList.push({
        id: user.id,
        socketId: socketId,
        name: user.name,
        ip: user.ip, // Admin sees IP
        country: user.country,
        mode: user.mode,
        isAdmin: user.isAdmin,
        connectedAt: user.connectedAt,
        rooms: Array.from(user.rooms),
        reports: state.reports.filter(r => r.reportedUserId === user.id).length
    });
  }

  const roomsList = [];
  for (const [roomId, room] of state.rooms.entries()) {
      roomsList.push({
          id: roomId,
          mode: room.mode,
          users: Array.from(room.users),
          createdAt: room.createdAt,
          maxSize: ROOM_MAX_SIZE[room.mode],
          status: room.status
      });
  }

  return {
      users: usersList,
      rooms: roomsList,
      reports: state.reports,
      contacts: state.contacts,
      blocked: {
          users: Array.from(state.blockedUsers.entries()),
          ips: Array.from(state.blockedIPs.entries())
      },
      stats: {
          totalUsers: state.users.size,
          onlineUsers: state.users.size,
          blockedUsers: state.blockedUsers.size,
          activeRooms: state.rooms.size,
          reportsCount: state.reports.length
      },
      securityLogs: state.securityLogs.slice(0, 50), // Send recent logs
      adConfig: adConfig
  };
}

async function handleAdminCommand(socket, command, data) {
    const adminName = state.users.get(socket.id)?.name || 'Admin';
    
    try {
        switch(command) {
            case 'end-room':
                if (data.roomId) {
                    endRoom(data.roomId, `Ended by admin ${adminName}`);
                    socket.emit('command-success', { command, message: `Room ${data.roomId} ended` });
                    logAdminAction(socket.id, 'END_ROOM', { roomId: data.roomId });
                }
                break;
                
            case 'ban-user':
                if (data.userId) {
                     const banData = {
                        type: 'user',
                        value: data.userId,
                        reason: data.reason || 'Banned by admin',
                        bannedAt: Date.now(),
                        bannedBy: adminName,
                        expiresAt: Date.now() + 24 * 60 * 60 * 1000 // Default 24h
                     };
                     state.blockedUsers.set(data.userId, banData);
                     
                     // Find and disconnect user
                     for (const [sId, uData] of state.users.entries()) {
                         if (uData.id === data.userId) {
                             const targetSocket = io.sockets.sockets.get(sId);
                             if (targetSocket) {
                                 targetSocket.emit('banned', { reason: banData.reason });
                                 targetSocket.disconnect();
                             }
                             break;
                         }
                     }
                     
                     socket.emit('command-success', { command, message: `User ${data.userId} banned` });
                     logAdminAction(socket.id, 'BAN_USER', { userId: data.userId });
                }
                break;
                
            case 'resolve-report':
                if (data.reportId) {
                    const reportIndex = state.reports.findIndex(r => r.id === data.reportId);
                    if (reportIndex !== -1) {
                        state.reports[reportIndex].status = 'resolved';
                        state.reports[reportIndex].resolvedBy = adminName;
                        state.reports[reportIndex].resolvedAt = Date.now();
                        
                        socket.emit('command-success', { command, message: `Report ${data.reportId} resolved` });
                        logAdminAction(socket.id, 'RESOLVE_REPORT', { reportId: data.reportId });
                    }
                }
                break;

            case 'update-ad-config':
                if (data.config) {
                    await saveAdConfig(data.config);
                    socket.emit('command-success', { command, message: 'Ad configuration updated' });
                    logAdminAction(socket.id, 'UPDATE_AD_CONFIG', data.config);
                }
                break;
                
            default:
                socket.emit('error', { message: `Unknown command: ${command}` });
        }
        
        // Push update to all admins
        io.to('admins').emit('admin-state', getPublicStateForAdmin());
        
    } catch (error) {
        console.error('Admin command error:', error);
        socket.emit('error', { message: 'Command execution failed' });
    }
}

/* ================= PERIODIC CLEANUP ================= */
setInterval(() => {
  const now = Date.now();
  const oneHourAgo = now - (60 * 60 * 1000);
  const fiveMinutesAgo = now - (5 * 60 * 1000);
  const thirtyMinutesAgo = now - (30 * 60 * 1000);
  const twentyFourHoursAgo = now - (24 * 60 * 60 * 1000);
  
  // Clean up old rooms
  for (const [roomId, room] of state.rooms) {
    if (room.status === 'ended' && room.endedAt < oneHourAgo) {
      state.rooms.delete(roomId);
      state.messageHistory.delete(roomId);
    }
    
    if (room.status === 'active' && room.lastActivity < thirtyMinutesAgo) {
      endRoom(roomId, "inactivity");
    }
  }
  
  // Clean up users waiting too long
  for (const mode in state.waiting) {
    for (const [socketId, userData] of state.waiting[mode].entries()) {
      if (userData.waitingSince && userData.waitingSince < fiveMinutesAgo) {
        state.waiting[mode].delete(socketId);
      
        const socket = io.sockets.sockets.get(socketId);
        if (socket) {
          socket.emit('waiting-timeout');
        }
      }
    }
  }
  
  // Clean up old rate limit data
  for (const [socketId, limits] of state.socketRateLimits.entries()) {
    for (const type in limits) {
      if (now - limits[type].firstRequest > 120000) {
        delete limits[type];
      }
    }
    if (Object.keys(limits).length === 0) {
      state.socketRateLimits.delete(socketId);
    }
  }
  
  // Clean up expired bans
  for (const [userId, banData] of state.blockedUsers.entries()) {
    if (banData.expiresAt && now > banData.expiresAt) {
      state.blockedUsers.delete(userId);
    }
  }
  
  for (const [ip, banData] of state.blockedIPs.entries()) {
    if (banData.expiresAt && now > banData.expiresAt) {
      state.blockedIPs.delete(ip);
    }
  }
  
  for (const [token, banData] of state.blockedTokens.entries()) {
    if (banData.expiresAt && now > banData.expiresAt) {
      state.blockedTokens.delete(token);
    }
  }
  
  // Clean up old reports and logs
  if (state.reports.length > 1000) {
    state.reports = state.reports.slice(0, 1000);
  }
  
  if (state.securityLogs.length > 2000) {
    const logsToArchive = state.securityLogs.slice(1000);
    state.securityLogs = state.securityLogs.slice(0, 2000);
    
    logToFile("security-archive.log", {
      archivedAt: now,
      logs: logsToArchive
    });
  }
  
  // Clean up inactive users
  for (const [socketId, userData] of state.users.entries()) {
    if (userData.lastActivity && (now - userData.lastActivity) > 3600000) {
      const socket = io.sockets.sockets.get(socketId);
      if (socket) {
        socket.disconnect(true);
      }
    }
  }
  
  // Backup state every hour
  if (now % (60 * 60 * 1000) < 5000) {
    backupState();
  }
  
  // Update admin panel
  io.to('admins').emit('admin-state', getPublicStateForAdmin());
  
  // Log memory usage periodically
  const memoryUsage = process.memoryUsage();
  if (memoryUsage.heapUsed > 500 * 1024 * 1024) {
    console.warn(`⚠️  High memory usage: ${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB`);
    logSecurityEvent('HIGH_MEMORY_USAGE', {
      heapUsed: memoryUsage.heapUsed,
      heapTotal: memoryUsage.heapTotal,
      rss: memoryUsage.rss
    });
  }
  
  // Log server stats every 5 minutes
  if (now % (5 * 60 * 1000) < 5000) {
    console.log(`📊 Server Stats: Users=${state.users.size}, Rooms=${state.rooms.size}, Queue=${state.connectionQueue.length}`);
  }
  
}, 30 * 1000);

/* ================= START SERVER ================= */
async function startServer() {
  await setupLogging();
  
  server.listen(PORT, HOST, () => {
    console.log(`
    🚀 ManaMingle Server Started!
    ==============================
    👉 Environment: ${NODE_ENV}
    👉 Domain: ${DOMAIN}
    👉 Main URL: http://${HOST}:${PORT}
    👉 Video Chat: http://${HOST}:${PORT}/video
    👉 Admin Panel: http://${HOST}:${PORT}/admin
    👉 Health Check: http://${HOST}:${PORT}/health
    👉 TURN Endpoint: http://${HOST}:${PORT}/api/turn
    
    📊 Room Limits:
    • 1-on-1 Text/Video/Audio: 2 users
    • Group Text Chat: 6 users
    • Group Video Chat: 4 users
    
    ⚠️  ${NODE_ENV === 'production' ? 'PRODUCTION MODE' : 'DEVELOPMENT MODE'}
    ⚠️  ${ADMIN_CREDENTIALS.password === 'ChangeMe123!' ? 'CHANGE DEFAULT ADMIN CREDENTIALS!' : 'Admin credentials set'}
    
    📈 Starting with:
    • Max Users: ${MAX_USERS}
    • Queue Size: ${MAX_QUEUE_SIZE}
    • Rate Limit: ${RATE_LIMIT_MAX} req/${RATE_LIMIT_WINDOW/1000}s
    `);
  });
}

startServer().catch(console.error);

/* ================= ERROR HANDLING ================= */
process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION:', err);
  logSecurityEvent('SERVER_ERROR', { 
    error: err.message, 
    stack: err.stack 
  });
  logToFile("errors.log", { 
    type: 'uncaughtException', 
    error: err.message, 
    stack: err.stack,
    timestamp: Date.now() 
  });
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('UNHANDLED REJECTION at:', promise, 'reason:', reason);
  logSecurityEvent('UNHANDLED_REJECTION', { 
    reason: String(reason) 
  });
  logToFile("errors.log", { 
    type: 'unhandledRejection', 
    reason: String(reason),
    timestamp: Date.now() 
  });
});

// Graceful shutdown
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

function gracefulShutdown() {
  console.log('🛑 Received shutdown signal. Closing server...');
  
  io.emit('server-shutdown', { 
    message: 'Server is restarting. Please reconnect in a moment.',
    timestamp: Date.now(),
    reconnectDelay: 5000
  });
  
  for (const [roomId, room] of state.rooms) {
    if (room.status === 'active') {
      endRoom(roomId, 'server_maintenance');
    }
  }
  
  backupState();
  
  logToFile("shutdown.log", {
    timestamp: Date.now(),
    rooms: state.rooms.size,
    users: state.users.size,
    reports: state.reports.length,
    reason: "graceful_shutdown"
  });
  
  setTimeout(() => {
    io.close(() => {
      console.log('✅ Socket.IO closed');
    });
    
    server.close(() => {
      console.log('✅ HTTP server closed gracefully');
      process.exit(0);
    });
  }, 5000);
}

module.exports = { server, io, state };
