// ============================================
// SERVER.JS - PRODUCTION READY COMPLETE FILE (FIXED)
// ManaMingle Group Chat Server
// ============================================

const express = require("express");
const http = require("http");
const cors = require("cors");
const path = require("path");
const helmet = require("helmet");
const { Server } = require("socket.io");
const fs = require("fs").promises;
const rateLimit = require("express-rate-limit");
const compression = require("compression");
require("dotenv").config();

// ============================================
// CONFIGURATION
// ============================================
const MAX_USERS = 300;
const MAX_QUEUE_SIZE = 100;
const RATE_LIMIT_WINDOW = 60000;
const RATE_LIMIT_MAX = 100;
const MESSAGE_HISTORY_SIZE = 50;
const MAX_TEXT_USERS = 6;
const MAX_VIDEO_USERS = 4;

const PORT = process.env.PORT || 3000;
const HOST = "0.0.0.0";
const NODE_ENV = process.env.NODE_ENV || "development";
const DOMAIN = process.env.DOMAIN || "manamingle.site";

const ADMIN_CREDENTIALS = {
  username: process.env.ADMIN_USERNAME || process.env.ADMIN_USER || (NODE_ENV !== "production" ? "admin" : ""),
  password: process.env.ADMIN_PASSWORD || process.env.ADMIN_PASS || (NODE_ENV !== "production" ? "ChangeMe123!" : ""),
  adminKey: process.env.ADMIN_SECRET_KEY || process.env.ADMIN_KEY || process.env.ADMIN_SECRET || (NODE_ENV !== "production" ? "dev-admin-key" : "")
};

let FIXED_OTP = (process.env.OTP_NUMBER || "").trim();

function ensureOtp() {
  if (!/^\d{4}$/.test(FIXED_OTP)) {
    const code = String(Math.floor(1000 + Math.random() * 9000));
    FIXED_OTP = code;
    upsertEnv('OTP_NUMBER', code).then(() => {
      process.env.OTP_NUMBER = code;
      logSecurityEvent('ADMIN_FIXED_OTP_INITIALIZED', { masked: NODE_ENV === 'production' ? '****' : code });
    }).catch(() => {});
  }
}

const ROOM_MAX_SIZE = {
  text: 2,
  video: 2,
  audio: 2,
  group_text: MAX_TEXT_USERS,
  group_video: MAX_VIDEO_USERS
};

const ROOM_TIMEOUTS = {
  text: 30 * 60 * 1000,
  video: 60 * 60 * 1000,
  audio: 60 * 60 * 1000,
  group_text: 120 * 60 * 1000,
  group_video: 90 * 60 * 1000
};

const corsOptions = {
  origin: NODE_ENV === "production" 
    ? [`https://${DOMAIN}`, `https://www.${DOMAIN}`, `http://localhost:${PORT}`, `http://127.0.0.1:${PORT}`]
    : true,
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"]
};

// Validate production environment
if (NODE_ENV === "production") {
  const required = [
    { names: ["ADMIN_USERNAME", "ADMIN_USER"], value: ADMIN_CREDENTIALS.username },
    { names: ["ADMIN_PASSWORD", "ADMIN_PASS"], value: ADMIN_CREDENTIALS.password },
    { names: ["ADMIN_SECRET_KEY", "ADMIN_KEY"], value: ADMIN_CREDENTIALS.adminKey }
  ];
  for (const r of required) {
    if (!r.value) {
      console.error(`❌ ERROR: Missing required env: ${r.names.join(", ")}`);
      process.exit(1);
    }
  }
}

// ============================================
// PATHS
// ============================================
const publicPath = path.join(__dirname, "public");
const logsPath = path.join(__dirname, "logs");
const backupPath = path.join(__dirname, "backups");
const dataPath = path.join(backupPath, "store.json");

// ============================================
// GLOBAL STATE
// ============================================
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
  messageHistory: new Map(),
  resetTokens: new Map()
};

// ============================================
// LOGGING UTILITIES
// ============================================
async function setupLogging() {
  try {
    await fs.mkdir(logsPath, { recursive: true });
    await fs.mkdir(backupPath, { recursive: true });
    // Initialize data store if missing
    try {
      await fs.access(dataPath);
    } catch (_) {
      await fs.writeFile(dataPath, JSON.stringify({ coins: {}, subscription: {} }, null, 2));
    }
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
  logToFile("admin.log", log);
}

// ============================================
// SIMPLE PERSISTENT STORE (FILE)
// ============================================
async function loadStore() {
  try {
    const txt = await fs.readFile(dataPath, 'utf8');
    return JSON.parse(txt);
  } catch (e) {
    return { coins: {}, subscription: {}, adsConfig: {}, featuresConfig: {} };
  }
}

async function saveStore(store) {
  try {
    await fs.writeFile(dataPath, JSON.stringify(store, null, 2));
    return true;
  } catch (e) {
    console.error('Store save failed:', e);
    return false;
  }
}

function getTokenFromReq(req) {
  const c = req.headers['cookie'] || '';
  const m = c.match(/mm_token=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : null;
}

function genToken() {
  return 'tok_' + Date.now() + '_' + Math.random().toString(36).slice(2, 9);
}

// ============================================
// HELPER FUNCTIONS
// ============================================
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

function sanitizeText(text, maxLength = 2000) {
  if (typeof text !== 'string') return '';
  
  return text
    .trim()
    .slice(0, maxLength)
    .replace(/[<>]/g, '') // Remove HTML tags
    .replace(/javascript:/gi, '') // Remove javascript: protocol
    .replace(/on\w+=/gi, ''); // Remove event handlers
}

async function upsertEnv(key, value) {
  try {
    const envPath = path.join(__dirname, '.env');
    let content = '';
    try {
      content = await fs.readFile(envPath, 'utf8');
    } catch (_) {
      content = '';
    }
    const lines = content.split(/\r?\n/);
    let found = false;
    const updated = lines.map(line => {
      if (line.startsWith(key + '=')) {
        found = true;
        return `${key}=${value}`;
      }
      return line;
    });
    if (!found) updated.push(`${key}=${value}`);
    await fs.writeFile(envPath, updated.join('\n'));
    return true;
  } catch (e) {
    console.error('Failed to update .env:', e);
    return false;
  }
}

function validateStrongPassword(pw) {
  if (typeof pw !== 'string' || pw.length < 10) return false;
  const hasUpper = /[A-Z]/.test(pw);
  const hasLower = /[a-z]/.test(pw);
  const hasDigit = /\d/.test(pw);
  const hasSpecial = /[^\w\s]/.test(pw);
  return hasUpper && hasLower && hasDigit && hasSpecial;
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
    media: 20,
    report: 5,
    ai_flag: 10
  };
  
  limit.count++;
  limit.lastRequest = now;
  
  if (limit.count > (maxRequests[type] || 30)) {
    logSecurityEvent('RATE_LIMIT_EXCEEDED', { socketId, type, count: limit.count });
    return true;
  }
  
  return false;
}

// ============================================
// ROOM MANAGEMENT
// ============================================
function createRoom(mode, creatorSocketId, creatorData, ...otherUsers) {
  const roomId = generateRoomId();
  const allUsers = [{ socketId: creatorSocketId, data: creatorData }, ...otherUsers];
  
  const allTags = [];
  const allTokens = [];
  const participants = [];
  
  for (const user of allUsers) {
    if (user.data.tags) {
      allTags.push(...user.data.tags);
    }
    if (user.data.token) {
      allTokens.push(user.data.token);
    }
    
    participants.push({
      id: user.socketId,
      userId: user.data.id,
      name: user.data.name || 'Anonymous',
      tags: user.data.tags || [],
      joinedAt: Date.now(),
      ip: user.data.ip,
      isAdmin: user.data.isAdmin || false,
      isCreator: user.data.isCreator || false,
      coins: user.data.coins || 0,
      badges: user.data.badges || null
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
    isAdmin: userData.isAdmin || false,
    isCreator: userData.isCreator || false,
    coins: userData.coins || 0,
    badges: userData.badges || null
  });
  
  if (userData.token) {
    room.tokens.push(userData.token);
  }
  room.lastActivity = Date.now();
  
  return true;
}

// ✅ FIXED: Removed undefined 'socket' variable
function removeUserFromRoom(socketId, roomId, io, reason = "left") {
  const room = state.rooms.get(roomId);
  if (!room) return false;

  room.users.delete(socketId);

  const participantIndex = room.participants.findIndex(p => p.id === socketId);
  if (participantIndex !== -1) {
    room.participants.splice(participantIndex, 1);
  }

  // ✅ Get user data before notifying
  const userData = state.users.get(socketId);
  const remainingUsers = Array.from(room.users);
  
  if (remainingUsers.length > 0) {
    io.to(roomId).emit("user-left", {
      userId: socketId,  // ✅ Fixed: use parameter instead of undefined 'socket'
      nickname: userData?.name || 'Anonymous',
      roomId,
      reason,
      participantCount: remainingUsers.length
    });
  }

  if (room.users.size === 0) {
    endRoom(roomId, reason, io);
  }

  room.lastActivity = Date.now();
  return true;
}

function endRoom(roomId, reason = "ended", io) {
  const room = state.rooms.get(roomId);
  if (!room) return;

  if (room.timeout) {
    clearTimeout(room.timeout);
  }

  room.status = 'ended';
  room.endedAt = Date.now();
  room.endReason = reason;

  setTimeout(() => {
    state.rooms.delete(roomId);
    state.messageHistory.delete(roomId);
  }, 10000);

  if (io) {
    io.to(roomId).emit("room-ended", { reason, roomId });
  }

  logSecurityEvent('ROOM_ENDED', {
    roomId,
    mode: room.mode,
    reason,
    participantCount: room.participants.length,
    duration: room.endedAt - room.createdAt,
    messageCount: room.messages?.length || 0
  });
}

// ============================================
// QUEUE MANAGEMENT
// ============================================
function processQueue(io) {
  while (state.connectionQueue.length > 0 && state.users.size < MAX_USERS) {
    const queuedSocket = state.connectionQueue.shift();
    
    if (queuedSocket && queuedSocket.connected && !state.users.has(queuedSocket.id)) {
      acceptConnection(queuedSocket, io);
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

function acceptConnection(socket, io) {
  state.connectionQueue = state.connectionQueue.filter(s => s.id !== socket.id);

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
    coins: 1000,
    badges: null,
    isAdmin: false,
    isCreator: false,
    rooms: new Set(),
    connectedAt: Date.now(),
    userAgent: socket.handshake.headers['user-agent'],
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
    userAgent: socket.handshake.headers['user-agent']
  });
}

// ============================================
// ADMIN FUNCTIONS
// ============================================
function getPublicStateForAdmin() {
  const usersList = [];
  for (const [socketId, user] of state.users.entries()) {
    usersList.push({
      id: user.id,
      socketId: socketId,
      name: user.name,
      ip: user.ip,
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
      participants: room.participants.length,
      createdAt: room.createdAt,
      maxSize: ROOM_MAX_SIZE[room.mode],
      status: room.status
    });
  }

  return {
    users: usersList,
    rooms: roomsList,
    reports: state.reports.slice(0, 50),
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
    securityLogs: state.securityLogs.slice(0, 50)
  };
}

async function handleAdminCommand(socket, command, data, io) {
  const adminName = state.users.get(socket.id)?.name || 'Admin';
  
  try {
    switch(command) {
      case 'end-room':
        if (data.roomId) {
          endRoom(data.roomId, `Ended by admin ${adminName}`, io);
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
            expiresAt: Date.now() + 24 * 60 * 60 * 1000
          };
          state.blockedUsers.set(data.userId, banData);
          
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
        
      default:
        socket.emit('error', { message: `Unknown command: ${command}` });
    }
    
    io.to('admins').emit('admin-state', getPublicStateForAdmin());
    
  } catch (error) {
    console.error('Admin command error:', error);
    socket.emit('error', { message: 'Command execution failed' });
  }
}

// ============================================
// EXPRESS APP SETUP
// ============================================
const app = express();
app.set('trust proxy', 1);

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.socket.io", "https://cdn.jsdelivr.net", "https://webrtc.github.io"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "blob:", "https:"],
      mediaSrc: ["'self'", "blob:", "mediastream:"],
      connectSrc: ["'self'", "wss:", "ws:", "https:"]
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW,
  max: RATE_LIMIT_MAX,
  message: { error: "Too many requests, please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

const ipLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  message: { error: "Too many requests from this IP." },
  keyGenerator: (req) => req.ip
});

// Middleware
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

// Admin authentication middleware
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

// ============================================
// HTTP ROUTES
// ============================================

// Health check
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
    version: "1.0.1"
  });
});

// TURN/ICE configuration
app.get("/api/turn", (req, res) => {
  const iceServers = [
    { urls: "stun:stun.l.google.com:19302" },
    { urls: "stun:stun1.l.google.com:19302" },
    { urls: "stun:stun2.l.google.com:19302" },
    { urls: "stun:stun3.l.google.com:19302" },
    { urls: "stun:stun4.l.google.com:19302" }
  ];

  if (process.env.TURN_USERNAME && process.env.TURN_PASSWORD) {
    iceServers.push(
      {
        urls: "turn:global.relay.metered.ca:80",
        username: process.env.TURN_USERNAME,
        credential: process.env.TURN_PASSWORD
      },
      {
        urls: "turn:global.relay.metered.ca:443",
        username: process.env.TURN_USERNAME,
        credential: process.env.TURN_PASSWORD
      },
      {
        urls: "turn:global.relay.metered.ca:443?transport=tcp",
        username: process.env.TURN_USERNAME,
        credential: process.env.TURN_PASSWORD
      }
    );
  }

  res.json({ iceServers });
});

// Translation API
app.post("/api/translate", apiLimiter, async (req, res) => {
  try {
    const { text, source = "auto", target } = req.body || {};
    if (!text || !target) return res.status(400).json({ error: "bad_request" });
    
    const url = process.env.TRANSLATE_URL || "https://libretranslate.com/translate";
    const payload = { 
      q: String(text).slice(0, 2000), 
      source, 
      target, 
      format: "text" 
    };
    
    if (process.env.TRANSLATE_API_KEY) {
      payload.api_key = process.env.TRANSLATE_API_KEY;
    }
    
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    
    if (!response.ok) {
      console.error('Translation API error:', response.status);
      return res.status(502).json({ error: "translate_failed" });
    }
    
    const data = await response.json();
    res.json({ text: data.translatedText || data.text || "" });
  } catch (e) {
    console.error('Translation error:', e);
    res.status(500).json({ error: "translate_error" });
  }
});

// NSFW model proxy (avoids CORS issues when loading from static origins)
const NSFW_MODEL_BASE =
  process.env.NSFW_MODEL_BASE ||
  "https://d1zv2aa70wpiur.cloudfront.net/tfjs_quant_nsfw_mobilenet/";

app.get("/nsfw-model/*", async (req, res) => {
  try {
    const subpath = req.params[0] || "model.json";
    const url = NSFW_MODEL_BASE + subpath;
    const response = await fetch(url);
    if (!response.ok) {
      return res.status(response.status || 502).end();
    }
    const contentType = response.headers.get("content-type") || "application/octet-stream";
    const buf = Buffer.from(await response.arrayBuffer());
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Cache-Control", "public, max-age=86400");
    res.type(contentType).send(buf);
  } catch (e) {
    console.error("NSFW model proxy error:", e);
    res.status(502).end();
  }
});

// Report user (public)
app.post("/api/report-user", apiLimiter, (req, res) => {
  try {
    const { reportedUserId, reason, email } = req.body || {};
    
    if (!reportedUserId || !reason) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    
    const report = {
      id: `rep_${Date.now()}_${Math.random().toString(36).slice(2)}`,
      reporterEmail: String(email || "").slice(0, 120) || null,
      reportedUserId: String(reportedUserId).slice(0, 120),
      reason: String(reason).slice(0, 500),
      timestamp: Date.now(),
      status: "pending"
    };
    
    state.reports.push(report);
    res.json({ success: true, id: report.id });
  } catch (e) {
    console.error('Report error:', e);
    res.status(500).json({ error: "report_error" });
  }
});

// Admin login
app.post("/admin/login", apiLimiter, (req, res) => {
  const { username, password, adminKey } = req.body;

  console.log(`🔐 Admin login attempt from ${req.ip}`);

  if (username !== ADMIN_CREDENTIALS.username || 
      password !== ADMIN_CREDENTIALS.password ||
      adminKey !== ADMIN_CREDENTIALS.adminKey) {
    console.log(`❌ Admin login failed`);
    return res.status(401).json({ error: "Invalid credentials" });
  }

  console.log(`✅ Admin primary credentials verified`);
  ensureOtp();
  res.json({ success: true, requiresOtp: true });
});

// Admin OTP status (optional)
app.get('/admin/otp/status', apiLimiter, (req, res) => {
  ensureOtp();
  res.json({ configured: /^\d{4}$/.test(FIXED_OTP) });
});

// Admin OTP verify to complete login
app.post('/admin/otp/verify', apiLimiter, (req, res) => {
  try {
    ensureOtp();
    const { code } = req.body || {};
    if (!/^\d{4}$/.test(String(code || ''))) {
      return res.status(400).json({ error: 'invalid_code' });
    }
    if (String(code) !== FIXED_OTP) {
      logSecurityEvent('ADMIN_OTP_FAILED', { ip: req.ip });
      return res.status(401).json({ error: 'otp_incorrect' });
    }
    console.log('✅ Admin OTP verified');
    res.json({ success: true, token: ADMIN_CREDENTIALS.adminKey });
  } catch (e) {
    console.error('OTP verify error:', e);
    res.status(500).json({ error: 'otp_error' });
  }
});

// Admin forgot password - issue reset token
app.post("/admin/forgot", apiLimiter, async (req, res) => {
  try {
    const { username, email } = req.body || {};
    if (!username) return res.status(400).json({ error: "username_required" });
    if (username !== ADMIN_CREDENTIALS.username) {
      logSecurityEvent('ADMIN_FORGOT_INVALID_USER', { ip: req.ip, username });
      return res.status(200).json({ success: true });
    }
    const crypto = require('crypto');
    const token = crypto.randomBytes(24).toString('hex');
    const expiresAt = Date.now() + (15 * 60 * 1000); // 15 minutes
    state.resetTokens.set(token, { username, email: String(email || ''), expiresAt, ip: req.ip });
    logSecurityEvent('ADMIN_RESET_TOKEN_ISSUED', { ip: req.ip, username, email: String(email || ''), token: NODE_ENV === 'production' ? 'hidden' : token });
    // In production, you would send the token via email. For now, we return masked success.
    const payload = { success: true };
    if (NODE_ENV !== 'production') payload.token = token; // return for local testing only
    return res.json(payload);
  } catch (e) {
    console.error('Forgot password error:', e);
    return res.status(500).json({ error: 'forgot_error' });
  }
});

// Admin reset password - consume token and update env + in-memory
app.post("/admin/reset", apiLimiter, async (req, res) => {
  try {
    const { token, newPassword } = req.body || {};
    if (!token || !newPassword) return res.status(400).json({ error: 'missing_fields' });
    const rec = state.resetTokens.get(token);
    if (!rec) return res.status(400).json({ error: 'invalid_token' });
    if (rec.expiresAt < Date.now()) {
      state.resetTokens.delete(token);
      return res.status(400).json({ error: 'token_expired' });
    }
    if (!validateStrongPassword(newPassword)) {
      return res.status(400).json({ error: 'weak_password' });
    }
    ADMIN_CREDENTIALS.password = newPassword;
    const ok = await upsertEnv('ADMIN_PASSWORD', newPassword);
    state.resetTokens.delete(token);
    logAdminAction(req.ip, 'ADMIN_PASSWORD_RESET', { byToken: true });
    return res.json({ success: true, persisted: ok });
  } catch (e) {
    console.error('Reset password error:', e);
    return res.status(500).json({ error: 'reset_error' });
  }
});

// Admin stats
app.get("/admin/stats", authenticateAdmin, (req, res) => {
  res.json(getPublicStateForAdmin());
});

// Ads config endpoints
app.get('/api/ads/config', async (req, res) => {
  const store = await loadStore();
  const cfg = store.adsConfig || {};
  const def = {
    enabled: false,
    frequency: 10,
    type: 'placeholder',
    placeholderContent: '',
    adsenseClientId: '',
    adsenseSlotId: '',
    clicksThreshold: 3,
    showAdfreeToggle: false,
    showCoinBuyButtons: false
  };
  res.json({ ...def, ...cfg });
});

app.post('/api/admin/ads/config', authenticateAdmin, apiLimiter, async (req, res) => {
  try {
    const body = req.body || {};
    const store = await loadStore();
    store.adsConfig = {
      enabled: !!body.enabled,
      frequency: parseInt(body.frequency || 10, 10),
      type: String(body.type || 'placeholder'),
      placeholderContent: String(body.placeholderContent || ''),
      adsenseClientId: String(body.adsenseClientId || ''),
      adsenseSlotId: String(body.adsenseSlotId || ''),
      clicksThreshold: parseInt(body.clicksThreshold || 3, 10),
      showAdfreeToggle: !!body.showAdfreeToggle,
      showCoinBuyButtons: !!body.showCoinBuyButtons
    };
    await saveStore(store);
    logAdminAction(req.ip, 'ADS_CONFIG_UPDATED', store.adsConfig);
    res.json({ success: true });
  } catch (e) {
    console.error('Ads config save failed:', e);
    res.status(500).json({ error: 'ads_config_error' });
  }
});

// Feature flags (payment/premium) endpoints
app.get('/api/features/config', async (req, res) => {
  const store = await loadStore();
  const cfg = store.featuresConfig || {};
  const def = {
    paymentEnabled: false,
    premiumRecordingEnabled: false,
    premiumScreenshareEnabled: false
  };
  res.json({ ...def, ...cfg });
});

app.post('/api/admin/features/config', authenticateAdmin, apiLimiter, async (req, res) => {
  try {
    const body = req.body || {};
    const store = await loadStore();
    store.featuresConfig = {
      paymentEnabled: !!body.paymentEnabled,
      premiumRecordingEnabled: !!body.premiumRecordingEnabled,
      premiumScreenshareEnabled: !!body.premiumScreenshareEnabled
    };
    await saveStore(store);
    logAdminAction(req.ip, 'FEATURES_CONFIG_UPDATED', store.featuresConfig);
    res.json({ success: true });
  } catch (e) {
    console.error('Features config save failed:', e);
    res.status(500).json({ error: 'features_config_error' });
  }
});

// Session issuance for anonymous users
app.get('/api/session', async (req, res) => {
  try {
    let token = getTokenFromReq(req);
    if (!token) token = genToken();
    res.setHeader('Set-Cookie', [`mm_token=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax`]);
    res.json({ token });
  } catch (e) {
    res.status(500).json({ error: 'session_error' });
  }
});

// Coins balance
app.get('/api/coins/balance', async (req, res) => {
  const token = getTokenFromReq(req);
  if (!token) return res.status(401).json({ error: 'no_token' });
  const store = await loadStore();
  const coins = store.coins[token] || 0;
  res.json({ coins });
});

// Credit coins (dev/demo or webhook)
app.post('/api/coins/credit', apiLimiter, async (req, res) => {
  const token = getTokenFromReq(req);
  if (!token) return res.status(401).json({ error: 'no_token' });
  const { amount } = req.body || {};
  const amt = parseInt(amount || '0', 10);
  if (!Number.isFinite(amt) || amt <= 0 || amt > 10000) return res.status(400).json({ error: 'invalid_amount' });
  const store = await loadStore();
  store.coins[token] = (store.coins[token] || 0) + amt;
  await saveStore(store);
  res.json({ success: true, coins: store.coins[token] });
});

// Spend coins
app.post('/api/coins/spend', apiLimiter, async (req, res) => {
  const token = getTokenFromReq(req);
  if (!token) return res.status(401).json({ error: 'no_token' });
  const { amount } = req.body || {};
  const amt = parseInt(amount || '0', 10);
  if (!Number.isFinite(amt) || amt <= 0 || amt > 10000) return res.status(400).json({ error: 'invalid_amount' });
  const store = await loadStore();
  const cur = store.coins[token] || 0;
  if (cur < amt) return res.status(400).json({ error: 'insufficient' });
  store.coins[token] = cur - amt;
  await saveStore(store);
  res.json({ success: true, coins: store.coins[token] });
});

// Subscription (ad-free) status
app.get('/api/subscription/status', async (req, res) => {
  const token = getTokenFromReq(req);
  if (!token) return res.status(401).json({ error: 'no_token' });
  const store = await loadStore();
  const adfree = !!store.subscription[token];
  res.json({ adfree });
});

// Set subscription (demo toggle)
app.post('/api/subscription/set', apiLimiter, async (req, res) => {
  const token = getTokenFromReq(req);
  if (!token) return res.status(401).json({ error: 'no_token' });
  const { adfree } = req.body || {};
  const store = await loadStore();
  if (adfree) {
    store.subscription[token] = { adfree: true, since: Date.now() };
  } else {
    delete store.subscription[token];
  }
  await saveStore(store);
  res.setHeader('Set-Cookie', [`mm_adfree=${adfree ? 'true' : 'false'}; Path=/; SameSite=Lax`]);
  res.json({ success: true, adfree: !!adfree });
});

// Admin ban
app.post("/admin/ban", authenticateAdmin, apiLimiter, (req, res) => {
  const { type, value, reason } = req.body;
  
  if (!type || !value) {
    return res.status(400).json({ error: "Missing type or value" });
  }
  
  const banData = {
    type,
    value,
    reason: reason || "No reason provided",
    bannedAt: Date.now(),
    bannedBy: req.ip
  };
  
  switch (type) {
    case "user":
      state.blockedUsers.set(value, banData);
      break;
    case "ip":
      state.blockedIPs.set(value, banData);
      break;
    default:
      return res.status(400).json({ error: "Invalid ban type" });
  }
  
  logAdminAction(req.ip, "BAN_ADDED", banData);
  res.json({ success: true, message: `Banned ${type}: ${value}` });
});

// Pages
app.get("/admin", (req, res) => {
  res.sendFile(path.join(publicPath, "admin.html"));
});

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

// ============================================
// SOCKET.IO SETUP
// ============================================
const server = http.createServer(app);

const io = new Server(server, {
  transports: ["websocket", "polling"],
  pingInterval: 25000,
  pingTimeout: 20000,
  connectTimeout: 30000,
  maxHttpBufferSize: 10e6,
  cors: corsOptions,
  allowEIO3: true,
  serveClient: false
});

// ============================================
// SOCKET.IO EVENT HANDLERS
// ============================================
io.on('connection', (socket) => {
  console.log(`New connection: ${socket.id}`);
  
  // User limit enforcement with queue
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
      processQueue(io);
    });
  
    return;
  }
  
  acceptConnection(socket, io);
  state.connectionQueue = state.connectionQueue.filter(s => s.id !== socket.id);
  processQueue(io);
  
  // ============================================
  // ADMIN AUTHENTICATION
  // ============================================
  socket.on('admin-auth', (data) => {
    const { username, key } = data;
    
    if (key === ADMIN_CREDENTIALS.adminKey) {
      socket.join('admins');
      
      let userData = state.users.get(socket.id);
      if (!userData) {
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
      
      state.admins.add(socket.id);
      
      socket.emit('admin-auth-success', { 
        message: 'Authenticated as admin',
        username: userData.name
      });
      
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
    handleAdminCommand(socket, command, data, io);
  });

  // ============================================
  // CREATE GROUP ROOM
  // ============================================
  socket.on('create-group', (data) => {
    const userData = state.users.get(socket.id);
    if (!userData) return;
    
    const mode = data?.mode === 'group_video' ? 'group_video' : 'group_text';
    userData.name = sanitizeText(data?.nickname || userData.name || 'Anonymous', 30);
    userData.coins = Number.isFinite(data?.coins) ? data.coins : (userData.coins || 0);
    userData.badges = data?.badges || userData.badges || null;
    userData.isCreator = true;
    userData.mode = mode;
    userData.lastActivity = Date.now();

    const roomId = createRoom(mode, socket.id, userData);
    userData.rooms.add(roomId);
    socket.join(roomId);

    socket.emit('group-joined', {
      roomId,
      mode,
      isAdmin: Boolean(userData.isAdmin),
      isCreator: true,
      participantCount: 1
    });
    
    logSecurityEvent('GROUP_CREATED', {
      roomId,
      mode,
      creator: userData.id,
      name: userData.name
    });
  });

  // ============================================
  // JOIN GROUP ROOM
  // ============================================
  socket.on('join-group', (data) => {
    const userData = state.users.get(socket.id);
    if (!userData) return;
    
    const roomId = String(data?.roomId || '');
    const mode = data?.mode === 'group_video' ? 'group_video' : 'group_text';

    const room = state.rooms.get(roomId);
    if (!room || room.mode !== mode || room.status !== 'active') {
      return socket.emit('error', { message: 'Room not found or inactive' });
    }

    const maxSize = ROOM_MAX_SIZE[room.mode];
    if (room.users.size >= maxSize) {
      return socket.emit('room-full', { roomId, max: maxSize });
    }

    userData.name = sanitizeText(data?.nickname || userData.name || 'Anonymous', 30);
    userData.coins = Number.isFinite(data?.coins) ? data.coins : (userData.coins || 0);
    userData.badges = data?.badges || userData.badges || null;
    userData.mode = mode;
    userData.lastActivity = Date.now();

    const added = addUserToRoom(socket.id, roomId, userData);
    if (!added) {
      return socket.emit('room-full', { roomId, max: maxSize });
    }
    
    userData.rooms.add(roomId);
    socket.join(roomId);

    // Get existing peers
    const peers = Array.from(room.users)
      .filter(id => id !== socket.id)
      .map(peerId => {
        const peerData = state.users.get(peerId);
        return {
          socketId: peerId,
          userId: peerData?.id,
          nickname: peerData?.nickname || peerData?.name || 'Anonymous',
          coins: peerData?.coins || 0,
          badges: peerData?.badges || null,
          isAdmin: peerData?.isAdmin || false,
          isCreator: peerData?.isCreator || false
        };
      });

    socket.emit('group-joined', {
      roomId,
      mode,
      isAdmin: Boolean(userData.isAdmin),
      isCreator: false,
      participantCount: room.users.size
    });

    socket.emit('existing-peers', { roomId, peers, total: peers.length });

    // Notify existing peers
    io.to(roomId).emit('user-joined', {
      roomId,
      socketId: socket.id,
      userId: userData.id,
      nickname: userData.name,
      coins: userData.coins || 0,
      badges: userData.badges || null,
      isAdmin: Boolean(userData.isAdmin),
      isCreator: false,
      participantCount: room.users.size
    });
    
    // Send room chat history
    const history = state.messageHistory.get(roomId) || [];
    socket.emit('chat-history', { 
      roomId, 
      messages: history.slice(-MESSAGE_HISTORY_SIZE) 
    });

    logSecurityEvent('GROUP_JOINED', {
      roomId,
      mode,
      userId: userData.id,
      name: userData.name,
      participantCount: room.users.size
    });
  });

  // ============================================
  // FIND RANDOM PARTNER
  // ============================================
  socket.on('find-partner', (data) => {
    if (isRateLimited(socket.id, 'join')) {
      return socket.emit('rate-limited', { 
        message: 'Too many join requests. Please wait.' 
      });
    }

    const userData = state.users.get(socket.id);
    if (!userData) return;

    const mode = String(data?.mode || 'text');
    if (!['text', 'video', 'audio'].includes(mode)) {
      return socket.emit('error', { message: 'Invalid mode' });
    }

    // ✅ FIXED: Check if already in a room
    if (userData.rooms.size > 0) {
      return socket.emit('error', { message: 'Already in a room' });
    }

    const waitingQueue = state.waiting[mode];
    
    // ✅ FIXED: Check if already waiting
    if (waitingQueue.has(socket.id)) {
      return socket.emit('error', { message: 'Already searching' });
    }

    userData.name = sanitizeText(data?.nickname || userData.name || 'Anonymous', 30);
    userData.tags = Array.isArray(data?.tags) ? data.tags.slice(0, 10).filter(t => typeof t === 'string') : [];
    userData.mode = mode;
    userData.coins = Number.isFinite(data?.coins) ? data.coins : (userData.coins || 0);
    userData.badges = data?.badges || userData.badges || null;
    userData.lastActivity = Date.now();

    let foundPartner = null;

    // Search for compatible partner
    for (const [partnerId, partnerData] of waitingQueue.entries()) {
      if (partnerId === socket.id) continue;
      
      // Check if partner is still connected
      const partnerSocket = io.sockets.sockets.get(partnerId);
      if (!partnerSocket || !partnerSocket.connected) {
        waitingQueue.delete(partnerId);
        continue;
      }

      // ✅ FIXED: Check if partner is still available
      if (partnerData.rooms.size > 0) {
        waitingQueue.delete(partnerId);
        continue;
      }

      // Simple compatibility check
      const partnerTags = partnerData.tags || [];
      const userTags = userData.tags || [];
      const commonTags = partnerTags.filter(tag => userTags.includes(tag));
      
      if (commonTags.length > 0 || partnerTags.length === 0 || userTags.length === 0) {
        foundPartner = { id: partnerId, data: partnerData };
        break;
      }
    }

    if (foundPartner) {
      // ✅ FIXED: Remove from queue IMMEDIATELY to prevent race condition
      waitingQueue.delete(foundPartner.id);
      
      const roomId = createRoom(mode, socket.id, userData, 
        { socketId: foundPartner.id, data: foundPartner.data }
      );

      // Add both users to room
      userData.rooms.add(roomId);
      foundPartner.data.rooms.add(roomId);
      
      socket.join(roomId);
      const partnerSocket = io.sockets.sockets.get(foundPartner.id);
      if (partnerSocket) {
        partnerSocket.join(roomId);
      }

      // Notify both users
      socket.emit('partner-found', {
        roomId,
        mode,
        partner: {
          socketId: foundPartner.id,
          userId: foundPartner.data.id,
          nickname: foundPartner.data.name || 'Anonymous',
          tags: foundPartner.data.tags || [],
          coins: foundPartner.data.coins || 0,
          badges: foundPartner.data.badges || null
        }
      });

      if (partnerSocket) {
        partnerSocket.emit('partner-found', {
          roomId,
          mode,
          partner: {
            socketId: socket.id,
            userId: userData.id,
            nickname: userData.name,
            tags: userData.tags,
            coins: userData.coins || 0,
            badges: userData.badges || null
          }
        });
      }

      logSecurityEvent('PARTNER_FOUND', {
        roomId,
        mode,
        user1: { id: userData.id, name: userData.name },
        user2: { id: foundPartner.data.id, name: foundPartner.data.name }
      });

    } else {
      waitingQueue.set(socket.id, userData);
      socket.emit('searching', { 
        mode, 
        estimatedTime: 30,
        position: waitingQueue.size 
      });
    }
  });

  // ============================================
  // CANCEL SEARCH
  // ============================================
  socket.on('cancel-search', (data) => {
    const mode = String(data?.mode || 'text');
    if (state.waiting[mode]) {
      state.waiting[mode].delete(socket.id);
      socket.emit('search-cancelled', { mode });
    }
  });

  // ============================================
  // SEND MESSAGE
  // ============================================
  socket.on('send-message', (data) => {
    if (isRateLimited(socket.id, 'message')) {
      return socket.emit('rate-limited', { 
        message: 'Too many messages. Slow down.' 
      });
    }

    const userData = state.users.get(socket.id);
    if (!userData) return;

    const roomId = String(data?.roomId || '');
    const room = state.rooms.get(roomId);
    if (!room || !room.users.has(socket.id)) {
      return socket.emit('error', { message: 'Not in this room' });
    }

    // ✅ FIXED: Use sanitizeText helper
    const messageText = sanitizeText(data?.text);
    if (!messageText) return;

    const isAI = Boolean(data?.isAI);
    const language = String(data?.language || 'en').slice(0, 5);
    
    const message = {
      id: `msg_${Date.now()}_${Math.random().toString(36).slice(2)}`,
      roomId,
      senderId: socket.id,
      userId: userData.id,
      nickname: userData.name,
      text: messageText,
      isAI,
      language,
      timestamp: Date.now(),
      readBy: [socket.id]
    };

    // Save to message history
    const history = state.messageHistory.get(roomId) || [];
    history.push(message);
    
    if (history.length > MESSAGE_HISTORY_SIZE) {
      history.shift();
    }
    state.messageHistory.set(roomId, history);

    // Broadcast to room
    io.to(roomId).emit('new-message', message);
    room.lastActivity = Date.now();
    userData.lastActivity = Date.now();
  });

  // ============================================
  // REPORT USER
  // ============================================
  socket.on('report-user', (data) => {
    if (isRateLimited(socket.id, 'report')) {
      return socket.emit('rate-limited', { 
        message: 'Too many reports. Please wait.' 
      });
    }

    const reporterData = state.users.get(socket.id);
    if (!reporterData) return;

    const { reportedUserId, roomId, reason } = data || {};
    if (!reportedUserId || !reason) {
      return socket.emit('error', { message: 'Missing required fields' });
    }

    const report = {
      id: `rep_${Date.now()}_${Math.random().toString(36).slice(2)}`,
      reporterUserId: reporterData.id,
      reporterSocketId: socket.id,
      reportedUserId,
      roomId: roomId || null,
      reason: sanitizeText(reason, 500),
      timestamp: Date.now(),
      status: 'pending'
    };

    state.reports.push(report);
    
    socket.emit('report-submitted', { 
      success: true, 
      id: report.id 
    });

    // Notify admins
    io.to('admins').emit('new-report', report);

    logSecurityEvent('USER_REPORTED', {
      reportId: report.id,
      reporter: reporterData.id,
      reported: reportedUserId,
      reason: report.reason
    });
  });

  // ============================================
  // WEBRTC SIGNALING (ENHANCED)
  // ============================================
  socket.on('webrtc-signal', (data) => {
    if (isRateLimited(socket.id, 'signal')) {
      return;
    }

    const { roomId, targetSocketId, signal, type } = data || {};
    const userData = state.users.get(socket.id);
    const room = state.rooms.get(roomId);

    if (!userData || !room || !room.users.has(socket.id)) {
      return socket.emit('error', { message: 'Not in room or room not found' });
    }

    if (!room.users.has(targetSocketId)) {
      return socket.emit('error', { message: 'Target user not in room' });
    }

    const targetSocket = io.sockets.sockets.get(targetSocketId);
    if (!targetSocket) {
      return socket.emit('error', { message: 'Target user disconnected' });
    }

    // ✅ ENHANCED: Validate signal type
    const validTypes = ['offer', 'answer', 'ice-candidate'];
    if (!validTypes.includes(type)) {
      return socket.emit('error', { message: 'Invalid signal type' });
    }

    targetSocket.emit('webrtc-signal', {
      fromSocketId: socket.id,
      fromUserId: userData.id,
      fromNickname: userData.name,
      signal,
      type,
      roomId
    });

    room.lastActivity = Date.now();
    userData.lastActivity = Date.now();
  });

  // ============================================
  // TYPING INDICATOR
  // ============================================
  socket.on('typing', (data) => {
    if (isRateLimited(socket.id, 'typing')) {
      return;
    }

    const { roomId, isTyping } = data || {};
    const userData = state.users.get(socket.id);
    const room = state.rooms.get(roomId);

    if (!userData || !room || !room.users.has(socket.id)) {
      return;
    }

    socket.to(roomId).emit('user-typing', {
      roomId,
      socketId: socket.id,
      nickname: userData.name,
      isTyping: Boolean(isTyping)
    });
  });

  // ============================================
  // MEDIA CONTROLS
  // ============================================
  socket.on('media-control', (data) => {
    const { roomId, action, targetSocketId } = data || {};
    const userData = state.users.get(socket.id);
    const room = state.rooms.get(roomId);

    if (!userData || !room || !room.users.has(socket.id)) {
      return;
    }

    // Check if user has permission (admin or room creator)
    const isAdmin = userData.isAdmin;
    const isCreator = userData.isCreator;
    
    if (!isAdmin && !isCreator) {
      return socket.emit('error', { message: 'Permission denied' });
    }

    const targetSocket = io.sockets.sockets.get(targetSocketId);
    if (!targetSocket || !room.users.has(targetSocketId)) {
      return;
    }

    targetSocket.emit('media-control', {
      action,
      fromSocketId: socket.id,
      roomId
    });

    logSecurityEvent('MEDIA_CONTROL', {
      roomId,
      action,
      controller: userData.id,
      target: targetSocketId
    });
  });

  // ============================================
  // LEAVE ROOM
  // ============================================
  socket.on('leave-room', (data) => {
    const roomId = String(data?.roomId || '');
    const userData = state.users.get(socket.id);
    const room = state.rooms.get(roomId);

    if (!userData || !room || !room.users.has(socket.id)) {
      return;
    }

    removeUserFromRoom(socket.id, roomId, io, "voluntary");
    userData.rooms.delete(roomId);
    socket.leave(roomId);

    socket.emit('left-room', { roomId });

    logSecurityEvent('USER_LEFT_ROOM', {
      roomId,
      userId: userData.id,
      name: userData.name,
      mode: room.mode
    });
  });

  // ============================================
  // KEEP ALIVE / PONG
  // ============================================
  socket.on('pong', () => {
    const userData = state.users.get(socket.id);
    if (userData) {
      userData.lastActivity = Date.now();
    }
  });

  // ============================================
  // DISCONNECT
  // ============================================
  socket.on('disconnect', (reason) => {
    console.log(`Disconnected: ${socket.id} - ${reason}`);

    const userData = state.users.get(socket.id);
    if (!userData) {
      // Remove from queue if present
      state.connectionQueue = state.connectionQueue.filter(s => s.id !== socket.id);
      processQueue(io);
      return;
    }

    // Remove from waiting queues
    Object.values(state.waiting).forEach(queue => queue.delete(socket.id));

    // Leave all rooms
    for (const roomId of userData.rooms) {
      removeUserFromRoom(socket.id, roomId, io, "disconnected");
    }

    // Remove user
    state.users.delete(socket.id);
    state.admins.delete(socket.id);
    state.socketRateLimits.delete(socket.id);

    // Update online count
    io.emit('online_count', { count: state.users.size });

    logSecurityEvent('USER_DISCONNECTED', {
      socketId: socket.id,
      userId: userData.id,
      name: userData.name,
      reason,
      duration: Date.now() - userData.connectedAt
    });

    // Process queue
    processQueue(io);
  });

  // ============================================
  // ERROR HANDLING
  // ============================================
  socket.on('error', (error) => {
    console.error('Socket error:', error);
    logSecurityEvent('SOCKET_ERROR', {
      socketId: socket.id,
      error: error.message || String(error)
    });
  });
});

// ============================================
// PERIODIC CLEANUP
// ============================================
setInterval(() => {
  const now = Date.now();
  
  // Clean up old rooms
  for (const [roomId, room] of state.rooms.entries()) {
    const timeSinceActivity = now - room.lastActivity;
    const maxInactive = ROOM_TIMEOUTS[room.mode] || 3600000;
    
    if (room.status === 'active' && timeSinceActivity > maxInactive) {
      endRoom(roomId, "inactivity", io);
    }
  }
  
  // Clean up rate limit records
  for (const [socketId, limits] of state.socketRateLimits.entries()) {
    for (const [type, limit] of Object.entries(limits)) {
      if (now - limit.lastRequest > 600000) { // 10 minutes
        delete limits[type];
      }
    }
    if (Object.keys(limits).length === 0) {
      state.socketRateLimits.delete(socketId);
    }
  }
  
  // Clean up old security logs
  if (state.securityLogs.length > 5000) {
    state.securityLogs = state.securityLogs.slice(0, 2000);
  }
  
  // Clean up old reports
  if (state.reports.length > 1000) {
    state.reports = state.reports.slice(-500);
  }
  
  // Remove expired bans
  for (const [userId, ban] of state.blockedUsers.entries()) {
    if (ban.expiresAt && now > ban.expiresAt) {
      state.blockedUsers.delete(userId);
    }
  }
  
  for (const [ip, ban] of state.blockedIPs.entries()) {
    if (ban.expiresAt && now > ban.expiresAt) {
      state.blockedIPs.delete(ip);
    }
  }
}, 60000); // Run every minute

// ============================================
// START SERVER
// ============================================
async function startServer() {
  await setupLogging();
  
  server.listen(PORT, HOST, () => {
    console.log(`
============================================
🚀 ManaMingle Server Started (v1.0.1-FIXED)
============================================
📡 Server: http://${HOST}:${PORT}
🌐 Environment: ${NODE_ENV}
🔒 Admin Panel: /admin
📊 Health Check: /health
👥 Max Users: ${MAX_USERS}
⏰ Started: ${new Date().toISOString()}
✅ All critical bugs fixed
============================================
    `);
    
    if (NODE_ENV === 'production') {
      console.log('✅ Running in PRODUCTION mode');
    } else {
      console.log('🔧 Running in DEVELOPMENT mode');
      console.log('🔑 Default admin credentials may be active');
    }
  });
}

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully...');
  logSecurityEvent('SERVER_SHUTDOWN', { reason: 'SIGTERM' });
  
  // Disconnect all sockets
  io.disconnectSockets();
  
  setTimeout(() => {
    process.exit(0);
  }, 5000);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down...');
  logSecurityEvent('SERVER_SHUTDOWN', { reason: 'SIGINT' });
  
  io.disconnectSockets();
  
  setTimeout(() => {
    process.exit(0);
  }, 3000);
});

// Start the server
if (require.main === module) {
  startServer().catch(error => {
    console.error('Failed to start server:', error);
    process.exit(1);
  });
}

// ============================================
// EXPORTS FOR TESTING
// ============================================
module.exports = {
  app,
  server,
  io,
  state,
  generateRoomId,
  generateUserId,
  createRoom,
  addUserToRoom,
  removeUserFromRoom,
  endRoom,
  getPublicStateForAdmin,
  isRateLimited,
  sanitizeText
};
