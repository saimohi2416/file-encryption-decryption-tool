// api/db-sync.js
// Vercel Serverless Function to sync SecureVault data with MongoDB.

const { MongoClient } = require('mongodb');

let cachedClient = null;
let cachedDb = null;

async function connectToDatabase() {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    throw new Error('MONGODB_URI is not set');
  }

  if (cachedClient && cachedDb) {
    return { client: cachedClient, db: cachedDb };
  }

  // Initialize MongoClient
  const client = new MongoClient(uri);

  await client.connect();
  const db = client.db(); // Uses the database name from connection URI automatically

  cachedClient = client;
  cachedDb = db;
  return { client, db };
}

module.exports = async function handler(req, res) {
  // Set CORS headers for local development and cross-origin access
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  // Handle preflight request
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const { action } = req.query;

  // 1. Status action: Check if MongoDB is configured and connection is healthy
  if (action === 'status') {
    const uri = process.env.MONGODB_URI;
    if (!uri) {
      return res.status(200).json({ configured: false, connected: false, message: 'MONGODB_URI environment variable is missing.' });
    }
    try {
      const { db } = await connectToDatabase();
      // Test ping
      await db.command({ ping: 1 });
      return res.status(200).json({ configured: true, connected: true });
    } catch (err) {
      console.error('MongoDB connection status check failed:', err);
      return res.status(200).json({ configured: true, connected: false, error: err.message });
    }
  }

  // All other sync endpoints should be POST requests
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  try {
    const { db } = await connectToDatabase();
    const body = req.body || {};
    const { username, passwordHash } = body;

    if (!username) {
      return res.status(400).json({ error: 'Username is required.' });
    }

    const usersCol = db.collection('users');
    const ledgerCol = db.collection('ledger');
    const filesCol = db.collection('virtual_files');
    const auditCol = db.collection('audit_logs');

    // Ensure Indexes for performance and constraints
    await usersCol.createIndex({ username: 1 }, { unique: true });
    await filesCol.createIndex({ username: 1, path: 1, name: 1 });
    await ledgerCol.createIndex({ username: 1 });
    await auditCol.createIndex({ username: 1, timestamp: -1 });

    // 2. SignUp action
    if (action === 'signup') {
      const existingUser = await usersCol.findOne({ username });
      if (existingUser) {
        return res.status(400).json({ error: 'Username already exists.' });
      }
      await usersCol.insertOne({
        username,
        passwordHash,
        mfaEnabled: false,
        mfaSecret: null,
        createdAt: new Date().toISOString()
      });
      return res.status(200).json({ success: true });
    }

    // 3. SignIn action
    if (action === 'signin') {
      const user = await usersCol.findOne({ username });
      if (!user || user.passwordHash !== passwordHash) {
        return res.status(401).json({ error: 'Incorrect username or password.' });
      }
      return res.status(200).json({
        success: true,
        mfaRequired: !!user.mfaEnabled,
        mfaSecret: user.mfaEnabled ? user.mfaSecret : null
      });
    }

    // 3.5 OAuth Login (Google / GitHub)
    if (action === 'oauth_login') {
      const { email, provider, providerId, avatarUrl } = body;
      if (!username || !provider) {
        return res.status(400).json({ error: 'Username and provider are required for OAuth login.' });
      }

      let existingUser = await usersCol.findOne({ username });
      if (!existingUser) {
        await usersCol.insertOne({
          username,
          email: email || `${username}@${provider}.auth`,
          provider,
          providerId: providerId || `${provider}_${Date.now()}`,
          avatarUrl: avatarUrl || null,
          passwordHash: passwordHash || 'OAUTH_PASS_HASH_' + provider,
          mfaEnabled: false,
          mfaSecret: null,
          createdAt: new Date().toISOString()
        });
        existingUser = await usersCol.findOne({ username });
      } else {
        await usersCol.updateOne(
          { username },
          { $set: { lastLogin: new Date().toISOString(), avatarUrl: avatarUrl || existingUser.avatarUrl, provider } }
        );
      }

      return res.status(200).json({
        success: true,
        username: existingUser.username,
        email: existingUser.email,
        provider: existingUser.provider,
        mfaRequired: !!existingUser.mfaEnabled,
        mfaSecret: existingUser.mfaEnabled ? existingUser.mfaSecret : null
      });
    }

    // 4. Authenticate credentials for all subsequent data modification/retrieval actions
    const user = await usersCol.findOne({ username });
    if (!user || user.passwordHash !== passwordHash) {
      return res.status(401).json({ error: 'Unauthorized access.' });
    }

    // 5. MFA Management
    if (action === 'update_mfa') {
      const { mfaEnabled, mfaSecret } = body;
      await usersCol.updateOne(
        { username },
        { $set: { mfaEnabled: !!mfaEnabled, mfaSecret: mfaSecret || null } }
      );
      return res.status(200).json({ success: true, mfaEnabled: !!mfaEnabled });
    }

    // 6. Data Actions
    
    // Get all virtual files, ledger logs, and audit logs for user
    if (action === 'get_data') {
      const ledger = await ledgerCol.find({ username }).toArray();
      const files = await filesCol.find({ username }).toArray();
      const auditLogs = await auditCol.find({ username }).sort({ timestamp: -1 }).limit(100).toArray();
      
      const cleanLedger = ledger.map(item => { const { _id, ...rest } = item; return rest; });
      const cleanFiles = files.map(item => { const { _id, ...rest } = item; return rest; });
      const cleanAudit = auditLogs.map(item => { const { _id, ...rest } = item; return rest; });

      return res.status(200).json({
        ledger: cleanLedger,
        files: cleanFiles,
        auditLogs: cleanAudit,
        mfaEnabled: !!user.mfaEnabled
      });
    }

    // Add audit log entry (Zero-Knowledge encrypted or structured)
    if (action === 'add_audit_log') {
      const { logEntry } = body;
      if (!logEntry) {
        return res.status(400).json({ error: 'Invalid log payload.' });
      }
      await auditCol.insertOne({
        username,
        action: logEntry.action,
        severity: logEntry.severity || 'info',
        details: logEntry.details,
        timestamp: logEntry.timestamp || new Date().toISOString(),
        ipAddress: req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1'
      });
      return res.status(200).json({ success: true });
    }

    // Save/Update a virtual file
    if (action === 'save_file') {
      const { file } = body;
      if (!file || !file.name || !file.path) {
        return res.status(400).json({ error: 'Invalid file payload.' });
      }

      await filesCol.updateOne(
        { username, path: file.path, name: file.name },
        { 
          $set: { 
            username,
            name: file.name,
            type: file.type,
            size: file.size,
            date: file.date,
            path: file.path,
            content: file.content,
            mimeType: file.mimeType
          } 
        },
        { upsert: true }
      );
      return res.status(200).json({ success: true });
    }

    // Delete a virtual file
    if (action === 'delete_file') {
      const { path, name } = body;
      if (!name || !path) {
        return res.status(400).json({ error: 'Path and name are required to delete.' });
      }
      await filesCol.deleteOne({ username, path, name });
      return res.status(200).json({ success: true });
    }

    // Add a ledger entry
    if (action === 'add_ledger') {
      const { entry } = body;
      if (!entry || !entry.txHash) {
        return res.status(400).json({ error: 'Invalid ledger entry payload.' });
      }
      await ledgerCol.insertOne({
        username,
        txHash: entry.txHash,
        timestamp: entry.timestamp,
        fileName: entry.fileName,
        operation: entry.operation,
        size: entry.size,
        status: entry.status,
        sha256: entry.sha256
      });
      return res.status(200).json({ success: true });
    }

    // Clear ledger history
    if (action === 'clear_ledger') {
      await ledgerCol.deleteMany({ username });
      return res.status(200).json({ success: true });
    }

    return res.status(400).json({ error: 'Unknown action.' });

  } catch (error) {
    console.error('Server error in api/db-sync:', error);
    return res.status(500).json({ error: 'Internal Server Error: ' + error.message });
  }
};
