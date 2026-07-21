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

    // Ensure Indexes for performance and constraints
    await usersCol.createIndex({ username: 1 }, { unique: true });
    await filesCol.createIndex({ username: 1, path: 1, name: 1 });
    await ledgerCol.createIndex({ username: 1 });

    // 2. SignUp action
    if (action === 'signup') {
      const existingUser = await usersCol.findOne({ username });
      if (existingUser) {
        return res.status(400).json({ error: 'Username already exists.' });
      }
      await usersCol.insertOne({ username, passwordHash });
      return res.status(200).json({ success: true });
    }

    // 3. SignIn action
    if (action === 'signin') {
      const user = await usersCol.findOne({ username });
      if (!user || user.passwordHash !== passwordHash) {
        return res.status(401).json({ error: 'Incorrect username or password.' });
      }
      return res.status(200).json({ success: true });
    }

    // 4. Authenticate credentials for all subsequent data modification/retrieval actions
    const user = await usersCol.findOne({ username });
    if (!user || user.passwordHash !== passwordHash) {
      return res.status(401).json({ error: 'Unauthorized access.' });
    }

    // 5. Data Actions
    
    // Get all virtual files and ledger logs for user
    if (action === 'get_data') {
      const ledger = await ledgerCol.find({ username }).toArray();
      const files = await filesCol.find({ username }).toArray();
      
      // Clean MongoDB custom objects (e.g. _id) before returning
      const cleanLedger = ledger.map(item => {
        const { _id, ...rest } = item;
        return rest;
      });
      const cleanFiles = files.map(item => {
        const { _id, ...rest } = item;
        return rest;
      });

      return res.status(200).json({
        ledger: cleanLedger,
        files: cleanFiles
      });
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
            content: file.content, // base64 representation of file content
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
