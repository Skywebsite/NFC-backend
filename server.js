require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const { MongoClient } = require('mongodb');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const path = require('path');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3001;

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// MongoDB connection
let db;
let mongoClient;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/nfc-students';

async function connectToMongoDB() {
  try {
    mongoClient = await MongoClient.connect(MONGODB_URI);
    
    // Extract database name from URI
    // Format: mongodb+srv://user:pass@host/dbname?options
    let dbName = 'nfc-students'; // default
    const uriParts = MONGODB_URI.split('/');
    if (uriParts.length >= 4) {
      const dbPart = uriParts[uriParts.length - 1].split('?')[0];
      if (dbPart && dbPart.length > 0) {
        dbName = dbPart;
      }
    }
    
    db = mongoClient.db(dbName);
    
    console.log('Connected to MongoDB');
    console.log(`Database name: ${dbName}`);
    
    // Test the connection
    await db.admin().ping();
    console.log('MongoDB connection verified');
    
    // List all collections
    const collections = await db.listCollections().toArray();
    console.log('Available collections:', collections.map(c => c.name).join(', ') || 'None');
    
    // Check users collection
    const usersCollection = db.collection('users');
    const userCount = await usersCollection.countDocuments();
    console.log(`Users collection document count: ${userCount}`);
    
    // If users exist, show a sample
    if (userCount > 0) {
      const sampleUsers = await usersCollection.find({}).limit(3).toArray();
      console.log('Sample users:', sampleUsers.map(u => ({ userId: u.userId, accessCode: u.accessCode })));
    } else {
      // Create a test user if no users exist
      console.log('No users found. Creating test user...');
      const testUser = {
        userId: 'test-user-001',
        name: 'Test User',
        accessCode: 'TEST123',
        studentId: 'test-user-001',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      
      try {
        await usersCollection.insertOne(testUser);
        console.log('✅ Test user created successfully!');
        console.log('   📝 Access Code: TEST123');
        console.log('   👤 User ID: test-user-001');
        console.log('   📛 Name: Test User');
        console.log('   💡 You can use "TEST123" to login');
      } catch (err) {
        console.error('Failed to create test user:', err.message);
      }
    }
    
    return true;
  } catch (error) {
    console.error('MongoDB connection error:', error.message);
    console.error('Please check your MONGODB_URI in .env file');
    console.log('Server will continue running, but database operations will fail until MongoDB is connected.');
    // Don't exit - allow server to run and retry connection
    return false;
  }
}

// Start server after MongoDB connection
async function startServer() {
  await connectToMongoDB();
  
  app.listen(PORT, () => {
    console.log(`\n🚀 Server running on http://localhost:${PORT}`);
    console.log(`\n📋 API endpoints:`);
    console.log(`  POST   /api/admin/login - Admin login`);
    console.log(`  GET    /api/admin/verify - Verify admin session`);
    console.log(`  POST   /api/admin/logout - Admin logout`);
    console.log(`  POST   /api/students - Create/Update student`);
    console.log(`  GET    /api/students/:id - Get student by ID`);
    console.log(`  GET    /api/students - Get all students`);
    console.log(`  DELETE /api/students/:id - Delete student`);
    console.log(`  POST   /api/users - Create/Update user`);
    console.log(`  GET    /api/users - Get all users`);
    console.log(`  POST   /api/users/login - User login`);
    console.log(`  POST   /api/users/link - Generate profile link`);
    console.log(`  POST   /api/users/test - Create test user`);
    console.log(`  GET    /api/users/debug - Debug: List all users`);
    console.log(`  POST   /api/upload - Upload image`);
    console.log(`  GET    /api/health - Health check`);
    console.log(`\n💡 Admin Credentials:`);
    console.log(`   Admin ID: admin | Password: password123`);
    console.log(`   Admin ID: admin001 | Password: admin123`);
    console.log(`\n💡 Test User Credentials:`);
    console.log(`   Access Code: TEST123`);
    console.log(`   (Created automatically if no users exist)\n`);
  });
}

startServer();

// Helper function to check database connection
function checkDatabase(res) {
  if (!db) {
    res.status(503).json({ 
      error: 'Database not connected', 
      hint: 'Please check MongoDB connection and credentials in .env file' 
    });
    return false;
  }
  return true;
}

// CORS configuration for credentials support
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:3001', 
      'http://127.0.0.1:3000',
      'http://127.0.0.1:3001',
      'https://nfc-backend-gamma.vercel.app'
    ];
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true, // Allow credentials (cookies, authorization headers)
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
};

// Middleware
app.use(cors(corsOptions));
app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Configure multer for file uploads
const upload = multer({ storage: multer.memoryStorage() });

// Simple session storage (in production, use Redis or database)
const adminSessions = new Map();

// Generate simple session token
function generateSessionToken() {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

// ==================== ADMIN AUTHENTICATION ENDPOINTS ====================

app.post('/api/admin/login', async (req, res) => {
  try {
    const { adminId, password } = req.body;

    if (!adminId || !password) {
      return res.status(400).json({ error: 'Admin ID and password are required' });
    }

    // Simple admin credentials (in production, use database with hashed passwords)
    const validAdmins = {
      'admin001': 'admin123',
      'admin': 'password123'
    };

    if (validAdmins[adminId] && validAdmins[adminId] === password) {
      // Create session
      const sessionToken = generateSessionToken();
      const sessionData = {
        adminId,
        loginTime: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() // 24 hours
      };
      
      adminSessions.set(sessionToken, sessionData);

      // Set cookie
      res.cookie('adminSession', sessionToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
      });

      res.json({
        success: true,
        message: 'Login successful',
        data: { adminId }
      });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/admin/verify', (req, res) => {
  try {
    const sessionToken = req.cookies.adminSession;

    if (!sessionToken || !adminSessions.has(sessionToken)) {
      return res.status(401).json({ authenticated: false });
    }

    const session = adminSessions.get(sessionToken);
    const now = new Date();
    const expiresAt = new Date(session.expiresAt);

    if (now > expiresAt) {
      adminSessions.delete(sessionToken);
      res.clearCookie('adminSession');
      return res.status(401).json({ authenticated: false });
    }

    res.json({
      authenticated: true,
      adminId: session.adminId
    });
  } catch (error) {
    console.error('Admin verify error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

app.post('/api/admin/logout', (req, res) => {
  try {
    const sessionToken = req.cookies.adminSession;

    if (sessionToken && adminSessions.has(sessionToken)) {
      adminSessions.delete(sessionToken);
    }

    res.clearCookie('adminSession');
    res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    console.error('Admin logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
});

// ==================== STUDENT ENDPOINTS ====================

// POST endpoint to create/update student data
app.post('/api/students', async (req, res) => {
  try {
    if (!checkDatabase(res)) return;

    const { id, studentData } = req.body;

    if (!id) {
      return res.status(400).json({ error: 'ID is required' });
    }

    const collection = db.collection('students');
    const student = {
      id,
      ...studentData,
      updatedAt: new Date().toISOString(),
    };

    await collection.updateOne(
      { id },
      { $set: student },
      { upsert: true }
    );

    res.json({ success: true, message: 'Student data saved successfully', data: student });
  } catch (error) {
    console.error('Error saving student:', error);
    res.status(500).json({ error: 'Failed to save student data', details: error.message });
  }
});

// GET endpoint to fetch student data by ID
app.get('/api/students/:id', async (req, res) => {
  try {
    if (!checkDatabase(res)) return;

    const { id } = req.params;
    const collection = db.collection('students');
    const student = await collection.findOne({ id });

    if (!student) {
      return res.status(404).json({ error: 'Student not found' });
    }

    res.json({ success: true, data: student });
  } catch (error) {
    console.error('Error fetching student:', error);
    res.status(500).json({ error: 'Failed to fetch student data', details: error.message });
  }
});

// GET endpoint to fetch all students
app.get('/api/students', async (req, res) => {
  try {
    if (!checkDatabase(res)) return;

    const collection = db.collection('students');
    const students = await collection.find({}).toArray();
    res.json({ success: true, data: students });
  } catch (error) {
    console.error('Error fetching students:', error);
    res.status(500).json({ error: 'Failed to fetch students', details: error.message });
  }
});

// DELETE endpoint to delete student data
app.delete('/api/students/:id', async (req, res) => {
  try {
    if (!checkDatabase(res)) return;

    const { id } = req.params;
    const collection = db.collection('students');
    const result = await collection.deleteOne({ id });

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Student not found' });
    }

    res.json({ success: true, message: 'Student deleted successfully' });
  } catch (error) {
    console.error('Error deleting student:', error);
    res.status(500).json({ error: 'Failed to delete student', details: error.message });
  }
});

// ==================== USER ENDPOINTS ====================

// POST endpoint to create/update user
app.post('/api/users', async (req, res) => {
  try {
    if (!checkDatabase(res)) return;

    const { userId, name, accessCode, studentId } = req.body;

    if (!userId || !name || !accessCode) {
      return res.status(400).json({
        error: 'userId, name, and accessCode are required',
      });
    }

    const collection = db.collection('users');
    // Normalize access code (trim and uppercase)
    const normalizedAccessCode = accessCode.trim().toUpperCase();

    const user = {
      userId,
      name,
      accessCode: normalizedAccessCode,
      studentId: studentId || userId,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    await collection.updateOne(
      { userId },
      { $set: user },
      { upsert: true }
    );

    res.json({
      success: true,
      message: 'User created successfully',
      data: user,
    });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ error: 'Failed to create user', details: error.message });
  }
});

// GET endpoint to fetch all users
app.get('/api/users', async (req, res) => {
  try {
    if (!checkDatabase(res)) return;

    const collection = db.collection('users');
    const users = await collection.find({}).toArray();
    res.json({ success: true, data: users });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users', details: error.message });
  }
});

// POST endpoint for user login
app.post('/api/users/login', async (req, res) => {
  try {
    if (!checkDatabase(res)) return;

    const { accessCode } = req.body;

    if (!accessCode) {
      return res.status(400).json({ error: 'Access code is required' });
    }

    // Normalize the access code (trim, but keep original case for student ID matching)
    const normalizedAccessCode = accessCode.trim();
    const normalizedAccessCodeUpper = normalizedAccessCode.toUpperCase();
    console.log(`[LOGIN] Searching for access code: "${normalizedAccessCode}"`);

    // First, try users collection
    const usersCollection = db.collection('users');
    let user = await usersCollection.findOne({ accessCode: normalizedAccessCodeUpper });
    
    if (user) {
      console.log(`[LOGIN] Found in users collection: ${user.name}`);
      return res.json({
        success: true,
        data: {
          userId: user.userId,
          name: user.name,
          studentId: user.studentId,
          accessCode: user.accessCode,
        },
      });
    }

    // If not found in users, check students collection using id field
    console.log(`[LOGIN] Not found in users collection, checking students collection...`);
    const studentsCollection = db.collection('students');
    
    // Try exact match first
    let student = await studentsCollection.findOne({ id: normalizedAccessCode });
    
    // If not found, try case-insensitive
    if (!student) {
      const allStudents = await studentsCollection.find({}).toArray();
      student = allStudents.find(s => {
        const studentId = s.id?.toString().trim();
        return studentId === normalizedAccessCode || studentId?.toUpperCase() === normalizedAccessCodeUpper;
      });
    }

    if (student) {
      console.log(`[LOGIN] Found in students collection: ${student.studentName || student.id}`);
      
      // Create a user-like response from student data
      return res.json({
        success: true,
        data: {
          userId: student.id || student.idNumber,
          name: student.studentName || 'Student',
          studentId: student.id || student.idNumber,
          accessCode: student.id,
        },
      });
    }

    // Not found in either collection
    console.log(`[LOGIN] Access code "${normalizedAccessCode}" not found in users or students collections`);
    
    // Get counts for debugging
    const userCount = await usersCollection.countDocuments();
    const studentCount = await studentsCollection.countDocuments();
    const allStudents = await studentsCollection.find({}).toArray();
    const studentIds = allStudents.map(s => s.id).filter(Boolean);
    
    return res.status(401).json({
      error: 'Invalid access code',
      hint: 'Please make sure you have created a user with this access code, or use a valid student ID',
      debug: {
        searchedCode: normalizedAccessCode,
        usersCollection: {
          total: userCount,
          accessCodes: []
        },
        studentsCollection: {
          total: studentCount,
          studentIds: studentIds.length > 0 ? studentIds : 'No students found'
        }
      }
    });
  } catch (error) {
    console.error('Database error during login:', error);
    res.status(500).json({
      error: 'Database connection failed',
      details: error.message,
      hint: 'Please check your MongoDB connection and ensure .env is configured correctly',
    });
  }
});

// POST endpoint to generate profile link (from access code)
app.post('/api/users/link', async (req, res) => {
  try {
    if (!checkDatabase(res)) return;

    const { accessCode } = req.body;

    if (!accessCode) {
      return res.status(400).json({ error: 'Access code is required' });
    }

    const collection = db.collection('users');
    const normalizedAccessCode = accessCode.trim().toUpperCase();
    const user = await collection.findOne({ accessCode: normalizedAccessCode });

    if (!user) {
      return res.status(404).json({ error: 'Invalid access code' });
    }

    // Generate profile link
    // Format: nfc://profile?code=ACCESS_CODE
    const profileLink = `nfc://profile?code=${encodeURIComponent(normalizedAccessCode)}`;
    
    // Also generate a web link that redirects to the app
    const baseUrl = process.env.API_URL || 'http://localhost:3001';
    const webLink = `${baseUrl}/profile?code=${encodeURIComponent(normalizedAccessCode)}`;

    res.json({
      success: true,
      data: {
        profileLink,
        webLink,
        accessCode: user.accessCode,
        userId: user.userId,
        name: user.name,
      },
    });
  } catch (error) {
    console.error('Error generating link:', error);
    res.status(500).json({ error: 'Failed to generate link', details: error.message });
  }
});

// POST endpoint to generate profile link from student ID
app.post('/api/students/link', async (req, res) => {
  try {
    if (!checkDatabase(res)) return;

    const { studentId } = req.body;

    if (!studentId) {
      return res.status(400).json({ error: 'Student ID is required' });
    }

    const studentsCollection = db.collection('students');
    const student = await studentsCollection.findOne({ id: studentId });

    if (!student) {
      return res.status(404).json({ error: 'Student not found' });
    }

    // Use student ID as the access code (since login checks students collection)
    const accessCode = studentId;

    // Generate NFC link for NFC tags
    // Format: nfc://profile?code=STUDENT_ID
    const nfcLink = `nfc://profile?code=${encodeURIComponent(accessCode)}`;
    
    // Generate web link that redirects to app
    // For web admin, use the web-admin URL
    const webAdminUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';
    const webLink = `${webAdminUrl}/profile?code=${encodeURIComponent(accessCode)}`;
    
    // Generate Expo deep link (for testing)
    const expoIp = process.env.EXPO_IP || '192.168.0.6';
    const expoLink = `exp://${expoIp}:8081/--/profile?code=${encodeURIComponent(accessCode)}`;
    
    // Also generate a universal link format
    const universalLink = `https://nfc.app/profile?code=${encodeURIComponent(accessCode)}`;

    res.json({
      success: true,
      data: {
        studentId: student.id,
        studentName: student.studentName || 'Student',
        nfcLink, // For NFC tags - use this when programming NFC tags
        webLink, // For web browsers - opens profile page that redirects to app
        expoLink, // For Expo testing (development)
        accessCode: accessCode, // Student ID used for login
      },
    });
  } catch (error) {
    console.error('Error generating student link:', error);
    res.status(500).json({ error: 'Failed to generate link', details: error.message });
  }
});

// ==================== UPLOAD ENDPOINT ====================

// POST endpoint for image upload
app.post('/api/upload', upload.single('image'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image file provided' });
    }

    // Upload to Cloudinary
    const uploadResult = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        {
          resource_type: 'image',
          folder: 'nfc-students',
        },
        (error, result) => {
          if (error) {
            reject(error);
          } else {
            resolve(result);
          }
        }
      );
      uploadStream.end(req.file.buffer);
    });

    res.json({
      success: true,
      imageUrl: uploadResult?.secure_url || '',
    });
  } catch (error) {
    console.error('Error uploading image:', error);
    res.status(500).json({ error: 'Failed to upload image', details: error.message });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    success: true, 
    message: 'Server is running',
    database: db ? 'connected' : 'disconnected'
  });
});

// Endpoint to create a test user
app.post('/api/users/test', async (req, res) => {
  try {
    if (!checkDatabase(res)) return;

    const collection = db.collection('users');
    
    const testUser = {
      userId: 'test-user-001',
      name: 'Test User',
      accessCode: 'TEST123',
      studentId: 'test-user-001',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    // Check if test user already exists
    const existing = await collection.findOne({ userId: 'test-user-001' });
    if (existing) {
      return res.json({
        success: true,
        message: 'Test user already exists',
        data: {
          userId: existing.userId,
          name: existing.name,
          accessCode: existing.accessCode,
          studentId: existing.studentId
        },
        loginInfo: {
          accessCode: 'TEST123',
          message: 'Use "TEST123" to login'
        }
      });
    }

    await collection.insertOne(testUser);
    
    res.json({
      success: true,
      message: 'Test user created successfully',
      data: {
        userId: testUser.userId,
        name: testUser.name,
        accessCode: testUser.accessCode,
        studentId: testUser.studentId
      },
      loginInfo: {
        accessCode: 'TEST123',
        message: 'You can now use "TEST123" to login'
      }
    });
  } catch (error) {
    console.error('Error creating test user:', error);
    res.status(500).json({ error: 'Failed to create test user', details: error.message });
  }
});

// Debug endpoint to list all users and their access codes (for troubleshooting)
app.get('/api/users/debug', async (req, res) => {
  try {
    if (!checkDatabase(res)) return;

    const usersCollection = db.collection('users');
    const studentsCollection = db.collection('students');
    
    const users = await usersCollection.find({}).toArray();
    const students = await studentsCollection.find({}).toArray();
    
    const userList = users.map(u => ({
      userId: u.userId,
      name: u.name,
      accessCode: u.accessCode,
      studentId: u.studentId
    }));

    const studentList = students.map(s => ({
      id: s.id,
      studentName: s.studentName,
      idNumber: s.idNumber
    }));

    res.json({
      success: true,
      collections: {
        users: {
          total: users.length,
          documents: userList
        },
        students: {
          total: students.length,
          documents: studentList
        }
      },
      note: 'Login uses the "users" collection, not "students" collection'
    });
  } catch (error) {
    console.error('Error fetching users for debug:', error);
    res.status(500).json({ error: 'Failed to fetch users', details: error.message });
  }
});

// Endpoint to create a test user
app.post('/api/users/test', async (req, res) => {
  try {
    if (!checkDatabase(res)) return;

    const collection = db.collection('users');
    
    const testUser = {
      userId: 'test-user-001',
      name: 'Test User',
      accessCode: 'TEST123',
      studentId: 'test-user-001',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    // Check if test user already exists
    const existing = await collection.findOne({ userId: 'test-user-001' });
    if (existing) {
      return res.json({
        success: true,
        message: 'Test user already exists',
        data: {
          userId: existing.userId,
          name: existing.name,
          accessCode: existing.accessCode,
          studentId: existing.studentId
        },
        loginInfo: {
          accessCode: 'TEST123',
          message: 'Use "TEST123" to login'
        }
      });
    }

    await collection.insertOne(testUser);
    
    res.json({
      success: true,
      message: 'Test user created successfully',
      data: {
        userId: testUser.userId,
        name: testUser.name,
        accessCode: testUser.accessCode,
        studentId: testUser.studentId
      },
      loginInfo: {
        accessCode: 'TEST123',
        message: 'You can now use "TEST123" to login'
      }
    });
  } catch (error) {
    console.error('Error creating test user:', error);
    res.status(500).json({ error: 'Failed to create test user', details: error.message });
  }
});
