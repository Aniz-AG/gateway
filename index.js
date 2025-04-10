const express = require('express');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const fs = require('fs');
const crypto = require('crypto');
const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/payment-gateway', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// Client Schema
const clientSchema = new mongoose.Schema({
  baseUrl: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  upiId: {
    type: String,
    trim: true
  },
  qrImagePath: {
    type: String
  },
  securityCodeHash: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

const Client = mongoose.model('Client', clientSchema);

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadsDir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
    }
    cb(null, uploadsDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + uuidv4();
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

// File filter to only allow images
const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/')) {
    cb(null, true);
  } else {
    cb(new Error('Only image files are allowed'), false);
  }
};

const upload = multer({ 
  storage, 
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Setup CORS with whitelist
const corsOptions = {
  origin: function (origin, callback) {
    // In production, you'd replace this with your actual whitelist
    // For now, allow any origin during development
    callback(null, true);
  },
  methods: ['GET', 'POST'],
  credentials: true
};

app.use(cors(corsOptions));
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Hash security code
const hashSecurityCode = (code) => {
  return crypto.createHash('sha256').update(code).digest('hex');
};

// Route to update payment details
app.post('/update', upload.single('qrImage'), async (req, res) => {
  try {
    const { baseUrl, upiId, securityCode, existingSecurityCode } = req.body;
    
    if (!baseUrl) {
      return res.status(400).json({ success: false, message: 'Base URL is required' });
    }

    const qrImagePath = req.file ? `/uploads/${req.file.filename}` : null;
    
    // Check if client exists
    const existingClient = await Client.findOne({ baseUrl });
    
    // If client doesn't exist, create new client with security code
    if (!existingClient) {
      if (!securityCode) {
        return res.status(400).json({ success: false, message: 'Security code is required for new client' });
      }
      
      const newClient = new Client({
        baseUrl,
        upiId: upiId || '',
        qrImagePath: qrImagePath || '',
        securityCodeHash: hashSecurityCode(securityCode)
      });
      
      await newClient.save();
      
      return res.status(201).json({ 
        success: true, 
        message: 'Client added successfully',
        data: {
          baseUrl: newClient.baseUrl,
          upiId: newClient.upiId,
          qrImagePath: newClient.qrImagePath,
        }
      });
    }
    
    // If client exists, verify security code
    if (!existingSecurityCode) {
      return res.status(400).json({ success: false, message: 'Security code is required' });
    }
    
    if (hashSecurityCode(existingSecurityCode) !== existingClient.securityCodeHash) {
      return res.status(403).json({ success: false, message: 'Invalid security code' });
    }
    
    // Update client details
    const updateData = {
      updatedAt: new Date()
    };
    
    if (upiId) updateData.upiId = upiId;
    if (qrImagePath) {
      // Delete old image if exists
      if (existingClient.qrImagePath && existingClient.qrImagePath.startsWith('/uploads/')) {
        const oldFilePath = path.join(__dirname, existingClient.qrImagePath);
        if (fs.existsSync(oldFilePath)) {
          fs.unlinkSync(oldFilePath);
        }
      }
      updateData.qrImagePath = qrImagePath;
    }
    
    // Update security code if provided
    if (securityCode) {
      updateData.securityCodeHash = hashSecurityCode(securityCode);
    }
    
    const updatedClient = await Client.findOneAndUpdate(
      { baseUrl },
      updateData,
      { new: true }
    );
    
    return res.json({ 
      success: true, 
      message: 'Client updated successfully',
      data: {
        baseUrl: updatedClient.baseUrl,
        upiId: updatedClient.upiId,
        qrImagePath: updatedClient.qrImagePath,
      }
    });
    
  } catch (error) {
    console.error('Update error:', error);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Route to get payment details for a client
app.get('/payment-details', async (req, res) => {
  try {
    const { baseUrl } = req.query;
    
    if (!baseUrl) {
      return res.status(400).json({ success: false, message: 'Base URL parameter is required' });
    }
    
    const client = await Client.findOne({ baseUrl });
    
    if (!client) {
      return res.status(404).json({ success: false, message: 'Client not found' });
    }
    
    // Return payment details without sensitive information
    return res.json({
      success: true,
      data: {
        upiId: client.upiId,
        qrImagePath: client.qrImagePath ? `${req.protocol}://${req.get('host')}${client.qrImagePath}` : null
      }
    });
    
  } catch (error) {
    console.error('Get payment details error:', error);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Middleware to handle 404
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ success: false, message: 'File is too large' });
    }
    return res.status(400).json({ success: false, message: err.message });
  }
  res.status(500).json({ success: false, message: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});