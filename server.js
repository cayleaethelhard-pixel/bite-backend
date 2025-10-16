import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import crypto from 'crypto'; 
import nodemailer from 'nodemailer';

// Create reusable transporter object
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

const app = express();
const prisma = new PrismaClient();

// In your backend (server.js)
const PERMISSIONS = {
  student: {
    free: ['basic_matching', 'text_chat', 'search'],
    pro: ['basic_matching', 'text_chat', 'video_calls', 'verified_badge', 'project_showcase'],
    'career-plus': ['all_features', 'career_analytics', 'global_certificate']
  },
  startup: {
    free: ['create_profile', 'browse_students'],
    'scale-faster': ['unlimited_matches', 'post_projects', 'verified_profile'],
    'pro-founder': ['all_features', 'meet_investors', 'tailored_matching']
  },
  business: {
    free: ['create_profile', 'browse_students'],
    'talent-plus': ['unlimited_matches', 'internship_pipeline', 'global_access', 'project_management', 'verified_profile', 'mentor_analytics'],
    'investor-plus': ['all_features', 'global_profiles', 'verified_students']
  },
  investor: {
    free: ['browse_profiles', 'basic_contact'],
    explorer: ['browse_all', 'direct_messaging', 'investment_analytics'],
    'pro-investor': ['all_features', 'portfolio_tracking', 'exclusive_pitches', 'video_calls']
  }
};

// Middleware
const corsOptions = {
  origin: [
    'http://localhost:3000',
    'https://bite-frontend-oxj1.onrender.com'
  ],
  credentials: true
};
app.use(cors(corsOptions));
app.use(express.json());

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware to protect routes
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

// Forgot Password Endpoint
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });
    
    if (user) {
      // Generate secure, random reset token
      const resetToken = crypto.randomBytes(32).toString('hex');
      const resetExpires = new Date(Date.now() + 3600000); // 1 hour
      
      // Save token to database
      await prisma.user.update({
        where: { id: user.id },
        data: { 
          resetToken, 
          resetExpires 
        }
      });

      // Create reset URL
      const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;
      
      // Send email
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'BITE Password Reset Request',
        html: `
          <h2>Password Reset Request</h2>
          <p>You requested to reset your password for BITE.</p>
          <p>Click the button below to reset your password:</p>
          <a href="${resetUrl}" style="background-color: #4f46e5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block; margin: 20px 0;">
            Reset Password
          </a>
          <p>This link expires in 1 hour.</p>
          <p>If you didn't request this, please ignore this email.</p>
        `
      });
    }
    
    // Always return success (security best practice)
    res.json({ 
      success: true, 
      message: 'If your email is registered, you will receive a reset link.' 
    });
    
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Failed to process request' });
  }
});

//Reset Password Endpoint
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    
    // Find user with valid reset token
    const user = await prisma.user.findFirst({
      where: {
        resetToken: token,
        resetExpires: { gt: new Date() }
      }
    });
    
    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }
    
    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    // Update password and clear reset token
    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        resetToken: null,
        resetExpires: null
      }
    });
    
    res.json({ success: true, message: 'Password reset successful' });
    
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// Authentication Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, fullName, role, location, institution, skills, goals, companyName, description, industry, fundingStage, companySize, hiringNeeds, firmName, investmentFocus, portfolioSize, preferredIndustries } = req.body;
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) return res.status(400).json({ error: 'User already exists' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const userData = {
      email, password: hashedPassword, fullName, location, role: role.toUpperCase(),
      institution, skills, goals, companyName, description, industry, fundingStage,
      companySize, hiringNeeds, firmName, investmentFocus, portfolioSize, preferredIndustries
    };
    const user = await prisma.user.create({ data: userData });

    // After successful payment
    const selectedTierId = 'tier'; // Default tier upon registration
    await prisma.user.update({
      where: { id: user.id },
      data: { tier: selectedTierId }
    });
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    const { password: _, ...userWithoutPassword } = user;
    res.status(201).json({ user: userWithoutPassword, token });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    const { password: _, ...userWithoutPassword } = user;
    res.json({ user: userWithoutPassword, token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Protected Routes
app.get('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.user.userId },
      select: { 
        id: true,
        email: true,
        fullName: true,
        role: true,
        tier: true, 
        profilePicture: true, 
      }    
    });
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { password: _, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

app.get('/api/messages', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const messages = await prisma.message.findMany({
      where: { OR: [{ senderId: userId }, { receiverId: userId }] },
      include: { sender: { select: { id: true, fullName: true, email: true } }, receiver: { select: { id: true, fullName: true, email: true } } },
      orderBy: { createdAt: 'desc' }
    });
    const conversations = {};
    messages.forEach(msg => {
      const otherUserId = msg.senderId === userId ? msg.receiverId : msg.senderId;
      if (!conversations[otherUserId]) {
        conversations[otherUserId] = { id: otherUserId, participants: [userId, otherUserId], messages: [], lastMessage: '', unreadCount: 0 };
      }
      conversations[otherUserId].messages.push({
        id: msg.id, senderId: msg.senderId, senderName: msg.sender.fullName || msg.sender.email,
        content: msg.content, timestamp: msg.createdAt, read: msg.read
      });
      if (!msg.read && msg.receiverId === userId) conversations[otherUserId].unreadCount++;
      if (!conversations[otherUserId].lastMessage || new Date(msg.createdAt) > new Date(conversations[otherUserId].lastMessage)) {
        conversations[otherUserId].lastMessage = msg.content;
      }
    });
    res.json(Object.values(conversations));
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

app.post('/api/messages', authenticateToken, async (req, res) => {
  try {
    const { receiverId, content } = req.body;
    const senderId = req.user.userId;
    const message = await prisma.message.create({
      data: { senderId, receiverId: parseInt(receiverId), content },
      include: { sender: { select: { id: true, fullName: true, email: true } } }
    });
    const messageResponse = {
      id: message.id, senderId: message.senderId, senderName: message.sender.fullName || message.sender.email,
      content: message.content, timestamp: message.createdAt, read: message.read
    };
    res.status(201).json(messageResponse);
  } catch (error) {
    console.error('Send message error:', error);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

app.get('/api/search', authenticateToken, async (req, res) => {
  try {
    const { q: searchTerm } = req.query;
    const currentUserId = req.user.userId;
    if (!searchTerm) return res.json([]);
    const users = await prisma.user.findMany({
      where: {
        id: { not: currentUserId },
        OR: [
          { fullName: { contains: searchTerm, mode: 'insensitive' } },
          { email: { contains: searchTerm, mode: 'insensitive' } },
          { companyName: { contains: searchTerm, mode: 'insensitive' } },
          { institution: { contains: searchTerm, mode: 'insensitive' } }
        ]
      },
      select: { id: true, fullName: true, email: true, role: true, location: true, companyName: true, institution: true, profilePicture: true }
    });
    res.json(users);
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ error: 'Search failed' });
  }
});

// Dashboard Endpoints
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    const totalMatches = await prisma.match.count({ where: { userId: userId } });

    const activeConversations = await prisma.message.count({ where: { senderId: userId }, distinct: ['receiverId'] });

    const profileViews = 0;
    const compatibilityScore = totalMatches > 0 ? Math.min(85 + totalMatches * 5, 95) : 50;
    
    res.json({ totalMatches, activeConversations, profileViews, compatibilityScore: `${compatibilityScore}%` });
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ error: 'Failed to fetch dashboard stats' });
  }
});

app.get('/api/dashboard/activity', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const limit = 4;
    const recentMatches = await prisma.match.findMany({
      where: { userId: userId },
      include: { matchedUser: { select: { fullName: true, companyName: true, institution: true } } },
      orderBy: { createdAt: 'desc' },
      take: limit
    });
    const recentMessages = await prisma.message.findMany({
      where: { senderId: userId },
      include: { receiver: { select: { fullName: true, companyName: true, institution: true } } },
      orderBy: { createdAt: 'desc' },
      take: limit
    });
    const activities = [
      ...recentMatches.map(match => ({
        id: `match-${match.id}`, type: 'match',
        user: match.matchedUser.fullName || match.matchedUser.companyName || match.matchedUser.institution || 'Unknown User',
        time: formatTimeAgo(match.createdAt), icon: 'UsersIcon'
      })),
      ...recentMessages.map(msg => ({
        id: `msg-${msg.id}`, type: 'message',
        user: msg.receiver.fullName || msg.receiver.companyName || msg.receiver.institution || 'Unknown User',
        time: formatTimeAgo(msg.createdAt), icon: 'MessageIcon'
      }))
    ].sort((a, b) => new Date(b.time) - new Date(a.time)).slice(0, limit);
    res.json(activities);
  } catch (error) {
    console.error('Dashboard activity error:', error);
    res.status(500).json({ error: 'Failed to fetch recent activity' });
  }
});

function formatTimeAgo(date) {
  const now = new Date();
  const diff = now - new Date(date);
  const hours = Math.floor(diff / (1000 * 60 * 60));
  const days = Math.floor(diff / (1000 * 60 * 60 * 24));
  if (hours < 1) return 'Just now';
  if (hours < 24) return `${hours} hour${hours !== 1 ? 's' : ''} ago`;
  if (days < 7) return `${days} day${days !== 1 ? 's' : ''} ago`;
  return new Date(date).toLocaleDateString();
}

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Handle graceful shutdown
process.on('SIGTERM', async () => {
  await prisma.$disconnect();
  process.exit(0);
});


// Backend middleware function
const canAccessFeature = (user, feature) => {
  const userPermissions = PERMISSIONS[user.role]?.[user.tier] || [];
  
  // If user has 'all_features' permission
  if (userPermissions.includes('all_features')) {
    return true;
  }
  
  // Check if specific feature is allowed
  return userPermissions.includes(feature);
};

// Usage in protected routes
app.get('/api/premium-feature', authenticateToken, async (req, res) => {
  if (!canAccessFeature(req.user, 'premium_feature')) {
    return res.status(403).json({ error: 'Insufficient permissions' });
  }
  // Proceed with premium feature logic
});

// Handle successful payment and update user tier
app.post('/api/payments/success', authenticateToken, async (req, res) => {
  try {
    const { tier } = req.body;
    const userId = req.user.userId;

    // Validate tier exists for the user's role
    const validTiers = {
      student: ['free', 'pro', 'career-plus'],
      startup: ['free', 'scale-faster', 'pro-founder'],
      business: ['free', 'talent-plus', 'investor-plus'],
      investor: ['free', 'explorer', 'pro-investor']
    };

    const user = await prisma.user.findUnique({ where: { userId: userId } });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!validTiers[user.role].includes(tier)) {
      return res.status(400).json({ error: 'Invalid tier for your role' });
    }

    // Update user's tier
    await prisma.user.update({
      where: { userId: userId },
      data: { tier }
    });

    res.json({ success: true, message: 'Payment processed successfully' });

  } catch (error) {
    console.error('Payment success error:', error);
    res.status(500).json({ error: 'Failed to process payment' });
  }
});