const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
dotenv.config();

const app = express();
app.use(express.json()); // Parse JSON requests

// Temporary in-memory database (in a real app, use a database)
const users = [];

// Middleware to protect routes
const auth = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) return res.status(403).json({ message: "Token is required" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
};

// Public Route: Register new user
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  // Check if user already exists
  const userExists = users.find((user) => user.email === email);
  if (userExists)
    return res.status(400).json({ message: "User already exists" });

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Save user to "database"
  users.push({ id: users.length + 1, name, email, password: hashedPassword });

  res.status(201).json({ message: "User registered successfully" });
});

// Public Route: Login user
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  // Find user by email
  const user = users.find((user) => user.email === email);
  if (!user) return res.status(400).json({ message: "User not found" });

  // Check password
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword)
    return res.status(400).json({ message: "Invalid password" });

  // Create a JWT token
  const token = jwt.sign(
    { id: user.id, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: "3h" }
  );

  res.json({ message: "Login successful", token });
});

// Protected Route: Get user profile
app.get("/profile", auth, (req, res) => {
  res.json({ message: `Welcome ${req.user.name}`, user: req.user });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
