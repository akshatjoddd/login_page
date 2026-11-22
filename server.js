// ===== 1. IMPORTS =====
import express from "express";                    // web server
import bcrypt from "bcrypt";                      // password hashing
import { inspectPassword } from "password-inspector"; // password strength checker
import fs from "fs";                              // read/write files
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ===== 2. SETTINGS =====
const PORT = process.env.PORT || 3000;
const USERS_FILE = "data/users.json"; // where users are saved
const MIN_SCORE = 40;                 // minimum password score to register
const SALT_ROUNDS = 12;               // how slow/strong the bcrypt hash is

// ===== 3. SET UP THE SERVER =====
const app = express();
app.use(express.json());        // lets us read JSON sent from the page

if (fs.existsSync(path.join(__dirname, "public"))) {
  app.use(express.static(path.join(__dirname, "public")));
}

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// ===== 4. HELPER FUNCTIONS =====

// Read all users from the file (returns an empty list if the file doesn't exist yet)
function getUsers() {
  if (!fs.existsSync(USERS_FILE)) {
    return [];
  }
  const text = fs.readFileSync(USERS_FILE, "utf8");
  return JSON.parse(text);
}

// Save the list of users to the file
function saveUsers(users) {
  fs.mkdirSync("data", { recursive: true }); // make the data folder if missing
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// ===== 5. ROUTES =====

// Check a password's strength (the page calls this while you type)
app.post("/api/check-password", (req, res) => {
  const password = req.body.password;

  if (typeof password !== "string") {
    return res.status(400).json({ error: "Password must be text." });
  }

  const result = inspectPassword(password);

  res.json({
    score: result.score,
    strength: result.strength,
    suggestions: result.suggestions,
    minScore: MIN_SCORE,
  });
});

// Create a new account
app.post("/api/register", async (req, res) => {
  const username = req.body.username;
  const email = req.body.email;
  const password = req.body.password;

  // Check that everything was filled in
  if (!username || !email || !password) {
    return res.status(400).json({ error: "Please fill in all fields." });
  }

  // Check the username: 3-20 letters, numbers or underscores
  const usernameOk = /^[a-zA-Z0-9_]{3,20}$/.test(username);
  if (!usernameOk) {
    return res.status(400).json({ error: "Username must be 3-20 letters, numbers or underscores." });
  }

  // Check the email looks like name@site.com
  const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if (!emailOk) {
    return res.status(400).json({ error: "Enter a valid email address." });
  }

  // bcrypt only uses the first 72 characters, so don't allow more
  if (password.length > 72) {
    return res.status(400).json({ error: "Password must be 72 characters or fewer." });
  }

  // Check the password is strong enough
  const strength = inspectPassword(password);
  if (strength.score < MIN_SCORE) {
    return res.status(400).json({
      error: "Password is too weak (" + strength.strength + ").",
      suggestions: strength.suggestions,
    });
  }

  // Make sure the username and email aren't already used
  const users = getUsers();
  const cleanEmail = email.toLowerCase();

  for (const user of users) {
    if (user.username.toLowerCase() === username.toLowerCase()) {
      return res.status(409).json({ error: "That username is taken." });
    }
    if (user.email === cleanEmail) {
      return res.status(409).json({ error: "That email is already registered." });
    }
  }

  // Hash the password (never save the real password!)
  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

  // Save the new user
  users.push({
    username: username,
    email: cleanEmail,
    passwordHash: passwordHash,
  });
  saveUsers(users);

  res.status(201).json({ message: "Account created. You can sign in now." });
});

// Sign in
app.post("/api/login", async (req, res) => {
  const identifier = req.body.identifier; // username OR email
  const password = req.body.password;

  if (!identifier || !password) {
    return res.status(400).json({ error: "Enter your username or email and password." });
  }

  // Find the user by username or email
  const search = identifier.trim().toLowerCase();
  const users = getUsers();
  let foundUser = null;

  for (const user of users) {
    if (user.username.toLowerCase() === search || user.email === search) {
      foundUser = user;
    }
  }

  if (!foundUser) {
    return res.status(401).json({ error: "Incorrect username/email or password." });
  }

  // Compare the typed password with the saved hash
  const passwordMatches = await bcrypt.compare(password, foundUser.passwordHash);
  if (!passwordMatches) {
    return res.status(401).json({ error: "Incorrect username/email or password." });
  }

  res.json({ message: "Signed in.", username: foundUser.username });
});

// ===== 6. START THE SERVER =====
app.listen(PORT, () => {
  console.log("Running at http://localhost:" + PORT);
});
