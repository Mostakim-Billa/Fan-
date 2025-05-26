// server.js const express = require("express"); const mongoose = require("mongoose"); const cors = require("cors"); const dotenv = require("dotenv"); const authRoutes = require("./routes/authRoutes");

dotenv.config(); const app = express();

app.use(cors()); app.use(express.json()); app.use("/api/auth", authRoutes);

mongoose .connect(process.env.MONGO_URI) .then(() => { app.listen(5000, () => console.log("Server running on port 5000")); }) .catch((err) => console.error(err));

// --- models/User.js --- // const mongoose = require("mongoose"); const userSchema = new mongoose.Schema({ name: { type: String, required: true }, email: { type: String, required: true, unique: true }, password: { type: String, required: true }, isAdmin: { type: Boolean, default: false } }); module.exports = mongoose.model("User", userSchema);

// --- routes/authRoutes.js --- // const express = require("express"); const router = express.Router(); const bcrypt = require("bcryptjs"); const jwt = require("jsonwebtoken"); const User = require("../models/User");

router.post("/signup", async (req, res) => { const { name, email, password } = req.body; try { const exists = await User.findOne({ email }); if (exists) return res.status(400).json({ msg: "User already exists" }); const hashed = await bcrypt.hash(password, 10); const user = new User({ name, email, password: hashed }); await user.save(); res.status(201).json({ msg: "User registered" }); } catch (err) { res.status(500).json({ msg: "Server error" }); } });

router.post("/login", async (req, res) => { const { email, password } = req.body; try { const user = await User.findOne({ email }); if (!user) return res.status(400).json({ msg: "User not found" }); const isMatch = await bcrypt.compare(password, user.password); if (!isMatch) return res.status(400).json({ msg: "Invalid credentials" }); const token = jwt.sign({ id: user._id, isAdmin: user.isAdmin }, process.env.JWT_SECRET); res.json({ token, user: { name: user.name, email: user.email, isAdmin: user.isAdmin } }); } catch (err) { res.status(500).json({ msg: "Server error" }); } });

module.exports = router;

// --- middleware/authMiddleware.js --- // const jwt = require("jsonwebtoken"); function authMiddleware(req, res, next) { const token = req.header("Authorization"); if (!token) return res.status(401).json({ msg: "No token, access denied" }); try { const decoded = jwt.verify(token, process.env.JWT_SECRET); req.user = decoded; next(); } catch { res.status(401).json({ msg: "Invalid token" }); } } module.exports = authMiddleware;


