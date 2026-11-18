
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const low = require("lowdb");
const FileSync = require("lowdb/adapters/FileSync");

const adapter = new FileSync("yanz.json");
const db = low(adapter);
db.defaults({ users: [], messages: [] }).write();

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const sessionMiddleware = session({
    secret: "yanz-message-secret-ganti-nanti",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        maxAge: 7 * 24 * 60 * 60 * 1000
    }
});

app.use(cors({
    origin: true,
    credentials: true
}));
app.use(express.json());
app.use(express.static("public"));
app.use(sessionMiddleware);

app.post("/register", (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: "Isi semua kolom!" });
    }

    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
        return res.status(400).json({ message: "Username harus 3-20 karakter." });
    }

    if (password.length < 6) {
        return res.status(400).json({ message: "Password minimal 6 karakter." });
    }

    const existing = db.get("users").find({ username }).value();

    if (existing) {
        return res.status(409).json({ message: "Username sudah digunakan!" });
    }

    const hash = bcrypt.hashSync(password, 10);

    db.get("users").push({
        id: Date.now().toString(),
        username,
        password: hash
    }).write();

    req.session.user = { username };

    res.json({ message: "Akun berhasil dibuat!", username });
});

app.post("/login", (req, res) => {
    const { username, password } = req.body;
    const user = db.get("users").find({ username }).value();

    if (!user || !bcrypt.compareSync(password || "", user.password)) {
        return res.status(401).json({ message: "Username atau password salah!" });
    }

    req.session.user = { username: user.username };
    res.json({ message: "Login berhasil!", username: user.username });
});

app.get("/me", (req, res) => {
    res.json({ user: req.session.user || null });
});

app.get("/users", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ message: "Silakan login!" });
    }

    const users = db.get("users")
        .filter(user => user.username !== req.session.user.username)
        .map(user => ({ username: user.username }))
        .value();

    res.json(users);
});

app.get("/messages/:username", (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ message: "Silakan login!" });
    }

    const me = req.session.user.username;
    const other = req.params.username;

    const messages = db.get("messages")
        .filter(message =>
            (message.from === me && message.to === other) ||
            (message.from === other && message.to === me)
        )
        .value();

    res.json(messages);
});

app.post("/logout", (req, res) => {
    req.session.destroy(() => {
        res.json({ message: "Berhasil logout!" });
    });
});

io.engine.use(sessionMiddleware);

io.use((socket, next) => {
    const user = socket.request.session.user;
    if (!user) return next(new Error("Silakan login!"));
    socket.username = user.username;
    next();
});

const onlineUsers = new Map();
io.on("connection", socket => {
    console.log("User online:", socket.username);
onlineUsers.set(socket.username, socket.id);
io.emit("online-users", Array.from(onlineUsers.keys()));

    socket.join(socket.username);

    socket.on("private-message", data => {
        const to = String(data.to || "");
        const message = String(data.message || "").trim();

        if (!to || !message || message.length > 2000) return;

        const recipient = db.get("users").find({ username: to }).value();
        if (!recipient || to === socket.username) return;

        const saved = {
            from: socket.username,
            to,
            message,
            time: new Date().toLocaleTimeString()
        };

        db.get("messages").push(saved).write();

        io.to(socket.username).to(to).emit("private-message", saved);
    });

    socket.on("disconnect", () => {
onlineUsers.delete(socket.username);
io.emit("online-users", Array.from(onlineUsers.keys()));
        console.log("User keluar:", socket.username);
    });
});

app.get("/status", (req, res) => {
    res.send("YANZ MESSAGE SERVER AKTIF!");
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, "0.0.0.0", () => {
    console.log("YANZ MESSAGE berjalan di port " + PORT);
});
