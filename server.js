require("dotenv").config();
const express=require("express"),http=require("http");
const {Server}=require("socket.io"),cors=require("cors"),bcrypt=require("bcryptjs");
const session=require("express-session"),low=require("lowdb");
const FileSync=require("lowdb/adapters/FileSync"),multer=require("multer");
const path=require("path"),fs=require("fs"),crypto=require("crypto");

const db=low(new FileSync("yanz.json"));
db.defaults({users:[],messages:[],contacts:[],statuses:[]}).write();
db.get("users").value().forEach(u=>{if(typeof u.profilePhoto!=="string")u.profilePhoto="";});
db.get("messages").value().forEach(m=>{
 if(!m.id)m.id=crypto.randomUUID();
 if(!Array.isArray(m.deletedFor))m.deletedFor=[];
 if(!Array.isArray(m.unreadFor))m.unreadFor=m.to?[m.to]:[];
 if(!m.type)m.type="text";
});
db.write();

const app=express(),server=http.createServer(app);
const io=new Server(server,{cors:{origin:true,credentials:true}});
const sessionMiddleware=session({
 secret:process.env.SESSION_SECRET||"yanz-message-local-session-secret-change-this",
 resave:false,saveUninitialized:false,
 cookie:{httpOnly:true,sameSite:"lax",maxAge:7*24*60*60*1000}
});
app.use(cors({origin:true,credentials:true}));
app.use(express.json({limit:"1mb"}));
app.use(sessionMiddleware);
app.use(express.static(path.join(__dirname,"public")));
io.engine.use(sessionMiddleware);

function requireLogin(req,res,next){
 if(!req.session.user)return res.status(401).json({message:"Silakan login terlebih dahulu!"});
 next();
}
function safeImageUrl(value){
 const url=String(value||"");
 return /^\/uploads\/[a-zA-Z0-9._-]+$/.test(url)?url:"";
}
function unreadCounts(username){
 const counts={};
 db.get("messages").value().forEach(m=>{
  if(m.to===username&&Array.isArray(m.unreadFor)&&m.unreadFor.includes(username)&&!(m.deletedFor||[]).includes(username))
   counts[m.from]=(counts[m.from]||0)+1;
 });
 return counts;
}
function emitUnread(username){io.to(username).emit("unread-counts",unreadCounts(username));}
function saveMessage({from,to,message="",imageUrl="",type="text",statusId=""}){
 const saved={id:crypto.randomUUID(),from,to,message,imageUrl,type,statusId,
  time:new Date().toLocaleTimeString("id-ID",{hour:"2-digit",minute:"2-digit"}),
  createdAt:Date.now(),deletedFor:[],unreadFor:[to]};
 db.get("messages").push(saved).write();
 io.to(from).to(to).emit("private-message",saved);emitUnread(to);
 return saved;
}

const uploadDir=path.join(__dirname,"public","uploads");
fs.mkdirSync(uploadDir,{recursive:true});
const storage=multer.diskStorage({
 destination:(_req,_file,cb)=>cb(null,uploadDir),
 filename:(_req,file,cb)=>{
  const ext={"image/jpeg":".jpg","image/png":".png","image/webp":".webp","image/gif":".gif"}[file.mimetype];
  cb(null,`${Date.now()}-${crypto.randomBytes(8).toString("hex")}${ext}`);
 }
});
const photoUpload=multer({
 storage,limits:{fileSize:5*1024*1024,files:1},
 fileFilter:(_req,file,cb)=>{
  if(!["image/jpeg","image/png","image/webp","image/gif"].includes(file.mimetype))
   return cb(new Error("Format foto harus JPG, PNG, WebP, atau GIF."));
  cb(null,true);
 }
});

app.get("/users",requireLogin,(req,res)=>{
 const me=req.session.user.username,counts=unreadCounts(me);
 res.json(db.get("users").filter(u=>u.username!==me)
  .map(u=>({username:u.username,profilePhoto:u.profilePhoto||"",unreadCount:counts[u.username]||0})).value());
});
app.get("/contacts",requireLogin,(req,res)=>{
 res.json(db.get("contacts").filter({owner:req.session.user.username}).value());
});
app.post("/contacts",requireLogin,(req,res)=>{
 const owner=req.session.user.username,username=String(req.body.username||"").trim(),name=String(req.body.name||"").trim();
 if(!username||username===owner)return res.status(400).json({message:"Username kontak tidak valid."});
 if(!db.get("users").find({username}).value())return res.status(404).json({message:"Pengguna tidak ditemukan."});
 if(!name||name.length>30)return res.status(400).json({message:"Nama kontak wajib diisi (maksimal 30 karakter)."});
 const old=db.get("contacts").find({owner,username}).value();
 if(old)db.get("contacts").find({owner,username}).assign({name}).write();
 else db.get("contacts").push({owner,username,name}).write();
 res.json({message:"Kontak berhasil disimpan!",contact:{owner,username,name}});
});
app.delete("/contacts/:username",requireLogin,(req,res)=>{
 db.get("contacts").remove({owner:req.session.user.username,username:req.params.username}).write();
 res.json({message:"Kontak dihapus."});
});

app.post("/register",(req,res)=>{
 const username=String(req.body.username||"").trim(),password=String(req.body.password||"");
 if(!username||!password)return res.status(400).json({message:"Isi semua kolom!"});
 if(!/^[a-zA-Z0-9_]{3,20}$/.test(username))return res.status(400).json({message:"Username harus 3-20 karakter."});
 if(password.length<6)return res.status(400).json({message:"Password minimal 6 karakter."});
 if(db.get("users").find({username}).value())return res.status(409).json({message:"Username sudah digunakan!"});
 db.get("users").push({id:Date.now().toString(),username,password:bcrypt.hashSync(password,10),profilePhoto:""}).write();
 req.session.user={username};res.json({message:"Akun berhasil dibuat!",username});
});
app.post("/login",(req,res)=>{
 const username=String(req.body.username||"").trim(),password=String(req.body.password||"");
 const user=db.get("users").find({username}).value();
 if(!user||!bcrypt.compareSync(password,user.password))return res.status(401).json({message:"Username atau password salah!"});
 req.session.user={username:user.username};res.json({message:"Login berhasil!",username:user.username});
});
app.get("/me",(req,res)=>{
 if(!req.session.user)return res.json({user:null});
 const u=db.get("users").find({username:req.session.user.username}).value();
 res.json({user:u?{username:u.username,profilePhoto:u.profilePhoto||""}:null});
});
app.get("/messages/:username",requireLogin,(req,res)=>{
 const me=req.session.user.username,other=req.params.username;
 const messages=db.get("messages").filter(m=>(m.from===me&&m.to===other)||(m.from===other&&m.to===me)).value();
 let changed=false;
 messages.forEach(m=>{
  if(m.to===me&&Array.isArray(m.unreadFor)&&m.unreadFor.includes(me)){
   m.unreadFor=m.unreadFor.filter(n=>n!==me);changed=true;
  }
 });
 if(changed){db.write();emitUnread(me);}
 res.json(messages.filter(m=>!(m.deletedFor||[]).includes(me)));
});
app.post("/upload",requireLogin,(req,res)=>{
 photoUpload.single("photo")(req,res,error=>{
  if(error)return res.status(400).json({message:error.code==="LIMIT_FILE_SIZE"?"Ukuran foto maksimal 5 MB.":error.message});
  if(!req.file)return res.status(400).json({message:"Pilih foto terlebih dahulu."});
  res.json({imageUrl:`/uploads/${req.file.filename}`});
 });
});
app.post("/profile/photo",requireLogin,(req,res)=>{
 const username=req.session.user.username,imageUrl=safeImageUrl(req.body.imageUrl);
 if(!imageUrl)return res.status(400).json({message:"Foto profil tidak valid."});
 const user=db.get("users").find({username}).value();
 if(!user)return res.status(404).json({message:"Akun tidak ditemukan."});
 user.profilePhoto=imageUrl;db.write();
 io.emit("profile-updated",{username,profilePhoto:imageUrl});
 res.json({message:"Foto profil berhasil diperbarui.",profilePhoto:imageUrl});
});

// Status teks/foto berlaku 24 jam.
app.get("/statuses",requireLogin,(req,res)=>{
 const now=Date.now(),me=req.session.user.username;
 res.json(db.get("statuses").value().filter(s=>s.expiresAt>now)
  .sort((a,b)=>b.createdAt-a.createdAt).map(s=>({
   id:s.id,username:s.username,text:s.text,imageUrl:s.imageUrl,createdAt:s.createdAt,
   expiresAt:s.expiresAt,viewerCount:(s.views||[]).length,
   viewedByMe:(s.views||[]).some(v=>v.username===me)
  })));
});
app.post("/statuses",requireLogin,(req,res)=>{
 const username=req.session.user.username,text=String(req.body.text||"").trim(),imageUrl=safeImageUrl(req.body.imageUrl);
 if(text.length>500)return res.status(400).json({message:"Status maksimal 500 karakter."});
 if(!text&&!imageUrl)return res.status(400).json({message:"Isi teks atau pilih foto status."});
 const status={id:crypto.randomUUID(),username,text,imageUrl,createdAt:Date.now(),expiresAt:Date.now()+86400000,views:[]};
 db.get("statuses").push(status).write();
 res.json({message:"Status berhasil dibagikan!",status:{id:status.id,username,text,imageUrl,createdAt:status.createdAt,expiresAt:status.expiresAt,viewerCount:0,viewedByMe:false}});
});
app.post("/statuses/:id/view",requireLogin,(req,res)=>{
 const username=req.session.user.username,s=db.get("statuses").find({id:req.params.id}).value();
 if(!s||s.expiresAt<=Date.now())return res.status(404).json({message:"Status sudah tidak tersedia."});
 if(!Array.isArray(s.views))s.views=[];
 if(s.username!==username&&!s.views.some(v=>v.username===username)){s.views.push({username,viewedAt:Date.now()});db.write();}
 res.json({message:"Tampilan status tercatat.",viewerCount:s.views.length});
});
app.get("/statuses/:id/views",requireLogin,(req,res)=>{
 const s=db.get("statuses").find({id:req.params.id}).value();
 if(!s)return res.status(404).json({message:"Status tidak ditemukan."});
 if(s.username!==req.session.user.username)return res.status(403).json({message:"Daftar penonton hanya bisa dilihat pemilik status."});
 res.json((s.views||[]).map(v=>{
  const u=db.get("users").find({username:v.username}).value();
  return {username:v.username,profilePhoto:u?u.profilePhoto||"":"",viewedAt:v.viewedAt};
 }));
});
app.post("/statuses/:id/reply",requireLogin,(req,res)=>{
 const from=req.session.user.username,s=db.get("statuses").find({id:req.params.id}).value(),message=String(req.body.message||"").trim();
 if(!s||s.expiresAt<=Date.now())return res.status(404).json({message:"Status sudah tidak tersedia."});
 if(s.username===from)return res.status(400).json({message:"Kamu tidak bisa membalas status sendiri."});
 if(!message||message.length>1000)return res.status(400).json({message:"Balasan harus 1-1000 karakter."});
 const saved=saveMessage({from,to:s.username,message,type:"status-reply",statusId:s.id});
 res.json({message:"Balasan status terkirim!",saved});
});
app.post("/logout",(req,res)=>req.session.destroy(()=>res.json({message:"Berhasil logout!"})));
app.get("/status",(_req,res)=>res.send("YANZ MESSAGE SERVER AKTIF!"));

io.use((socket,next)=>{
 const user=socket.request.session&&socket.request.session.user;
 if(!user)return next(new Error("Silakan login!"));
 socket.username=user.username;next();
});
const onlineUsers=new Map();
io.on("connection",socket=>{
 const username=socket.username;
 onlineUsers.set(username,socket.id);socket.join(username);
 io.emit("online-users",Array.from(onlineUsers.keys()));
 socket.emit("unread-counts",unreadCounts(username));
 socket.on("private-message",data=>{
  const to=String(data&&data.to||"").trim(),message=String(data&&data.message||"").trim();
  const imageUrl=safeImageUrl(data&&data.imageUrl);
  if(!to||to===username||!db.get("users").find({username:to}).value())return;
  const hasText=message.length>0&&message.length<=2000,hasImage=!!imageUrl;
  if(!hasText&&!hasImage)return;
  saveMessage({from:username,to,message:hasText?message:"",imageUrl:hasImage?imageUrl:"",type:hasImage?(hasText?"mixed":"image"):"text"});
 });
 socket.on("delete-message",data=>{
  const id=String(data&&data.id||""),mode=String(data&&data.mode||""),m=db.get("messages").find({id}).value();
  if(!m||(m.from!==username&&m.to!==username))return;
  if(mode==="everyone"){
   if(m.from!==username)return;
   m.deletedForEveryone=true;m.type="deleted";m.message="";m.imageUrl="";m.unreadFor=[];
  }else if(mode==="me"){
   if(!Array.isArray(m.deletedFor))m.deletedFor=[];
   if(!m.deletedFor.includes(username))m.deletedFor.push(username);
   if(Array.isArray(m.unreadFor))m.unreadFor=m.unreadFor.filter(n=>n!==username);
  }else return;
  db.write();
  if(mode==="me")io.to(username).emit("message-updated",{...m});
  else{io.to(m.from).to(m.to).emit("message-updated",{...m});emitUnread(m.to);}
 });
 socket.on("disconnect",()=>{
  if(onlineUsers.get(username)===socket.id)onlineUsers.delete(username);
  io.emit("online-users",Array.from(onlineUsers.keys()));
  console.log("User keluar:",username);
 });
 console.log("User online:",username);
});
const PORT=process.env.PORT||3000;
server.listen(PORT,"0.0.0.0",()=>console.log("YANZ MESSAGE berjalan di port "+PORT));
