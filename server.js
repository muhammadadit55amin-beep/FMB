/* ============================================================
   LEGACYOS SERVER — backend nyata: SQLite + auth + API
   Jalankan:  node server.js       (default port 8787)
   Env:       PORT, ANTHROPIC_API_KEY (opsional, untuk pindai AI)
============================================================ */
const express=require("express");
const bcrypt=require("bcryptjs");
const crypto=require("crypto");
const path=require("path");
const fs=require("fs");

const DATA_DIR=path.join(__dirname,"data");
fs.mkdirSync(DATA_DIR,{recursive:true});
const db=require("better-sqlite3")(path.join(DATA_DIR,"legacyos.db"));
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  pass_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','editor','viewer')),
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT UNIQUE NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS state(
  id INTEGER PRIMARY KEY CHECK(id=1),
  data TEXT,
  version INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT,
  updated_by TEXT
);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  user TEXT NOT NULL,
  action TEXT NOT NULL
);
INSERT OR IGNORE INTO state(id,data,version) VALUES(1,NULL,0);
`);

const app=express();
app.use(express.json({limit:"8mb"}));
app.disable("x-powered-by");
app.use((req,res,next)=>{
  res.set("X-Content-Type-Options","nosniff");
  res.set("X-Frame-Options","DENY");
  res.set("Referrer-Policy","no-referrer");
  next();
});

/* ---------- util ---------- */
const now=()=>new Date().toISOString();
const sha=t=>crypto.createHash("sha256").update(t).digest("hex");
const audit=(user,action)=>db.prepare("INSERT INTO audit(at,user,action) VALUES(?,?,?)").run(now(),user,action);
const SESS_DAYS=14;
const isProd=process.env.NODE_ENV==="production";

function setSession(res,userId){
  const token=crypto.randomBytes(32).toString("hex");
  const exp=Date.now()+SESS_DAYS*864e5;
  db.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)").run(sha(token),userId,exp);
  res.cookie?res.cookie:null;
  res.setHeader("Set-Cookie",
    `los_sess=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESS_DAYS*86400}${isProd?"; Secure":""}`);
}
function clearSession(res){res.setHeader("Set-Cookie","los_sess=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");}
function readToken(req){
  const c=req.headers.cookie||"";
  const m=c.match(/(?:^|;\s*)los_sess=([a-f0-9]{64})/);
  return m?m[1]:null;
}
function currentUser(req){
  const t=readToken(req); if(!t)return null;
  const row=db.prepare(`SELECT u.id,u.email,u.name,u.role,s.expires_at,s.id AS sid
    FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?`).get(sha(t));
  if(!row)return null;
  if(row.expires_at<Date.now()){db.prepare("DELETE FROM sessions WHERE id=?").run(row.sid);return null;}
  return row;
}
function auth(roles){ // roles: array atau null (cukup login)
  return (req,res,next)=>{
    const u=currentUser(req);
    if(!u)return res.status(401).json({error:"Belum masuk."});
    if(roles&&!roles.includes(u.role))return res.status(403).json({error:"Peran Anda tidak diizinkan untuk aksi ini."});
    req.user=u; next();
  };
}
// Mutasi wajib membawa header kustom (mitigasi CSRF, dipadukan SameSite=Lax)
function csrf(req,res,next){
  if(["POST","PUT","PATCH","DELETE"].includes(req.method)&&req.headers["x-requested-with"]!=="fetch")
    return res.status(403).json({error:"Header X-Requested-With wajib."});
  next();
}
app.use("/api",csrf);

// rate-limit login sederhana per-IP: 10 percobaan / 10 menit
const hits=new Map();
function rateLimit(req,res,next){
  const ip=req.ip||req.socket.remoteAddress||"?";
  const rec=hits.get(ip)||{n:0,t:Date.now()};
  if(Date.now()-rec.t>600e3){rec.n=0;rec.t=Date.now();}
  if(++rec.n>10){hits.set(ip,rec);return res.status(429).json({error:"Terlalu banyak percobaan. Coba lagi beberapa menit."});}
  hits.set(ip,rec); next();
}

const userCount=()=>db.prepare("SELECT COUNT(*) c FROM users").get().c;
const pub=u=>({id:u.id,email:u.email,name:u.name,role:u.role});

/* ---------- kesehatan & mode ---------- */
app.get("/api/health",(req,res)=>res.json({ok:true,app:"legacyos-server",setup_needed:userCount()===0}));

/* ---------- setup admin pertama ---------- */
app.post("/api/setup",rateLimit,(req,res)=>{
  if(userCount()>0)return res.status(409).json({error:"Sudah ada admin. Silakan masuk."});
  const {email,pass,name,family}=req.body||{};
  if(!email||!/.+@.+/.test(email))return res.status(400).json({error:"Email tidak valid."});
  if(!pass||pass.length<8)return res.status(400).json({error:"Kata sandi minimal 8 karakter."});
  const u=db.prepare("INSERT INTO users(email,name,pass_hash,role,created_at) VALUES(?,?,?,?,?)")
    .run(email.toLowerCase().trim(),(name||email.split("@")[0]).trim(),bcrypt.hashSync(pass,11),"admin",now());
  if(family){ // benih state awal dgn profil keluarga
    const seed=JSON.stringify({core:{live:true,profile:{family:String(family).slice(0,80),lang:"id",created:now()}}});
    db.prepare("UPDATE state SET data=?,version=1,updated_at=?,updated_by=? WHERE id=1").run(seed,now(),email);
  }
  setSession(res,u.lastInsertRowid);
  audit(email,"Setup admin pertama");
  res.json({user:pub({id:u.lastInsertRowid,email,name:name||email,role:"admin"})});
});

/* ---------- login / logout / me ---------- */
app.post("/api/login",rateLimit,(req,res)=>{
  const {email,pass}=req.body||{};
  const u=db.prepare("SELECT * FROM users WHERE email=?").get(String(email||"").toLowerCase().trim());
  if(!u||!bcrypt.compareSync(String(pass||""),u.pass_hash))
    return res.status(401).json({error:"Email atau kata sandi salah."});
  setSession(res,u.id);
  audit(u.email,"Masuk");
  res.json({user:pub(u)});
});
app.post("/api/logout",auth(null),(req,res)=>{
  const t=readToken(req); if(t)db.prepare("DELETE FROM sessions WHERE token_hash=?").run(sha(t));
  clearSession(res); audit(req.user.email,"Keluar"); res.json({ok:true});
});
app.get("/api/me",auth(null),(req,res)=>res.json({user:pub(req.user)}));

/* ---------- state berversi ---------- */
app.get("/api/state",auth(null),(req,res)=>{
  const row=db.prepare("SELECT data,version,updated_at,updated_by FROM state WHERE id=1").get();
  res.json({version:row.version,updated_at:row.updated_at,updated_by:row.updated_by,
    data:row.data?JSON.parse(row.data):null});
});
app.put("/api/state",auth(["admin","editor"]),(req,res)=>{
  const {data,version}=req.body||{};
  if(typeof version!=="number"||data==null)return res.status(400).json({error:"Butuh {data, version}."});
  const row=db.prepare("SELECT data,version FROM state WHERE id=1").get();
  if(version!==row.version)
    return res.status(409).json({error:"Konflik versi — data di server lebih baru.",version:row.version,
      data:row.data?JSON.parse(row.data):null});
  const nv=row.version+1;
  db.prepare("UPDATE state SET data=?,version=?,updated_at=?,updated_by=? WHERE id=1")
    .run(JSON.stringify(data),nv,now(),req.user.email);
  audit(req.user.email,"Simpan data v"+nv);
  res.json({version:nv});
});

/* ---------- pengguna (admin) ---------- */
app.get("/api/users",auth(["admin"]),(req,res)=>{
  res.json({users:db.prepare("SELECT id,email,name,role,created_at FROM users ORDER BY id").all()});
});
app.post("/api/users",auth(["admin"]),(req,res)=>{
  const {email,pass,name,role}=req.body||{};
  if(!email||!/.+@.+/.test(email))return res.status(400).json({error:"Email tidak valid."});
  if(!pass||pass.length<8)return res.status(400).json({error:"Kata sandi minimal 8 karakter."});
  if(!["admin","editor","viewer"].includes(role))return res.status(400).json({error:"Peran tidak dikenal."});
  try{
    const u=db.prepare("INSERT INTO users(email,name,pass_hash,role,created_at) VALUES(?,?,?,?,?)")
      .run(email.toLowerCase().trim(),(name||email.split("@")[0]).trim(),bcrypt.hashSync(pass,11),role,now());
    audit(req.user.email,"Tambah pengguna "+email+" ("+role+")");
    res.json({user:{id:u.lastInsertRowid,email,name,role}});
  }catch(e){res.status(409).json({error:"Email sudah terdaftar."});}
});
app.patch("/api/users/:id",auth(["admin"]),(req,res)=>{
  const id=+req.params.id, {role,pass}=req.body||{};
  const u=db.prepare("SELECT * FROM users WHERE id=?").get(id);
  if(!u)return res.status(404).json({error:"Tidak ditemukan."});
  if(role){
    if(!["admin","editor","viewer"].includes(role))return res.status(400).json({error:"Peran tidak dikenal."});
    if(u.role==="admin"&&role!=="admin"&&db.prepare("SELECT COUNT(*) c FROM users WHERE role='admin'").get().c===1)
      return res.status(400).json({error:"Tidak bisa menurunkan admin terakhir."});
    db.prepare("UPDATE users SET role=? WHERE id=?").run(role,id);
    audit(req.user.email,"Ubah peran "+u.email+" → "+role);
  }
  if(pass){
    if(pass.length<8)return res.status(400).json({error:"Kata sandi minimal 8 karakter."});
    db.prepare("UPDATE users SET pass_hash=? WHERE id=?").run(bcrypt.hashSync(pass,11),id);
    db.prepare("DELETE FROM sessions WHERE user_id=?").run(id);
    audit(req.user.email,"Reset sandi "+u.email);
  }
  res.json({ok:true});
});
app.delete("/api/users/:id",auth(["admin"]),(req,res)=>{
  const id=+req.params.id;
  const u=db.prepare("SELECT * FROM users WHERE id=?").get(id);
  if(!u)return res.status(404).json({error:"Tidak ditemukan."});
  if(u.role==="admin"&&db.prepare("SELECT COUNT(*) c FROM users WHERE role='admin'").get().c===1)
    return res.status(400).json({error:"Tidak bisa menghapus admin terakhir."});
  db.prepare("DELETE FROM users WHERE id=?").run(id);
  audit(req.user.email,"Hapus pengguna "+u.email);
  res.json({ok:true});
});

/* ---------- audit ---------- */
app.get("/api/audit",auth(["admin","editor"]),(req,res)=>{
  res.json({rows:db.prepare("SELECT at,user,action FROM audit ORDER BY id DESC LIMIT 200").all()});
});

/* ---------- proxy pindai AI (kunci tetap di server) ---------- */
app.post("/api/scan",auth(["admin","editor"]),async(req,res)=>{
  const key=process.env.ANTHROPIC_API_KEY;
  if(!key)return res.status(503).json({error:"ANTHROPIC_API_KEY belum diatur di server — pindai memakai ekstraksi lokal."});
  try{
    const r=await fetch("https://api.anthropic.com/v1/messages",{
      method:"POST",
      headers:{"Content-Type":"application/json","x-api-key":key,"anthropic-version":"2023-06-01"},
      body:JSON.stringify(req.body&&req.body.payload?req.body.payload:{})
    });
    const j=await r.json();
    if(!r.ok)return res.status(502).json({error:(j&&j.error&&j.error.message)||"Gagal memanggil model."});
    audit(req.user.email,"Pindai dokumen (AI)");
    res.json(j);
  }catch(e){res.status(502).json({error:"Tidak dapat menghubungi API model."});}
});

/* ---------- statis ---------- */
app.use(express.static(path.join(__dirname,"public"),{index:"index.html",maxAge:0}));

const PORT=process.env.PORT||8787;
app.listen(PORT,()=>console.log(`LegacyOS server aktif di http://localhost:${PORT}  (DB: data/legacyos.db)`));
