const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const helmet = require('helmet');

const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.join(__dirname, 'data');
const BACKUP_DIR = path.join(__dirname, 'backups');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(BACKUP_DIR, { recursive: true });

const dbPath = path.join(DATA_DIR, 'two-hearts.db');
const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'admin',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS menu_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  category_id INTEGER NOT NULL,
  price INTEGER NOT NULL,
  icon TEXT DEFAULT '🍽️',
  available INTEGER NOT NULL DEFAULT 1,
  stock INTEGER NOT NULL DEFAULT 0,
  low_stock_threshold INTEGER NOT NULL DEFAULT 5,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(category_id) REFERENCES categories(id)
);
CREATE TABLE IF NOT EXISTS cafe_tables (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  table_no INTEGER UNIQUE NOT NULL,
  status TEXT NOT NULL DEFAULT 'available'
);
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  bill_no TEXT UNIQUE NOT NULL,
  order_type TEXT NOT NULL,
  table_no INTEGER,
  customer_name TEXT NOT NULL DEFAULT 'Walk-in Customer',
  subtotal INTEGER NOT NULL,
  discount INTEGER NOT NULL DEFAULT 0,
  gst_rate REAL NOT NULL DEFAULT 5,
  gst INTEGER NOT NULL DEFAULT 0,
  total INTEGER NOT NULL,
  payment_method TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'paid',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL,
  menu_item_id INTEGER,
  item_name TEXT NOT NULL,
  quantity INTEGER NOT NULL,
  unit_price INTEGER NOT NULL,
  line_total INTEGER NOT NULL,
  FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE,
  FOREIGN KEY(menu_item_id) REFERENCES menu_items(id) ON DELETE SET NULL
);
`);

function setting(key, fallback='') {
  const row = db.prepare('SELECT value FROM settings WHERE key=?').get(key);
  return row ? row.value : fallback;
}
function setSetting(key, value) {
  db.prepare(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`).run(key, String(value));
}
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return { salt, hash: crypto.scryptSync(password, salt, 64).toString('hex') };
}
function verifyPassword(password, hash, salt) {
  const derived = crypto.scryptSync(password, salt, 64);
  const stored = Buffer.from(hash, 'hex');
  return derived.length === stored.length && crypto.timingSafeEqual(derived, stored);
}
function clean(v, fallback='') { return String(v ?? fallback).trim().replace(/[<>]/g, ''); }
function money(v) { const n=Number(v); if(!Number.isFinite(n)||n<0) throw new Error('Invalid amount'); return Math.round(n); }
function parseCookies(req, _res, next) {
  req.cookies={};
  for (const part of (req.headers.cookie||'').split(';')) {
    const i=part.indexOf('='); if(i<0) continue;
    req.cookies[part.slice(0,i).trim()]=decodeURIComponent(part.slice(i+1));
  }
  next();
}
function createSession(userId) {
  const token=crypto.randomBytes(32).toString('hex');
  const expires=Date.now()+8*60*60*1000;
  db.prepare('INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)').run(token,userId,expires);
  return {token,expires};
}
function auth(req,res,next) {
  const token=req.get('x-session-token')||req.cookies.session;
  if(!token) return res.status(401).json({error:'Unauthorized'});
  const row=db.prepare(`SELECT s.token,s.user_id,s.expires_at,u.username,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?`).get(token);
  if(!row || row.expires_at<Date.now()) { if(row) db.prepare('DELETE FROM sessions WHERE token=?').run(token); return res.status(401).json({error:'Session expired'}); }
  req.user=row; next();
}
function initData(){
  if(!setting('shop_name')) setSetting('shop_name','Two Hearts Cafe');
  if(!setting('shop_tagline')) setSetting('shop_tagline','Good Food • Good Mood');
  if(!setting('shop_address')) setSetting('shop_address','');
  if(!setting('gst_rate')) setSetting('gst_rate','5');
  if(db.prepare('SELECT COUNT(*) c FROM users').get().c===0){
    const {hash,salt}=hashPassword('admin123');
    db.prepare('INSERT INTO users(username,password_hash,salt,role) VALUES(?,?,?,?)').run('admin',hash,salt,'admin');
  }
  if(db.prepare('SELECT COUNT(*) c FROM categories').get().c===0){
    const cats=['Coffee','Burgers','Pizza','Drinks','Snacks','Desserts'];
    const ins=db.prepare('INSERT INTO categories(name) VALUES(?)');
    db.transaction(()=>cats.forEach(x=>ins.run(x)))();
    const ids=Object.fromEntries(db.prepare('SELECT id,name FROM categories').all().map(x=>[x.name,x.id]));
    const items=[['Cappuccino','Coffee',150,'☕'],['Cold Coffee','Drinks',180,'🥤'],['Veg Burger','Burgers',220,'🍔'],['Margherita Pizza','Pizza',300,'🍕'],['French Fries','Snacks',120,'🍟'],['Chocolate Brownie','Desserts',160,'🍰']];
    const insItem=db.prepare('INSERT INTO menu_items(name,category_id,price,icon,stock,low_stock_threshold) VALUES(?,?,?,?,50,5)');
    db.transaction(()=>items.forEach(([n,c,p,i])=>insItem.run(n,ids[c],p,i)))();
  }
  if(db.prepare('SELECT COUNT(*) c FROM cafe_tables').get().c===0){ const ins=db.prepare(`INSERT INTO cafe_tables(table_no,status) VALUES(?, 'available')`); db.transaction(()=>{for(let i=1;i<=12;i++)ins.run(i)})(); }
}
initData();

const app=express();
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:'1mb'}));
app.use(parseCookies);
app.use(express.static(path.join(__dirname,'public')));

app.get('/api/health',(_req,res)=>res.json({ok:true}));
app.post('/api/login',(req,res)=>{
  const u=clean(req.body.username), p=String(req.body.password||'');
  const user=db.prepare('SELECT * FROM users WHERE username=?').get(u);
  if(!user||!verifyPassword(p,user.password_hash,user.salt)) return res.status(401).json({error:'Invalid username or password'});
  const s=createSession(user.id);
  res.cookie('session',s.token,{httpOnly:true,sameSite:'strict',secure:process.env.NODE_ENV==='production',maxAge:8*60*60*1000});
  res.json({user:{id:user.id,username:user.username,role:user.role},expires:s.expires});
});
app.post('/api/logout',auth,(req,res)=>{db.prepare('DELETE FROM sessions WHERE token=?').run(req.user.token);res.clearCookie('session');res.json({ok:true})});
app.get('/api/me',auth,(req,res)=>res.json({user:{id:req.user.user_id,username:req.user.username,role:req.user.role}}));
app.put('/api/me/password',auth,(req,res)=>{const oldPassword=String(req.body.oldPassword||''),newPassword=String(req.body.newPassword||'');if(newPassword.length<8)return res.status(400).json({error:'New password must be at least 8 characters'});const user=db.prepare('SELECT * FROM users WHERE id=?').get(req.user.user_id);if(!verifyPassword(oldPassword,user.password_hash,user.salt))return res.status(400).json({error:'Current password is incorrect'});const {hash,salt}=hashPassword(newPassword);db.prepare('UPDATE users SET password_hash=?,salt=? WHERE id=?').run(hash,salt,user.id);db.prepare('DELETE FROM sessions WHERE user_id=? AND token<>?').run(user.id,req.user.token);res.json({ok:true})});

app.get('/api/settings',auth,(_req,res)=>res.json({shopName:setting('shop_name'),tagline:setting('shop_tagline'),address:setting('shop_address'),gstRate:Number(setting('gst_rate','5'))}));
app.put('/api/settings',auth,(req,res)=>{const rate=Number(req.body.gstRate);if(!Number.isFinite(rate)||rate<0||rate>100)return res.status(400).json({error:'Invalid GST rate'});setSetting('shop_name',clean(req.body.shopName,'Two Hearts Cafe'));setSetting('shop_tagline',clean(req.body.tagline,'Good Food • Good Mood'));setSetting('shop_address',clean(req.body.address));setSetting('gst_rate',rate);res.json({ok:true})});

app.get('/api/categories',auth,(_req,res)=>res.json(db.prepare('SELECT id,name,active FROM categories WHERE active=1 ORDER BY name').all()));
app.post('/api/categories',auth,(req,res)=>{try{const name=clean(req.body.name);if(!name)throw new Error('Category name required');const x=db.prepare('INSERT INTO categories(name) VALUES(?)').run(name);res.json({id:x.lastInsertRowid,name,active:1})}catch{res.status(400).json({error:'Category already exists or invalid'})}});

app.get('/api/menu',auth,(_req,res)=>res.json(db.prepare(`SELECT m.id,m.name,m.price,m.icon,m.available,m.stock,m.low_stock_threshold,c.id category_id,c.name category FROM menu_items m JOIN categories c ON c.id=m.category_id ORDER BY c.name,m.name`).all()));
app.post('/api/menu',auth,(req,res)=>{try{const name=clean(req.body.name),categoryId=Number(req.body.categoryId),price=money(req.body.price),icon=clean(req.body.icon,'🍽️'),stock=Math.max(0,Math.floor(Number(req.body.stock||0))),low=Math.max(0,Math.floor(Number(req.body.lowStockThreshold||5)));if(!name||!Number.isInteger(categoryId))throw new Error('Invalid item');const x=db.prepare('INSERT INTO menu_items(name,category_id,price,icon,stock,low_stock_threshold) VALUES(?,?,?,?,?,?)').run(name,categoryId,price,icon,stock,low);res.json(db.prepare(`SELECT m.id,m.name,m.price,m.icon,m.available,m.stock,m.low_stock_threshold,c.id category_id,c.name category FROM menu_items m JOIN categories c ON c.id=m.category_id WHERE m.id=?`).get(x.lastInsertRowid))}catch(e){res.status(400).json({error:e.message})}});
app.put('/api/menu/:id',auth,(req,res)=>{try{const id=Number(req.params.id),old=db.prepare('SELECT * FROM menu_items WHERE id=?').get(id);if(!old)return res.status(404).json({error:'Item not found'});const name=clean(req.body.name,old.name),cat=Number(req.body.categoryId||old.category_id),price=req.body.price==null?old.price:money(req.body.price),icon=clean(req.body.icon,old.icon),available=req.body.available==null?old.available:(req.body.available?1:0),stock=req.body.stock==null?old.stock:Math.max(0,Math.floor(Number(req.body.stock))),low=req.body.lowStockThreshold==null?old.low_stock_threshold:Math.max(0,Math.floor(Number(req.body.lowStockThreshold)));db.prepare('UPDATE menu_items SET name=?,category_id=?,price=?,icon=?,available=?,stock=?,low_stock_threshold=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(name,cat,price,icon,available,stock,low,id);res.json({ok:true})}catch(e){res.status(400).json({error:e.message})}});
app.delete('/api/menu/:id',auth,(req,res)=>{const id=Number(req.params.id);if(db.prepare('SELECT COUNT(*) c FROM order_items WHERE menu_item_id=?').get(id).c)return res.status(409).json({error:'Item has sales history. Disable it instead.'});db.prepare('DELETE FROM menu_items WHERE id=?').run(id);res.json({ok:true})});

app.get('/api/tables',auth,(_req,res)=>res.json(db.prepare('SELECT * FROM cafe_tables ORDER BY table_no').all()));

function nextBill(){const p=new Date().toISOString().slice(0,10).replace(/-/g,'');const c=db.prepare(`SELECT COUNT(*) c FROM orders WHERE date(created_at)=date('now')`).get().c+1;return `TH-${p}-${String(c).padStart(4,'0')}`}
function getOrder(id){const o=db.prepare('SELECT * FROM orders WHERE id=?').get(id);if(!o)return null;o.items=db.prepare('SELECT * FROM order_items WHERE order_id=? ORDER BY id').all(id);return o}
app.post('/api/orders',auth,(req,res)=>{
  const raw=Array.isArray(req.body.items)?req.body.items:[];if(!raw.length)return res.status(400).json({error:'Cart is empty'});
  const type=req.body.orderType==='Takeaway'?'Takeaway':'Dine In', table=type==='Dine In'?(Number(req.body.tableNo)||null):null;if(type==='Dine In'&&!table)return res.status(400).json({error:'Select a table'});
  const payment=['Cash','UPI','Card'].includes(req.body.paymentMethod)?req.body.paymentMethod:'Cash';const customer=clean(req.body.customerName,'Walk-in Customer');const discount=Math.max(0,Math.round(Number(req.body.discount||0)));const gstRate=Number(setting('gst_rate','5'));
  const items=[];let subtotal=0;
  for(const x of raw){const row=db.prepare('SELECT * FROM menu_items WHERE id=?').get(Number(x.id));const qty=Math.max(1,Math.floor(Number(x.quantity||1)));if(!row||!row.available)return res.status(400).json({error:'One or more items are unavailable'});if(row.stock<qty)return res.status(400).json({error:`Insufficient stock for ${row.name}`});const line=row.price*qty;subtotal+=line;items.push({row,qty,line})}
  if(discount>subtotal)return res.status(400).json({error:'Discount exceeds subtotal'});const taxable=subtotal-discount,gst=Math.round(taxable*gstRate/100),total=taxable+gst,bill=nextBill();
  const orderId=db.transaction(()=>{const x=db.prepare('INSERT INTO orders(bill_no,order_type,table_no,customer_name,subtotal,discount,gst_rate,gst,total,payment_method,status) VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(bill,type,table,customer,subtotal,discount,gstRate,gst,total,payment,'paid');const orderId=x.lastInsertRowid;const oi=db.prepare('INSERT INTO order_items(order_id,menu_item_id,item_name,quantity,unit_price,line_total) VALUES(?,?,?,?,?,?)'),up=db.prepare('UPDATE menu_items SET stock=stock-?,updated_at=CURRENT_TIMESTAMP WHERE id=?');items.forEach(x=>{oi.run(orderId,x.row.id,x.row.name,x.qty,x.row.price,x.line)});items.forEach(x=>up.run(x.qty,x.row.id));return orderId})();
  res.json(getOrder(orderId));
});

app.get('/api/orders',auth,(req,res)=>{const q=clean(req.query.q),date=clean(req.query.date);let sql='SELECT * FROM orders WHERE 1=1',p=[];if(q){sql+=' AND (bill_no LIKE ? OR customer_name LIKE ?)';p.push(`%${q}%`,`%${q}%`)}if(date){sql+=' AND date(created_at)=date(?)';p.push(date)}sql+=' ORDER BY id DESC LIMIT 300';res.json(db.prepare(sql).all(...p))});
app.get('/api/orders/:id',auth,(req,res)=>{const o=getOrder(Number(req.params.id));if(!o)return res.status(404).json({error:'Order not found'});res.json(o)});
app.get('/api/dashboard',auth,(_req,res)=>{const today=db.prepare(`SELECT COALESCE(SUM(total),0) sales,COUNT(*) orders FROM orders WHERE date(created_at)=date('now')`).get(),month=db.prepare(`SELECT COALESCE(SUM(total),0) sales,COUNT(*) orders FROM orders WHERE strftime('%Y-%m',created_at)=strftime('%Y-%m','now')`).get(),top=db.prepare(`SELECT item_name,SUM(quantity) quantity FROM order_items oi JOIN orders o ON o.id=oi.order_id WHERE date(o.created_at)=date('now') GROUP BY item_name ORDER BY quantity DESC LIMIT 5`).all(),low=db.prepare(`SELECT m.name,m.stock,m.low_stock_threshold FROM menu_items m WHERE m.available=1 AND m.stock<=m.low_stock_threshold ORDER BY m.stock`).all(),payments=db.prepare(`SELECT payment_method,SUM(total) total,COUNT(*) count FROM orders WHERE date(created_at)=date('now') GROUP BY payment_method`).all();res.json({today,month,top,low,payments})});

app.get('/api/backup',auth,(_req,res)=>{db.pragma('wal_checkpoint(TRUNCATE)');const stamp=new Date().toISOString().replace(/[:.]/g,'-'),dest=path.join(BACKUP_DIR,`two-hearts-${stamp}.db`);fs.copyFileSync(dbPath,dest);res.download(dest,'two-hearts-backup.db')});

app.get('/',(_req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.get('/login.html',(_req,res)=>res.sendFile(path.join(__dirname,'public','login.html')));
app.use((err,_req,res,_next)=>{console.error(err);res.status(500).json({error:'Internal server error'})});
app.listen(PORT,()=>console.log(`Two Hearts Cafe POS: http://localhost:${PORT}`));
