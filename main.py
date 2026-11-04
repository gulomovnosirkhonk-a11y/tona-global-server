import os, sqlite3, secrets, hashlib, hmac, json, re, time, asyncio
import smtplib, ssl, urllib.request, urllib.parse, urllib.error, base64
from email.message import EmailMessage
from fastapi import Request
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, UploadFile, File
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE=Path(__file__).resolve().parent
DATA=Path(os.getenv('TONA_DATA_DIR',str(BASE/'data'))); DATA.mkdir(parents=True,exist_ok=True)
MEDIA=DATA/'media'; MEDIA.mkdir(exist_ok=True)
DB=DATA/'tona.db'
REQUIRE_VERIFICATION=os.getenv('TONA_REQUIRE_VERIFICATION','false').lower()=='true'
app=FastAPI(title='TONA Global API',version='0.2.0')


@contextmanager
def db():
 c=sqlite3.connect(DB,timeout=20);c.row_factory=sqlite3.Row;c.execute('PRAGMA foreign_keys=ON');c.execute('PRAGMA journal_mode=WAL')
 try:
  yield c;c.commit()
 finally:c.close()

with db() as c:
 c.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,contact TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),expires INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS friendships(a INTEGER NOT NULL,b INTEGER NOT NULL,status TEXT NOT NULL,requester INTEGER NOT NULL,PRIMARY KEY(a,b));
 CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY,sender INTEGER NOT NULL,recipient INTEGER NOT NULL,body TEXT NOT NULL,created INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS idx_msg ON messages(sender,recipient,created);
 CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL,kind TEXT NOT NULL,media_url TEXT NOT NULL,caption TEXT NOT NULL,created INTEGER NOT NULL,expires INTEGER);
 CREATE TABLE IF NOT EXISTS uploads(filename TEXT PRIMARY KEY,owner_id INTEGER NOT NULL REFERENCES users(id),created INTEGER NOT NULL);''')

with db() as c:
 c.executescript("""CREATE TABLE IF NOT EXISTS verification(contact TEXT PRIMARY KEY, digest TEXT NOT NULL, expires INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS rate_limits(bucket TEXT PRIMARY KEY, count INTEGER NOT NULL, expires INTEGER NOT NULL);""")

def now():return int(time.time())
def rate_limit(bucket, limit, window):
 with db() as c:
  c.execute('DELETE FROM rate_limits WHERE expires<=?',(now(),))
  c.execute('INSERT INTO rate_limits VALUES(?,1,?) ON CONFLICT(bucket) DO UPDATE SET count=count+1',(bucket,now()+window))
  count=c.execute('SELECT count FROM rate_limits WHERE bucket=?',(bucket,)).fetchone()[0]
 if count>limit:raise HTTPException(429,'Juda ko‘p urinish. Keyinroq qayta urinib ko‘ring.')
def normalize_contact(value):
 value=value.strip().lower()
 if re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',value) or re.fullmatch(r'\+[1-9]\d{7,14}',value):return value
 raise HTTPException(400,'Email yoki xalqaro telefon raqamini kiriting: +998...')
def twilio(action, contact, code=None):
 sid=os.getenv('TWILIO_ACCOUNT_SID');secret=os.getenv('TWILIO_AUTH_TOKEN');service=os.getenv('TWILIO_VERIFY_SERVICE_SID')
 if not all((sid,secret,service)):raise HTTPException(503,'SMS tasdiqlash xizmati hali sozlanmagan.')
 data={'To':contact};data.update({'Code':code} if code else {'Channel':'sms'})
 req=urllib.request.Request('https://verify.twilio.com/v2/Services/'+service+'/'+action,data=urllib.parse.urlencode(data).encode(),headers={'Authorization':'Basic '+base64.b64encode((sid+':'+secret).encode()).decode()})
 try:
  with urllib.request.urlopen(req,timeout=15) as response:return json.load(response)
 except (urllib.error.URLError,TimeoutError):raise HTTPException(502,'SMS xizmati bilan aloqa bo‘lmadi. Qayta urinib ko‘ring.')
class VerificationRequest(BaseModel):
 contact:str=Field(min_length=5,max_length=254)
@app.post('/api/auth/request-code')
def request_code(x:VerificationRequest,request:Request):
 contact=normalize_contact(x.contact)
 rate_limit('code-ip:'+request.client.host,10,3600)
 rate_limit('code:'+contact,3,600)
 if contact.startswith('+'):
  twilio('Verifications',contact)
 else:
  host=os.getenv('SMTP_HOST');sender=os.getenv('SMTP_FROM')
  if not host or not sender:raise HTTPException(503,'Email tasdiqlash xizmati hali sozlanmagan.')
  code=str(secrets.randbelow(1000000)).zfill(6)
  with db() as c:c.execute('INSERT OR REPLACE INTO verification VALUES(?,?,?,0)',(contact,hashlib.sha256(code.encode()).hexdigest(),now()+600))
  msg=EmailMessage();msg['From']=sender;msg['To']=contact;msg['Subject']='TONA — tasdiqlash kodi';msg.set_content('TONA tasdiqlash kodi: '+code+'\nKod 10 daqiqa amal qiladi.')
  try:
   with smtplib.SMTP(host,int(os.getenv('SMTP_PORT','587')),timeout=15) as smtp:
    smtp.starttls(context=ssl.create_default_context())
    if os.getenv('SMTP_USER'):smtp.login(os.environ['SMTP_USER'],os.environ['SMTP_PASSWORD'])
    smtp.send_message(msg)
  except Exception:raise HTTPException(502,'Email yuborilmadi. Keyinroq qayta urinib ko‘ring.')
 return {'ok':True}
def verify_code(contact,code):
 if contact.startswith('+'):
  if twilio('VerificationCheck',contact,code).get('status')!='approved':raise HTTPException(400,'Tasdiqlash kodi noto‘g‘ri yoki muddati tugagan.')
 else:
  with db() as c:
   row=c.execute('SELECT * FROM verification WHERE contact=?',(contact,)).fetchone()
   c.execute('UPDATE verification SET attempts=attempts+1 WHERE contact=?',(contact,))
  if not row or row['expires']<=now() or row['attempts']>=5 or not hmac.compare_digest(row['digest'],hashlib.sha256(code.encode()).hexdigest()):raise HTTPException(400,'Tasdiqlash kodi noto‘g‘ri yoki muddati tugagan.')
  with db() as c:c.execute('DELETE FROM verification WHERE contact=?',(contact,))
@app.get('/api/config')
def config():return {'verification_required':REQUIRE_VERIFICATION}
@app.get('/healthz')
def health():
 with db() as c:c.execute('SELECT 1')
 return {'status':'ok'}

def password_hash(p):
 salt=secrets.token_bytes(16);return salt.hex()+':'+hashlib.pbkdf2_hmac('sha256',p.encode(),salt,250000).hex()
def check_password(p,stored):
 try:
  s,h=stored.split(':');return hmac.compare_digest(hashlib.pbkdf2_hmac('sha256',p.encode(),bytes.fromhex(s),250000).hex(),h)
 except Exception:return False

def bearer(authorization:str|None=None):return authorization
from fastapi import Header
def current_user(authorization:str|None=Header(None)):
 if not authorization or not authorization.startswith('Bearer '):raise HTTPException(401,'Login required')
 token=authorization[7:]
 with db() as c:
  u=c.execute('SELECT users.id,users.username,users.contact FROM sessions JOIN users ON users.id=sessions.user_id WHERE token_hash=? AND expires>?',(hashlib.sha256(token.encode()).hexdigest(),now())).fetchone()
 if not u:raise HTTPException(401,'Session expired')
 return dict(u)
def issue_token(c,uid):
 t=secrets.token_urlsafe(40);c.execute('INSERT INTO sessions VALUES(?,?,?)',(hashlib.sha256(t.encode()).hexdigest(),uid,now()+30*86400));return t

def is_friend(c,a,b):
 x,y=sorted((a,b));return bool(c.execute("SELECT 1 FROM friendships WHERE a=? AND b=? AND status='accepted'",(x,y)).fetchone())

class Auth(BaseModel):
 code:str=Field(default="",max_length=6)
 username:str=Field(min_length=3,max_length=32)
 contact:str=Field(min_length=5,max_length=254)
 password:str=Field(min_length=10,max_length=128)
class Login(BaseModel):
 contact:str=Field(max_length=254)
 password:str=Field(max_length=128)
class FriendRequest(BaseModel): user_id:int
class Message(BaseModel): recipient:int;body:str=Field(min_length=1,max_length=4000)
class Post(BaseModel): kind:str;media_url:str=Field(max_length=500);caption:str=Field(default='',max_length=500)

@app.get('/static/tona-logo.png')
def logo():return FileResponse(BASE/'tona-logo.png')

@app.get('/')
def home():return FileResponse(BASE/'index.html')
@app.post('/api/register')
def register(x:Auth,request:Request):
 rate_limit("register:"+request.client.host,10,3600)
 username=x.username.strip();contact=x.contact.strip().lower()
 if not re.fullmatch(r'[a-zA-Z0-9_]{3,32}',username):raise HTTPException(400,'Username: letters, digits, underscore')
 if not (re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',contact) or re.fullmatch(r'\+[1-9]\d{7,14}',contact)):raise HTTPException(400,'Use email or international phone +998...')
 if REQUIRE_VERIFICATION:
  if not re.fullmatch(r"[0-9]{6}",x.code):raise HTTPException(400,"6 xonali tasdiqlash kodini kiriting")
  verify_code(contact,x.code)
 with db() as c:
  try:
   cur=c.execute('INSERT INTO users(username,contact,password_hash,created) VALUES(?,?,?,?)',(username,contact,password_hash(x.password),now()))
   token=issue_token(c,cur.lastrowid)
  except sqlite3.IntegrityError:raise HTTPException(409,'Username or contact already exists')
 return {'token':token,'user':{'id':cur.lastrowid,'username':username,'contact':contact}}
@app.post('/api/login')
def login(x:Login,request:Request):
 rate_limit("login:"+request.client.host,30,600)
 with db() as c:
  u=c.execute('SELECT * FROM users WHERE contact=?',(x.contact.strip().lower(),)).fetchone()
  if not u or not check_password(x.password,u['password_hash']):raise HTTPException(401,'Invalid credentials')
  token=issue_token(c,u['id'])
 return {'token':token,'user':{'id':u['id'],'username':u['username'],'contact':u['contact']}}
@app.post('/api/logout')
def logout(u=Depends(current_user),authorization:str|None=Header(None)):
 with db() as c:c.execute('DELETE FROM sessions WHERE token_hash=?',(hashlib.sha256(authorization[7:].encode()).hexdigest(),))
 return {'ok':True}
@app.get('/api/me')
def me(u=Depends(current_user)):return u
@app.get('/api/users')
def users(q:str='',u=Depends(current_user)):
 with db() as c:
  return [dict(x) for x in c.execute('SELECT id,username FROM users WHERE id!=? AND username LIKE ? LIMIT 50',(u['id'],'%'+q[:40]+'%')).fetchall()]
@app.post('/api/friends/request')
def friend_request(x:FriendRequest,u=Depends(current_user)):
 if x.user_id==u['id']:raise HTTPException(400,'Cannot friend yourself')
 a,b=sorted((x.user_id,u['id']))
 with db() as c:
  if not c.execute('SELECT 1 FROM users WHERE id=?',(x.user_id,)).fetchone():raise HTTPException(404,'User not found')
  existing=c.execute('SELECT status FROM friendships WHERE a=? AND b=?',(a,b)).fetchone()
  if existing:raise HTTPException(409,'Request already exists')
  c.execute('INSERT INTO friendships VALUES(?,?,?,?)',(a,b,'pending',u['id']))
 return {'ok':True}
@app.get('/api/friends')
def friends(u=Depends(current_user)):
 with db() as c:
  rows=c.execute('''SELECT f.a,f.b,f.status,f.requester,other.id,other.username FROM friendships f JOIN users other ON other.id=CASE WHEN f.a=? THEN f.b ELSE f.a END WHERE f.a=? OR f.b=?''',(u['id'],u['id'],u['id'])).fetchall()
 return [dict(r) for r in rows]
@app.post('/api/friends/{other}/accept')
def accept(other:int,u=Depends(current_user)):
 a,b=sorted((other,u['id']))
 with db() as c:
  cur=c.execute("UPDATE friendships SET status='accepted' WHERE a=? AND b=? AND status='pending' AND requester!=?",(a,b,u['id']))
  if not cur.rowcount:raise HTTPException(404,'No incoming request')
 return {'ok':True}
@app.delete('/api/friends/{other}')
def remove_friend(other:int,u=Depends(current_user)):
 a,b=sorted((other,u['id']))
 with db() as c:c.execute('DELETE FROM friendships WHERE a=? AND b=?',(a,b))
 return {'ok':True}
@app.get('/api/messages/{other}')
def history(other:int,u=Depends(current_user)):
 with db() as c:
  if not is_friend(c,u['id'],other):raise HTTPException(403,'Only accepted friends can chat')
  rows=c.execute('''SELECT * FROM (SELECT id,sender,recipient,body,created FROM messages WHERE (sender=? AND recipient=?) OR (sender=? AND recipient=?) ORDER BY id DESC LIMIT 100) ORDER BY id ASC''',(u['id'],other,other,u['id'])).fetchall()
 return [dict(r) for r in rows]
connections={}
async def broadcast(uid,event):
 for ws in list(connections.get(uid,set())):
  try:
   with db() as c:valid=c.execute('SELECT 1 FROM sessions WHERE token_hash=? AND expires>?',(ws.state.token_hash,now())).fetchone()
   if not valid:
    await ws.close(code=1008);connections.get(uid,set()).discard(ws);continue
   await ws.send_json(event)
  except Exception:connections.get(uid,set()).discard(ws)
@app.post('/api/messages')
async def send(x:Message,u=Depends(current_user)):
 if not x.body.strip():raise HTTPException(400,'Xabar bo‘sh bo‘lishi mumkin emas')
 rate_limit('message:'+str(u['id']),120,60)
 with db() as c:
  if not is_friend(c,u['id'],x.recipient):raise HTTPException(403,'Only accepted friends can chat')
  cur=c.execute('INSERT INTO messages(sender,recipient,body,created) VALUES(?,?,?,?)',(u['id'],x.recipient,x.body,now()))
  msg={'id':cur.lastrowid,'sender':u['id'],'recipient':x.recipient,'body':x.body,'created':now()}
 await broadcast(x.recipient,{'type':'message','message':msg});await broadcast(u['id'],{'type':'message','message':msg})
 return msg
@app.websocket('/ws')
async def websocket(ws:WebSocket):
 await ws.accept()
 try:
  payload=await asyncio.wait_for(ws.receive_json(),timeout=10)
  token=payload.get('token','')
  if not isinstance(token,str):raise ValueError()
 except Exception:
  await ws.close(code=1008);return
 with db() as c:
  row=c.execute('SELECT user_id FROM sessions WHERE token_hash=? AND expires>?',(hashlib.sha256(token.encode()).hexdigest(),now())).fetchone()
 if not row:
  await ws.close(code=1008);return
 uid=row['user_id'];ws.state.token_hash=hashlib.sha256(token.encode()).hexdigest();connections.setdefault(uid,set()).add(ws)
 try:
  while True:
   await ws.receive_text()
   with db() as c:valid=c.execute('SELECT 1 FROM sessions WHERE token_hash=? AND expires>?',(hashlib.sha256(token.encode()).hexdigest(),now())).fetchone()
   if not valid:
    await ws.close(code=1008);break
   await ws.send_json({'type':'pong'})
 except WebSocketDisconnect:pass
 finally:connections.get(uid,set()).discard(ws)
@app.post('/api/upload')
async def upload(file:UploadFile=File(...),u=Depends(current_user)):
 allowed={'image/jpeg':'.jpg','image/png':'.png','image/webp':'.webp','video/mp4':'.mp4','video/webm':'.webm'}
 if file.content_type not in allowed:raise HTTPException(415,'Only images or MP4/WebM')
 suffix=allowed[file.content_type];filename=secrets.token_hex(18)+suffix;path=MEDIA/filename
 size=0
 try:
  with path.open('wb') as f:
   while chunk:=await file.read(1024*1024):
    size+=len(chunk)
    if size>25*1024*1024:raise HTTPException(413,'25 MB upload limit')
    f.write(chunk)
 except Exception:
  path.unlink(missing_ok=True);raise
 with db() as c:c.execute('INSERT INTO uploads VALUES(?,?,?)',(filename,u['id'],now()))
 return {'media_url':'/media/'+filename}
@app.post('/api/posts')
def create_post(x:Post,u=Depends(current_user)):
 if x.kind not in ('reel','story') or not re.fullmatch(r'/media/[a-f0-9]{36}\.(jpg|png|webp|mp4|webm)',x.media_url):raise HTTPException(400,'Upload media first')
 with db() as c:
  owned=c.execute('SELECT 1 FROM uploads WHERE filename=? AND owner_id=?',(x.media_url.split('/')[-1],u['id'])).fetchone()
  used=c.execute('SELECT 1 FROM posts WHERE media_url=?',(x.media_url,)).fetchone()
  if not owned or used:raise HTTPException(403,'Upload your own new file')
  cur=c.execute('INSERT INTO posts(user_id,kind,media_url,caption,created,expires) VALUES(?,?,?,?,?,?)',(u['id'],x.kind,x.media_url,x.caption,now(),now()+86400 if x.kind=='story' else None))
 return {'id':cur.lastrowid,'ok':True}
@app.get('/api/feed')
def feed(kind:str='reel',u=Depends(current_user)):
 if kind not in ('reel','story'):raise HTTPException(400,'Invalid feed')
 with db() as c:
  rows=c.execute('''SELECT p.id,p.user_id,p.kind,p.media_url,p.caption,p.created,p.expires,users.username FROM posts p JOIN users ON users.id=p.user_id WHERE p.kind=? AND (p.expires IS NULL OR p.expires>?) AND (p.user_id=? OR EXISTS(SELECT 1 FROM friendships f WHERE f.a=min(p.user_id,?) AND f.b=max(p.user_id,?) AND f.status='accepted')) ORDER BY p.created DESC LIMIT 100''',(kind,now(),u['id'],u['id'],u['id'])).fetchall()
 return [dict(r) for r in rows]

@app.get('/media/{filename}')
def private_media(filename:str,u=Depends(current_user)):
 if not re.fullmatch(r'[a-f0-9]{36}\.(jpg|png|webp|mp4|webm)',filename):raise HTTPException(404,'Not found')
 with db() as c:
  post=c.execute('SELECT user_id,expires FROM posts WHERE media_url=?',('/media/'+filename,)).fetchone()
  if not post or (post['expires'] is not None and post['expires']<=now()):raise HTTPException(404,'Not found')
  if post['user_id']!=u['id'] and not is_friend(c,u['id'],post['user_id']):raise HTTPException(403,'Friends only')
 path=MEDIA/filename
 if not path.is_file():raise HTTPException(404,'Not found')
 return FileResponse(path,headers={'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'})

@app.delete('/api/posts/{post_id}')
def delete_post(post_id:int,u=Depends(current_user)):
 with db() as c:
  row=c.execute('SELECT media_url FROM posts WHERE id=? AND user_id=?',(post_id,u['id'])).fetchone()
  if not row:raise HTTPException(404,'Post topilmadi')
  filename=row['media_url'].split('/')[-1]
  c.execute('DELETE FROM posts WHERE id=?',(post_id,))
  c.execute('DELETE FROM uploads WHERE filename=?',(filename,))
 (MEDIA/filename).unlink(missing_ok=True)
 return {'ok':True}
