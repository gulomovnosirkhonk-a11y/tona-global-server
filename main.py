import os, sqlite3, secrets, hashlib, hmac, json, re, time, asyncio
import smtplib, ssl, urllib.request, urllib.parse, urllib.error, base64
from email.message import EmailMessage
from fastapi import Request, Response, Query
from migrations import upgrade
from fastapi.responses import JSONResponse
from PIL import Image, ImageOps, UnidentifiedImageError
import io, warnings
from typing import Literal
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, UploadFile, File, Form
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE=Path(__file__).resolve().parent
DATA=Path(os.getenv('TONA_DATA_DIR',str(BASE/'data'))); DATA.mkdir(parents=True,exist_ok=True)
MEDIA=DATA/'media'; MEDIA.mkdir(exist_ok=True)
DB=DATA/'tona.db'
PHONE_LOGIN=os.getenv('TONA_PHONE_LOGIN','true').lower()=='true'
REQUIRE_VERIFICATION=os.getenv('TONA_REQUIRE_VERIFICATION','false').lower()=='true'
app=FastAPI(title='TONA Global API',version='0.6.0')


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

with db() as c:
 columns={r['name'] for r in c.execute('PRAGMA table_info(users)')}
 for name,definition in {
  'display_name':"TEXT NOT NULL DEFAULT ''",'bio':"TEXT NOT NULL DEFAULT ''",
  'avatar':"TEXT NOT NULL DEFAULT ''",'avatar_visibility':"TEXT NOT NULL DEFAULT 'contacts'",
  'discoverable':"INTEGER NOT NULL DEFAULT 1",'allow_requests':"INTEGER NOT NULL DEFAULT 1",
  'theme':"TEXT NOT NULL DEFAULT 'dark'",'font_size':"TEXT NOT NULL DEFAULT 'normal'",
  'is_moderator':"INTEGER NOT NULL DEFAULT 0",'banned':"INTEGER NOT NULL DEFAULT 0",'ban_reason':"TEXT NOT NULL DEFAULT ''"
 }.items():
  if name not in columns:c.execute(f'ALTER TABLE users ADD COLUMN {name} {definition}')
 if 'hidden' not in {r['name'] for r in c.execute('PRAGMA table_info(posts)')}:
  c.execute('ALTER TABLE posts ADD COLUMN hidden INTEGER NOT NULL DEFAULT 0')
 c.executescript("""
 CREATE TABLE IF NOT EXISTS blocks(owner INTEGER NOT NULL,target INTEGER NOT NULL,created INTEGER NOT NULL,PRIMARY KEY(owner,target));
 CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY,reporter INTEGER NOT NULL,target INTEGER NOT NULL,post_id INTEGER,message_id INTEGER,category TEXT NOT NULL,details TEXT NOT NULL,evidence TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'open',created INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS moderation_log(id INTEGER PRIMARY KEY,moderator INTEGER NOT NULL,report_id INTEGER NOT NULL,action TEXT NOT NULL,created INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS session_info(token_hash TEXT PRIMARY KEY,device TEXT NOT NULL,created INTEGER NOT NULL);
 """)

with db() as c:upgrade(c)

def is_blocked(c,a,b):
 return bool(c.execute('SELECT 1 FROM blocks WHERE (owner=? AND target=?) OR (owner=? AND target=?)',(a,b,b,a)).fetchone())
def admin_ids():
 with db() as c:return {r['id'] for r in c.execute('SELECT id FROM users WHERE is_moderator=1 AND banned=0')}

def set_session(response,request,token):
 response.set_cookie('tona_session',token,httponly=True,secure=request.url.hostname not in ('127.0.0.1','localhost','testserver'),samesite='lax',max_age=30*86400,path='/')
 with db() as c:c.execute('INSERT OR REPLACE INTO session_info VALUES(?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),request.headers.get('user-agent','Unknown')[:250],now()))

def request_token(request,authorization=None):
 if authorization and authorization.startswith('Bearer '):return authorization[7:]
 return request.cookies.get('tona_session','')

@app.middleware('http')
async def security_headers(request,call_next):
 if request.method in ('POST','PUT','PATCH','DELETE') and request.cookies.get('tona_session') and not request.headers.get('authorization'):
  if request.headers.get('x-tona-client')!='web':return JSONResponse({'detail':'Request rejected'},status_code=403)
  origin=request.headers.get('origin')
  if origin and urllib.parse.urlsplit(origin).netloc!=request.url.netloc:return JSONResponse({'detail':'Origin rejected'},status_code=403)
 response=await call_next(request)
 response.headers['X-Content-Type-Options']='nosniff'
 response.headers['X-Frame-Options']='DENY'
 response.headers['Referrer-Policy']='no-referrer'
 response.headers['Permissions-Policy']='camera=(self), microphone=(self), geolocation=()'
 response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; media-src 'self' blob:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
 if request.url.path.startswith(('/api/','/media/')):response.headers['Cache-Control']='no-store'
 elif request.url.path in ('/','/app.js','/i18n.js','/style.css'):response.headers['Cache-Control']='no-cache, must-revalidate'
 return response

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
 raise HTTPException(400,'Email yoki xalqaro telefon raqamini kiriting: +1...')
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
  host=os.getenv('SMTP_HOST');sender=os.getenv('EMAIL_FROM') or os.getenv('SMTP_FROM');api_key=os.getenv('RESEND_API_KEY')
  if not (host or api_key) or not sender:raise HTTPException(503,'Email tasdiqlash xizmati hali sozlanmagan.')
  code=str(secrets.randbelow(1000000)).zfill(6)
  with db() as c:c.execute('INSERT OR REPLACE INTO verification VALUES(?,?,?,0)',(contact,hashlib.sha256(code.encode()).hexdigest(),now()+600))
  msg=EmailMessage();msg['From']=sender;msg['To']=contact;msg['Subject']='TONA — tasdiqlash kodi';msg.set_content('TONA tasdiqlash kodi: '+code+'\nKod 10 daqiqa amal qiladi.')
  try:
   if api_key:
    payload={'from':sender,'to':[contact],'subject':str(msg['Subject']),'text':msg.get_content()}
    req=urllib.request.Request('https://api.resend.com/emails',data=json.dumps(payload).encode(),headers={'Authorization':'Bearer '+api_key,'Content-Type':'application/json','User-Agent':'TONA/0.6'})
    with urllib.request.urlopen(req,timeout=15) as result:
     if not json.load(result).get('id'):raise ValueError('Mail provider rejected request')
   else:
    with smtplib.SMTP(host,int(os.getenv('SMTP_PORT','587')),timeout=15) as smtp:
     smtp.starttls(context=ssl.create_default_context())
     if os.getenv('SMTP_USER'):smtp.login(os.environ['SMTP_USER'],os.environ['SMTP_PASSWORD'])
     smtp.send_message(msg)
  except Exception:
   with db() as c:c.execute('DELETE FROM verification WHERE contact=? AND digest=?',(contact,hashlib.sha256(code.encode()).hexdigest()))
   raise HTTPException(502,'Email yuborilmadi. Keyinroq qayta urinib ko‘ring.')
 return {'ok':True}
def verify_code(contact,code):
 if contact.startswith('+'):
  if twilio('VerificationCheck',contact,code).get('status')!='approved':raise HTTPException(400,'Tasdiqlash kodi noto‘g‘ri yoki muddati tugagan.')
 else:
  with db() as c:
   c.execute('BEGIN IMMEDIATE')
   row=c.execute('SELECT * FROM verification WHERE contact=?',(contact,)).fetchone()
   valid=bool(row and row['expires']>now() and row['attempts']<5 and hmac.compare_digest(row['digest'],hashlib.sha256(code.encode()).hexdigest()))
   if valid:c.execute('DELETE FROM verification WHERE contact=?',(contact,))
   else:c.execute('UPDATE verification SET attempts=attempts+1 WHERE contact=?',(contact,))
  if not valid:raise HTTPException(400,'Tasdiqlash kodi noto‘g‘ri yoki muddati tugagan.')
@app.get('/api/config')
def config():return {'email_login':True,'email_ready':bool((os.getenv('RESEND_API_KEY') or os.getenv('SMTP_HOST')) and (os.getenv('EMAIL_FROM') or os.getenv('SMTP_FROM'))),'phone_login':PHONE_LOGIN,'sms_ready':all(os.getenv(k) for k in ('TWILIO_ACCOUNT_SID','TWILIO_AUTH_TOKEN','TWILIO_VERIFY_SERVICE_SID')),'verification_required':REQUIRE_VERIFICATION,'moderation_active':bool(admin_ids()),'owner_setup_available':len(os.getenv('TONA_OWNER_KEY',''))>=32,'owner_username':os.getenv('TONA_OWNER_USERNAME','nosirkhon'),'ephemeral':os.getenv('TONA_EPHEMERAL','true')=='true'}
@app.get('/healthz')
def health():
 with db() as c:c.execute('SELECT 1')
 return {'status':'ok'}

def password_hash(p):
 salt=secrets.token_bytes(16)
 return 'pbkdf2_sha256$600000$'+salt.hex()+'$'+hashlib.pbkdf2_hmac('sha256',p.encode(),salt,600000).hex()
def check_password(p,stored):
 try:
  if stored.startswith('pbkdf2_sha256$'):
   _,rounds,s,h=stored.split('$');iterations=int(rounds)
  else:
   s,h=stored.split(':');iterations=250000
  return hmac.compare_digest(hashlib.pbkdf2_hmac('sha256',p.encode(),bytes.fromhex(s),iterations).hex(),h)
 except (ValueError,TypeError):return False

def bearer(authorization:str|None=None):return authorization
from fastapi import Header
def current_user(request:Request,authorization:str|None=Header(None)):
 token=request_token(request,authorization)
 if not token:raise HTTPException(401,'Kirish talab qilinadi')
 with db() as c:
  u=c.execute('SELECT users.* FROM sessions JOIN users ON users.id=sessions.user_id WHERE token_hash=? AND expires>?',(hashlib.sha256(token.encode()).hexdigest(),now())).fetchone()
 if not u:raise HTTPException(401,'Seans tugagan. Qayta kiring.')
 if u['banned']:raise HTTPException(403,'Akkaunt moderatsiya tomonidan cheklangan')
 result=dict(u);result.pop('password_hash',None);result.pop('ban_reason',None);result['is_admin']=result['id'] in admin_ids()
 return result

def issue_token(c,uid):
 t=secrets.token_urlsafe(40);c.execute('INSERT INTO sessions VALUES(?,?,?)',(hashlib.sha256(t.encode()).hexdigest(),uid,now()+30*86400));return t

def is_friend(c,a,b):
 if is_blocked(c,a,b):return False
 if c.execute('SELECT 1 FROM users WHERE id IN (?,?) AND banned=1',(a,b)).fetchone():return False
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
class Message(BaseModel):
 recipient:int
 body:str=Field(min_length=1,max_length=4000)
 reply_to:int|None=Field(default=None,ge=1)
class Post(BaseModel): kind:str;media_url:str=Field(max_length=500);caption:str=Field(default='',max_length=500)

@app.get('/static/tona-logo.png')
def logo():return FileResponse(BASE/'tona-logo.png')

@app.get('/i18n.js')
def translations():return FileResponse(BASE/'i18n.js',media_type='application/javascript')

@app.get('/app.js')
def script():return FileResponse(BASE/'app.js',media_type='application/javascript')
@app.get('/style.css')
def stylesheet():return FileResponse(BASE/'style.css',media_type='text/css')

@app.get('/')
def home():return FileResponse(BASE/'index.html')
@app.post('/api/register')
def register(x:Auth,request:Request,response:Response):
 if PHONE_LOGIN:raise HTTPException(403,"Telefon va SMS kod orqali ro‘yxatdan o‘ting")
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
 set_session(response,request,token)
 return {'token':token,'user':{'id':cur.lastrowid,'username':username,'contact':contact}}
@app.post('/api/login')
def login(x:Login,request:Request,response:Response):
 rate_limit("login:"+request.client.host,30,600)
 with db() as c:
  u=c.execute('SELECT * FROM users WHERE contact=?',(x.contact.strip().lower(),)).fetchone()
  if not u or not check_password(x.password,u['password_hash']):raise HTTPException(401,'Invalid credentials')
  if u['banned']:raise HTTPException(403,'Akkaunt cheklangan')
  token=issue_token(c,u['id'])
 set_session(response,request,token)
 return {'token':token,'user':{'id':u['id'],'username':u['username'],'contact':u['contact']}}
@app.post('/api/logout')
def logout(request:Request,response:Response,u=Depends(current_user),authorization:str|None=Header(None)):
 with db() as c:c.execute('DELETE FROM sessions WHERE token_hash=?',(hashlib.sha256(request_token(request,authorization).encode()).hexdigest(),))
 response.delete_cookie('tona_session',path='/')
 return {'ok':True}
@app.get('/api/me')
def me(u=Depends(current_user)):
 with db() as c:
  phone=c.execute('SELECT phone FROM verified_phones WHERE user_id=?',(u['id'],)).fetchone()
  email=c.execute('SELECT email FROM account_emails WHERE user_id=?',(u['id'],)).fetchone()
 return {**u,'verified_phone':phone['phone'] if phone else '', 'verified_email':email['email'] if email else ''}
@app.get('/api/users')
def users(q:str='',u=Depends(current_user)):
 with db() as c:
  return [public_profile(c,dict(x),u['id']) for x in c.execute('SELECT * FROM users WHERE id!=? AND banned=0 AND discoverable=1 AND username LIKE ? LIMIT 50',(u['id'],'%'+q[:40]+'%')).fetchall() if not is_blocked(c,u['id'],x['id'])]
@app.post('/api/friends/request')
def friend_request(x:FriendRequest,u=Depends(current_user)):
 if x.user_id==u['id']:raise HTTPException(400,'Cannot friend yourself')
 rate_limit('friend:'+str(u['id']),20,3600)
 a,b=sorted((x.user_id,u['id']))
 with db() as c:
  target=c.execute('SELECT * FROM users WHERE id=?',(x.user_id,)).fetchone()
  if not target or target['banned'] or not target['allow_requests'] or is_blocked(c,u['id'],x.user_id):raise HTTPException(403,'Kontakt so‘rovi yuborib bo‘lmaydi')
  if not c.execute('SELECT 1 FROM users WHERE id=?',(x.user_id,)).fetchone():raise HTTPException(404,'User not found')
  existing=c.execute('SELECT status FROM friendships WHERE a=? AND b=?',(a,b)).fetchone()
  if existing:raise HTTPException(409,'Request already exists')
  c.execute('INSERT INTO friendships VALUES(?,?,?,?)',(a,b,'pending',u['id']))
 return {'ok':True}
@app.get('/api/friends')
def friends(u=Depends(current_user)):
 with db() as c:
  rows=c.execute('''SELECT f.a,f.b,f.status,f.requester,other.id,other.username,other.display_name,other.bio,other.bio_visibility,other.avatar,other.avatar_visibility FROM friendships f JOIN users other ON other.id=CASE WHEN f.a=? THEN f.b ELSE f.a END WHERE f.a=? OR f.b=?''',(u['id'],u['id'],u['id'])).fetchall()
  return [{k:r[k] for k in ('a','b','status','requester')} | public_profile(c,dict(r),u['id']) for r in rows if not is_blocked(c,u['id'],r['id'])]
@app.post('/api/friends/{other}/accept')
def accept(other:int,u=Depends(current_user)):
 a,b=sorted((other,u['id']))
 with db() as c:
  if is_blocked(c,u['id'],other):raise HTTPException(403,'Kontakt bloklangan')
  cur=c.execute("UPDATE friendships SET status='accepted' WHERE a=? AND b=? AND status='pending' AND requester!=?",(a,b,u['id']))
  if not cur.rowcount:raise HTTPException(404,'No incoming request')
 return {'ok':True}
@app.delete('/api/friends/{other}')
def remove_friend(other:int,u=Depends(current_user)):
 a,b=sorted((other,u['id']))
 with db() as c:c.execute('DELETE FROM friendships WHERE a=? AND b=?',(a,b))
 return {'ok':True}
@app.get('/api/messages/{other}')
def history(other:int,q:str=Query(default='',max_length=200),before:int|None=Query(default=None,ge=1),limit:int=Query(default=100,ge=1,le=100),u=Depends(current_user)):
 with db() as c:
  if not is_friend(c,u['id'],other):raise HTTPException(403,'Only accepted friends can chat')
  rows=c.execute("""SELECT * FROM (SELECT * FROM messages WHERE ((sender=? AND recipient=?) OR (sender=? AND recipient=?)) AND (? IS NULL OR id<?) AND (?='' OR (deleted_at IS NULL AND instr(lower(body),lower(?))>0)) ORDER BY id DESC LIMIT ?) ORDER BY id ASC""",(u['id'],other,other,u['id'],before,before,q,q,limit)).fetchall()
 with db() as c:return [private_receipt(c,dict(r)) for r in rows]

def receipts_allowed(c,a,b):
 return not c.execute('SELECT 1 FROM users WHERE id IN (?,?) AND read_receipts=0',(a,b)).fetchone()

def private_receipt(c,message):
 if not receipts_allowed(c,message['sender'],message['recipient']):message={**message,'read_at':None}
 return message

connections={}
async def broadcast(uid,event):
 for ws in list(connections.get(uid,set())):
  try:
   with db() as c:valid=c.execute('SELECT 1 FROM sessions JOIN users ON users.id=sessions.user_id WHERE token_hash=? AND expires>? AND users.banned=0',(ws.state.token_hash,now())).fetchone()
   if not valid:
    await ws.close(code=1008);connections.get(uid,set()).discard(ws);continue
   with db() as c:
    outgoing=event
    if event.get('type')=='read' and not receipts_allowed(c,uid,event['reader']):continue
    if event.get('type')=='message':outgoing={**event,'message':private_receipt(c,event['message'])}
   await ws.send_json(outgoing)
  except Exception:connections.get(uid,set()).discard(ws)
@app.post('/api/messages')
async def send(x:Message,u=Depends(current_user)):
 if not x.body.strip():raise HTTPException(400,'Xabar bo‘sh bo‘lishi mumkin emas')
 rate_limit('message:'+str(u['id']),120,60)
 with db() as c:
  if not is_friend(c,u['id'],x.recipient):raise HTTPException(403,'Only accepted friends can chat')
  if x.reply_to is not None:
   parent=c.execute('SELECT * FROM messages WHERE id=? AND deleted_at IS NULL',(x.reply_to,)).fetchone()
   if not parent or {parent['sender'],parent['recipient']}!={u['id'],x.recipient}:raise HTTPException(404,'Reply message unavailable')
  cur=c.execute('INSERT INTO messages(sender,recipient,body,created,reply_to) VALUES(?,?,?,?,?)',(u['id'],x.recipient,x.body,now(),x.reply_to))
  msg=dict(c.execute('SELECT * FROM messages WHERE id=?',(cur.lastrowid,)).fetchone())
 await broadcast(x.recipient,{'type':'message','message':msg});await broadcast(u['id'],{'type':'message','message':msg})
 with db() as c:return private_receipt(c,msg)
@app.websocket('/ws')
async def websocket(ws:WebSocket):
 origin=ws.headers.get('origin')
 if origin and urllib.parse.urlsplit(origin).netloc!=ws.url.netloc:
  await ws.close(code=1008);return
 await ws.accept()
 try:
  payload=await asyncio.wait_for(ws.receive_json(),timeout=10)
  token=payload.get('token') or ws.cookies.get('tona_session','')
  if not isinstance(token,str):raise ValueError()
 except Exception:
  await ws.close(code=1008);return
 with db() as c:
  row=c.execute('SELECT user_id FROM sessions JOIN users ON users.id=sessions.user_id WHERE token_hash=? AND expires>? AND users.banned=0',(hashlib.sha256(token.encode()).hexdigest(),now())).fetchone()
 if not row:
  await ws.close(code=1008);return
 uid=row['user_id'];ws.state.token_hash=hashlib.sha256(token.encode()).hexdigest();connections.setdefault(uid,set()).add(ws)
 try:
  while True:
   await ws.receive_text()
   with db() as c:valid=c.execute('SELECT 1 FROM sessions JOIN users ON users.id=sessions.user_id WHERE token_hash=? AND expires>? AND users.banned=0',(hashlib.sha256(token.encode()).hexdigest(),now())).fetchone()
   if not valid:
    await ws.close(code=1008);break
   await ws.send_json({'type':'pong'})
 except WebSocketDisconnect:pass
 finally:connections.get(uid,set()).discard(ws)
@app.post('/api/upload')
async def upload(file:UploadFile=File(...),u=Depends(current_user)):
 rate_limit('upload:'+str(u['id']),20,3600)
 with db() as c:
  total=c.execute('SELECT count(*) FROM uploads WHERE owner_id=?',(u['id'],)).fetchone()[0]
 if total>=100:raise HTTPException(429,'Media limiti. Eski postlarni o‘chiring.')
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
 try:
  if suffix in ('.jpg','.png','.webp'):
   normalize_image(path)
  else:
   head=path.read_bytes()[:32]
   if (suffix=='.mp4' and head[4:8]!=b'ftyp') or (suffix=='.webm' and not head.startswith(bytes.fromhex('1a45dfa3'))):raise ValueError('video')
  if not size:raise ValueError('empty')
 except Exception:
  path.unlink(missing_ok=True);raise HTTPException(415,'Fayl formati noto‘g‘ri yoki shikastlangan')
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
  rows=c.execute('''SELECT p.id,p.user_id,p.kind,p.media_url,p.caption,p.created,p.expires,users.username FROM posts p JOIN users ON users.id=p.user_id WHERE p.hidden=0 AND users.banned=0 AND p.kind=? AND (p.expires IS NULL OR p.expires>?) AND (p.user_id=? OR EXISTS(SELECT 1 FROM friendships f WHERE f.a=min(p.user_id,?) AND f.b=max(p.user_id,?) AND f.status='accepted')) ORDER BY p.created DESC LIMIT 100''',(kind,now(),u['id'],u['id'],u['id'])).fetchall()
  return [dict(r) for r in rows if not is_blocked(c,u['id'],r['user_id'])]

@app.get('/media/{filename}')
def private_media(filename:str,u=Depends(current_user)):
 if not re.fullmatch(r'[a-f0-9]{36}\.(jpg|png|webp|mp4|webm)',filename):raise HTTPException(404,'Not found')
 with db() as c:
  post=c.execute('SELECT user_id,expires FROM posts JOIN users ON users.id=posts.user_id WHERE media_url=? AND hidden=0 AND users.banned=0',('/media/'+filename,)).fetchone()
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

# Profile data is deliberately separate from private phone/email identifiers.
def public_profile(c,row,viewer):
 visible=row['id']==viewer or row['avatar_visibility']=='everyone' or (row['avatar_visibility']=='contacts' and is_friend(c,viewer,row['id']))
 bio_visible=row['id']==viewer or row.get('bio_visibility','everyone')=='everyone' or (row.get('bio_visibility')=='contacts' and is_friend(c,viewer,row['id']))
 return {k:row[k] for k in ('id','username','display_name')} | {'bio':row['bio'] if bio_visible else '', 'avatar_url':f"/api/avatar/{row['id']}" if row['avatar'] and visible else ''}

def normalize_image(path,avatar=False):
 Image.MAX_IMAGE_PIXELS=8_000_000
 with warnings.catch_warnings():
  warnings.simplefilter('error',Image.DecompressionBombWarning)
  with Image.open(path) as im:
   im.load();im=ImageOps.exif_transpose(im).convert('RGB')
   im.thumbnail((640,640) if avatar else (1920,1920))
   # Re-encoding discards EXIF/GPS metadata and appended payloads.
   im.save(path,format='JPEG' if avatar or path.suffix=='.jpg' else 'PNG' if path.suffix=='.png' else 'WEBP')

class ProfileUpdate(BaseModel):
 username:str|None=Field(default=None,min_length=3,max_length=32)
 display_name:str=Field(default='',max_length=60)
 bio:str=Field(default='',max_length=160)
class SettingsUpdate(BaseModel):
 avatar_visibility:Literal['everyone','contacts','nobody']='contacts'
 bio_visibility:Literal['everyone','contacts','nobody']='everyone'
 discoverable:bool=True
 allow_requests:bool=True
 read_receipts:bool=True
 theme:Literal['light','dark']='light'
 font_size:Literal['normal','large']='normal'
class PasswordUpdate(BaseModel):
 current_password:str=Field(max_length=128)
 new_password:str=Field(min_length=10,max_length=128)

@app.patch('/api/profile')
def update_profile(x:ProfileUpdate,u=Depends(current_user)):
 if x.username is not None and not re.fullmatch(r'[a-zA-Z0-9_]{3,32}',x.username):raise HTTPException(400,'Username: letters, digits, underscore')
 with db() as c:
  try:
   if x.username is not None:c.execute('UPDATE users SET username=? WHERE id=?',(x.username,u['id']))
   c.execute('UPDATE users SET display_name=?,bio=? WHERE id=?',(x.display_name.strip(),x.bio.strip(),u['id']))
  except sqlite3.IntegrityError:raise HTTPException(409,'Username band')
 return {'ok':True}
@app.get('/api/profile/{uid}')
def profile(uid:int,u=Depends(current_user)):
 with db() as c:
  row=c.execute('SELECT * FROM users WHERE id=? AND banned=0',(uid,)).fetchone()
  if not row or is_blocked(c,u['id'],uid):raise HTTPException(404,'Profil topilmadi')
  return public_profile(c,dict(row),u['id'])
@app.patch('/api/settings')
def update_settings(x:SettingsUpdate,u=Depends(current_user)):
 values=x.model_dump(exclude_unset=True)
 if values:
  with db() as c:c.execute('UPDATE users SET '+','.join(key+'=?' for key in values)+' WHERE id=?',(*values.values(),u['id']))
 return {'ok':True}
@app.post('/api/profile/avatar')
async def upload_avatar(file:UploadFile=File(...),u=Depends(current_user)):
 rate_limit('avatar:'+str(u['id']),10,3600)
 data=await file.read(5*1024*1024+1)
 if len(data)>5*1024*1024:raise HTTPException(413,'Profil rasmi 5 MB dan kichik bo‘lsin')
 name=secrets.token_hex(18)+'.jpg';path=MEDIA/name;path.write_bytes(data)
 try:normalize_image(path,avatar=True)
 except Exception:
  path.unlink(missing_ok=True);raise HTTPException(415,'JPG, PNG yoki WebP rasm tanlang')
 with db() as c:
  old=c.execute('SELECT avatar FROM users WHERE id=?',(u['id'],)).fetchone()['avatar']
  c.execute('UPDATE users SET avatar=? WHERE id=?',(name,u['id']))
 if old:(MEDIA/old).unlink(missing_ok=True)
 return {'ok':True}
@app.delete('/api/profile/avatar')
def delete_avatar(u=Depends(current_user)):
 with db() as c:
  old=c.execute('SELECT avatar FROM users WHERE id=?',(u['id'],)).fetchone()['avatar']
  c.execute("UPDATE users SET avatar='' WHERE id=?",(u['id'],))
 if old:(MEDIA/old).unlink(missing_ok=True)
 return {'ok':True}
@app.get('/api/avatar/{uid}')
def avatar(uid:int,u=Depends(current_user)):
 with db() as c:
  row=c.execute('SELECT * FROM users WHERE id=? AND banned=0',(uid,)).fetchone()
  if not row or is_blocked(c,u['id'],uid) or not public_profile(c,dict(row),u['id'])['avatar_url']:raise HTTPException(404,'Rasm topilmadi')
  path=MEDIA/row['avatar']
 if not path.is_file():raise HTTPException(404,'Rasm topilmadi')
 return FileResponse(path,media_type='image/jpeg',headers={'Cache-Control':'no-store'})
@app.post('/api/password')
def update_password(x:PasswordUpdate,request:Request,u=Depends(current_user),authorization:str|None=Header(None)):
 rate_limit('password:'+str(u['id']),5,600)
 keep=hashlib.sha256(request_token(request,authorization).encode()).hexdigest()
 with db() as c:
  stored=c.execute('SELECT password_hash FROM users WHERE id=?',(u['id'],)).fetchone()[0]
  if not check_password(x.current_password,stored):raise HTTPException(400,'Hozirgi parol noto‘g‘ri')
  c.execute('UPDATE users SET password_hash=? WHERE id=?',(password_hash(x.new_password),u['id']))
  c.execute('DELETE FROM sessions WHERE user_id=? AND token_hash!=?',(u['id'],keep))
 return {'ok':True}
@app.get('/api/sessions')
def sessions(request:Request,u=Depends(current_user),authorization:str|None=Header(None)):
 current=hashlib.sha256(request_token(request,authorization).encode()).hexdigest()
 with db() as c:
  rows=c.execute("SELECT s.token_hash,s.expires,COALESCE(i.device,'Browser') device,COALESCE(i.created,0) created FROM sessions s LEFT JOIN session_info i ON i.token_hash=s.token_hash WHERE s.user_id=? AND s.expires>?",(u['id'],now())).fetchall()
 return [{'id':r['token_hash'],'device':r['device'],'created':r['created'],'current':r['token_hash']==current} for r in rows]
@app.delete('/api/sessions/others')
def close_other_sessions(request:Request,u=Depends(current_user),authorization:str|None=Header(None)):
 keep=hashlib.sha256(request_token(request,authorization).encode()).hexdigest()
 with db() as c:c.execute('DELETE FROM sessions WHERE user_id=? AND token_hash!=?',(u['id'],keep))
 return {'ok':True}
@app.delete('/api/sessions/{session_id}')
def close_session(session_id:str,u=Depends(current_user)):
 with db() as c:c.execute('DELETE FROM sessions WHERE user_id=? AND token_hash=?',(u['id'],session_id))
 return {'ok':True}
@app.get('/api/blocks')
def blocks(u=Depends(current_user)):
 with db() as c:return [dict(r) for r in c.execute('SELECT users.id,users.username,users.display_name FROM blocks JOIN users ON users.id=blocks.target WHERE owner=?',(u['id'],))]
@app.post('/api/blocks/{uid}')
def block(uid:int,u=Depends(current_user)):
 if uid==u['id']:raise HTTPException(400,'O‘zingizni bloklab bo‘lmaydi')
 with db() as c:
  if not c.execute('SELECT 1 FROM users WHERE id=?',(uid,)).fetchone():raise HTTPException(404,'Foydalanuvchi topilmadi')
  c.execute('INSERT OR IGNORE INTO blocks VALUES(?,?,?)',(u['id'],uid,now()))
  a,b=sorted((u['id'],uid));c.execute('DELETE FROM friendships WHERE a=? AND b=?',(a,b))
 return {'ok':True}
@app.delete('/api/blocks/{uid}')
def unblock(uid:int,u=Depends(current_user)):
 with db() as c:c.execute('DELETE FROM blocks WHERE owner=? AND target=?',(u['id'],uid))
 return {'ok':True}

class Report(BaseModel):
 target:int
 post_id:int|None=None
 message_id:int|None=None
 category:Literal['spam','fraud','harassment','violence','extremism','child_safety','other']
 details:str=Field(default='',max_length=1500)
@app.post('/api/reports')
def report(x:Report,u=Depends(current_user)):
 rate_limit('report:'+str(u['id']),10,3600)
 if x.target==u['id']:raise HTTPException(400,'O‘zingizga shikoyat yuborib bo‘lmaydi')
 with db() as c:
  target=c.execute('SELECT username,bio FROM users WHERE id=?',(x.target,)).fetchone()
  if not target:raise HTTPException(404,'Foydalanuvchi topilmadi')
  evidence={'username':target['username'],'bio':target['bio']}
  if x.post_id:
   post=c.execute('SELECT * FROM posts WHERE id=? AND user_id=?',(x.post_id,x.target)).fetchone()
   if not post or not is_friend(c,u['id'],x.target) or post['hidden'] or (post['expires'] and post['expires']<=now()):raise HTTPException(403,'Postga kirish mumkin emas')
   evidence['post']={'caption':post['caption'],'media_url':post['media_url']}
  if x.message_id:
   msg=c.execute('SELECT body FROM messages WHERE id=? AND sender=? AND recipient=?',(x.message_id,x.target,u['id'])).fetchone()
   if not msg:raise HTTPException(403,'Xabar sizga tegishli emas')
   evidence['message']=msg['body']
  existing=c.execute("SELECT id FROM reports WHERE reporter=? AND target=? AND COALESCE(post_id,0)=? AND COALESCE(message_id,0)=? AND status='open'",(u['id'],x.target,x.post_id or 0,x.message_id or 0)).fetchone()
  if existing:return {'id':existing['id'],'ok':True,'moderation_active':bool(admin_ids())}
  cur=c.execute('INSERT INTO reports(reporter,target,post_id,message_id,category,details,evidence,created) VALUES(?,?,?,?,?,?,?,?)',(u['id'],x.target,x.post_id,x.message_id,x.category,x.details,json.dumps(evidence),now()))
 return {'id':cur.lastrowid,'ok':True,'moderation_active':bool(admin_ids())}
@app.get('/api/reports/mine')
def my_reports(u=Depends(current_user)):
 with db() as c:return [dict(r) for r in c.execute('SELECT id,category,status,created FROM reports WHERE reporter=? ORDER BY id DESC LIMIT 100',(u['id'],))]
def moderator(u=Depends(current_user)):
 if u['id'] not in admin_ids():raise HTTPException(403,'Moderator huquqi kerak')
 return u
@app.get('/api/moderation/reports')
def moderation_reports(u=Depends(moderator)):
 with db() as c:return [dict(r) for r in c.execute('SELECT r.*,users.username FROM reports r JOIN users ON users.id=r.target ORDER BY CASE status WHEN \'open\' THEN 0 ELSE 1 END,id DESC LIMIT 100')]
class ModerationAction(BaseModel):
 action:Literal['dismiss','hide_post','ban']
@app.post('/api/moderation/reports/{report_id}')
def moderate(report_id:int,x:ModerationAction,u=Depends(moderator)):
 with db() as c:
  r=c.execute('SELECT * FROM reports WHERE id=?',(report_id,)).fetchone()
  if not r:raise HTTPException(404,'Shikoyat topilmadi')
  if x.action=='ban':
   if r['target'] in admin_ids():raise HTTPException(400,'Moderatorni bu yerda cheklab bo‘lmaydi')
   c.execute('UPDATE users SET banned=1,ban_reason=? WHERE id=?',(r['category'],r['target']))
   c.execute('DELETE FROM sessions WHERE user_id=?',(r['target'],))
  if x.action=='hide_post':
   if not r['post_id']:raise HTTPException(400,'Shikoyat postga tegishli emas')
   c.execute('UPDATE posts SET hidden=1 WHERE id=?',(r['post_id'],))
  c.execute('UPDATE reports SET status=? WHERE id=?',(x.action,report_id))
  c.execute('INSERT INTO moderation_log(moderator,report_id,action,created) VALUES(?,?,?,?)',(u['id'],report_id,x.action,now()))
 return {'ok':True}
@app.get('/api/moderation/media/{report_id}')
def evidence_media(report_id:int,u=Depends(moderator)):
 with db() as c:r=c.execute('SELECT evidence FROM reports WHERE id=?',(report_id,)).fetchone()
 if not r:raise HTTPException(404,'Topilmadi')
 url=json.loads(r['evidence']).get('post',{}).get('media_url','')
 if not re.fullmatch(r'/media/[a-f0-9]{36}\.(jpg|png|webp|mp4|webm)',url):raise HTTPException(404,'Media yo‘q')
 path=MEDIA/url.split('/')[-1]
 if not path.is_file():raise HTTPException(404,'Media o‘chirilgan')
 return FileResponse(path,headers={'Cache-Control':'no-store'})

class OwnerClaim(BaseModel):
 key:str=Field(min_length=32,max_length=256)
@app.post('/api/owner/claim')
def claim_owner(x:OwnerClaim,u=Depends(current_user)):
 rate_limit('owner:'+str(u['id']),5,3600)
 expected=os.getenv('TONA_OWNER_KEY','')
 if len(expected)<32 or u['username']!=os.getenv('TONA_OWNER_USERNAME','nosirkhon') or not hmac.compare_digest(x.key,expected):
  raise HTTPException(403,'Egaga tegishli kalit noto‘g‘ri yoki hali sozlanmagan')
 with db() as c:c.execute('UPDATE users SET is_moderator=1 WHERE id=?',(u['id'],))
 return {'ok':True}


class MessageEdit(BaseModel):
 body:str=Field(min_length=1,max_length=4000)

@app.patch('/api/messages/item/{mid}')
async def edit_message(mid:int,x:MessageEdit,u=Depends(current_user)):
 if not x.body.strip():raise HTTPException(400,'Xabar bo‘sh bo‘lishi mumkin emas')
 rate_limit('message_edit:'+str(u['id']),120,60)
 with db() as c:
  row=c.execute('SELECT * FROM messages WHERE id=? AND sender=? AND deleted_at IS NULL',(mid,u['id'])).fetchone()
  if not row or not is_friend(c,u['id'],row['recipient']):raise HTTPException(404,'Message unavailable')
  c.execute('UPDATE messages SET body=?,edited_at=? WHERE id=?',(x.body,now(),mid))
  result=dict(c.execute('SELECT * FROM messages WHERE id=?',(mid,)).fetchone())
 for uid in (result['sender'],result['recipient']):await broadcast(uid,{'type':'message','message':result})
 with db() as c:return private_receipt(c,result)

@app.delete('/api/messages/item/{mid}')
async def delete_message(mid:int,u=Depends(current_user)):
 with db() as c:
  row=c.execute('SELECT * FROM messages WHERE id=? AND sender=?',(mid,u['id'])).fetchone()
  if not row:raise HTTPException(404,'Message unavailable')
  # Remove message text; retain a tombstone so replies and synchronization remain coherent.
  c.execute("UPDATE messages SET body='',deleted_at=COALESCE(deleted_at,?) WHERE id=?",(now(),mid))
  result=dict(c.execute('SELECT * FROM messages WHERE id=?',(mid,)).fetchone())
 for uid in (result['sender'],result['recipient']):await broadcast(uid,{'type':'message','message':result})
 return {'ok':True}

class ReadMessages(BaseModel):
 through_id:int=Field(ge=1)

@app.post('/api/messages/{other}/read')
async def read_messages(other:int,x:ReadMessages,u=Depends(current_user)):
 with db() as c:
  if not is_friend(c,u['id'],other):raise HTTPException(403,'Only accepted friends can chat')
  seen=c.execute('SELECT 1 FROM messages WHERE id=? AND sender=? AND recipient=?',(x.through_id,other,u['id'])).fetchone()
  if not seen:raise HTTPException(404,'Message unavailable')
  if not receipts_allowed(c,u['id'],other):return {'ok':True}
  stamp=now();changed=c.execute('UPDATE messages SET read_at=? WHERE sender=? AND recipient=? AND id<=? AND read_at IS NULL AND deleted_at IS NULL',(stamp,other,u['id'],x.through_id)).rowcount
 if changed:await broadcast(other,{'type':'read','reader':u['id'],'read_at':stamp})
 return {'ok':True}

@app.get('/api/saved')
def saved_notes(before:int|None=Query(default=None,ge=1),u=Depends(current_user)):
 with db() as c:return [dict(r) for r in c.execute('SELECT id,body,created,updated FROM saved_notes WHERE owner=? AND (? IS NULL OR id<?) ORDER BY id DESC LIMIT 100',(u['id'],before,before))]

@app.post('/api/saved')
def create_note(x:MessageEdit,u=Depends(current_user)):
 if not x.body.strip():raise HTTPException(400,'Xabar bo‘sh bo‘lishi mumkin emas')
 rate_limit('notes:'+str(u['id']),120,60)
 with db() as c:
  cur=c.execute('INSERT INTO saved_notes(owner,body,created,updated) VALUES(?,?,?,?)',(u['id'],x.body,now(),now()))
  return {'id':cur.lastrowid,'ok':True}

@app.delete('/api/saved/{nid}')
def delete_note(nid:int,u=Depends(current_user)):
 with db() as c:
  cur=c.execute('DELETE FROM saved_notes WHERE id=? AND owner=?',(nid,u['id']))
  if not cur.rowcount:raise HTTPException(404,'Not found')
 return {'ok':True}

class LanguagePreference(BaseModel):
 language:Literal['uz','en','ru','tr','kk','ar','zh-CN','hi','es','fr']

@app.patch('/api/preferences/language')
def language_preference(x:LanguagePreference,u=Depends(current_user)):
 with db() as c:c.execute('UPDATE users SET language=? WHERE id=?',(x.language,u['id']))
 return {'ok':True}

@app.get('/api/account/export')
def export_account(u=Depends(current_user)):
 rate_limit('export:'+str(u['id']),3,3600)
 with db() as c:
  data={'format':'tona-account-export-v1','exported_at':now(),'account':me(u),
   'messages':[dict(r) for r in c.execute('SELECT * FROM messages WHERE sender=? OR recipient=? ORDER BY id',(u['id'],u['id']))],
   'saved_notes':[dict(r) for r in c.execute('SELECT id,body,created,updated FROM saved_notes WHERE owner=? ORDER BY id',(u['id'],))],
   'contacts':[dict(r) for r in c.execute('SELECT a,b,status,requester FROM friendships WHERE a=? OR b=?',(u['id'],u['id']))],
   'posts':[dict(r) for r in c.execute('SELECT id,kind,media_url,caption,created,expires FROM posts WHERE user_id=?',(u['id'],))],
   'reports':[dict(r) for r in c.execute('SELECT id,category,details,status,created FROM reports WHERE reporter=?',(u['id'],))]}
 with db() as c:data['messages']=[private_receipt(c,m) for m in data['messages']]
 return JSONResponse(data,headers={'Content-Disposition':f'attachment; filename="tona-account-{u["id"]}.json"','Cache-Control':'no-store'})


@app.post('/api/messages/media/{other}')
async def send_chat_media(other:int,file:UploadFile=File(...),kind:Literal['video','audio','round','gif']=Form(...),u=Depends(current_user)):
 rate_limit('chatmedia:'+str(u['id']),30,3600)
 with db() as c:
  if not is_friend(c,u['id'],other):raise HTTPException(403,'Only accepted friends can chat')
 with db() as c:
  if c.execute("SELECT count(*) FROM messages WHERE sender=? AND attachment!=''",(u['id'],)).fetchone()[0]>=100:raise HTTPException(429,'Media storage limit')
 formats={'video/mp4':'.mp4','video/webm':'.webm','audio/webm':'.webm','audio/ogg':'.ogg','audio/mpeg':'.mp3','audio/mp4':'.m4a','audio/wav':'.wav','audio/x-wav':'.wav','image/gif':'.gif'}
 mime=(file.content_type or '').split(';')[0]
 if mime not in formats or (kind=='gif' and mime!='image/gif') or (kind in ('video','round') and not mime.startswith('video/')) or (kind=='audio' and not mime.startswith('audio/')):raise HTTPException(415,'Unsupported media format')
 data=await file.read(25*1024*1024+1)
 if len(data)>25*1024*1024:raise HTTPException(413,'25 MB upload limit')
 ext=formats[mime];head=data[:32]
 valid={'.mp4':head[4:8]==b'ftyp','.m4a':head[4:8]==b'ftyp','.webm':head.startswith(bytes.fromhex('1a45dfa3')),'.ogg':head.startswith(b'OggS'),'.mp3':head.startswith(b'ID3') or (len(head)>1 and head[0]==255 and head[1]&224==224),'.wav':head[:4]==b'RIFF' and head[8:12]==b'WAVE','.gif':head[:6] in (b'GIF87a',b'GIF89a')}.get(ext,False)
 if not valid:raise HTTPException(415,'Unsupported media format')
 filename=secrets.token_hex(18)+ext;path=MEDIA/filename
 try:
  path.write_bytes(data)
  if ext=='.gif':
   with Image.open(path) as im:
    if im.width*im.height>16000000 or getattr(im,'n_frames',1)>500:raise ValueError()
    im.verify()
  with db() as c:
   if not is_friend(c,u['id'],other):raise HTTPException(403,'Only accepted friends can chat')
   cur=c.execute('INSERT INTO messages(sender,recipient,body,created,attachment,attachment_kind) VALUES(?,?,?,?,?,?)',(u['id'],other,'',now(),filename,kind))
   msg=dict(c.execute('SELECT * FROM messages WHERE id=?',(cur.lastrowid,)).fetchone())
 except HTTPException:
  path.unlink(missing_ok=True);raise
 except Exception:
  path.unlink(missing_ok=True);raise HTTPException(415,'Unsupported media format')
 await broadcast(other,{'type':'message','message':msg});await broadcast(u['id'],{'type':'message','message':msg})
 with db() as c:return private_receipt(c,msg)

@app.get('/api/messages/media/file/{mid}')
def chat_media_file(mid:int,u=Depends(current_user)):
 with db() as c:
  m=c.execute('SELECT * FROM messages WHERE id=? AND deleted_at IS NULL',(mid,)).fetchone()
  if not m or u['id'] not in (m['sender'],m['recipient']) or not is_friend(c,m['sender'],m['recipient']) or not m['attachment']:raise HTTPException(404,'Message unavailable')
  path=MEDIA/m['attachment']
  if not path.is_file():raise HTTPException(404,'Message unavailable')
 return FileResponse(path,headers={'Cache-Control':'private, no-store','X-Content-Type-Options':'nosniff'})


@app.get('/manifest.webmanifest')
def install_manifest():return FileResponse((BASE/'pwa' if (BASE/'pwa').is_dir() else BASE)/'manifest.webmanifest',media_type='application/manifest+json',headers={'Cache-Control':'no-cache'})

@app.get('/sw.js')
def install_worker():return FileResponse((BASE/'pwa' if (BASE/'pwa').is_dir() else BASE)/'sw.js',media_type='application/javascript',headers={'Cache-Control':'no-cache','Service-Worker-Allowed':'/'})

@app.get('/install')
def installation_page():return FileResponse((BASE/'pwa' if (BASE/'pwa').is_dir() else BASE)/'install.html',headers={'Cache-Control':'no-cache'})

@app.get('/pwa/{asset}')
def installation_asset(asset:str):
 if asset not in {'icon-180.png','icon-192.png','icon-512.png','install.js','install.css'}:raise HTTPException(404)
 return FileResponse((BASE/'pwa' if (BASE/'pwa').is_dir() else BASE)/asset,headers={'Cache-Control':'no-cache'})


class PhoneCode(BaseModel):
 phone:str=Field(max_length=25)
 code:str=Field(pattern=r'^[0-9]{6}$')

def normalized_phone(value):
 value=re.sub(r'[\s()-]','',value)
 if not re.fullmatch(r'\+[1-9]\d{7,14}',value):raise HTTPException(400,'Xalqaro telefon raqamini kiriting: +998...')
 return value

@app.post('/api/auth/phone/request')
def request_phone_code(x:VerificationRequest,request:Request):
 return request_code(VerificationRequest(contact=normalized_phone(x.contact)),request)

@app.post('/api/auth/phone/verify')
def phone_login(x:PhoneCode,request:Request,response:Response):
 phone=normalized_phone(x.phone)
 rate_limit('phone-login-ip:'+request.client.host,30,600)
 rate_limit('phone-login:'+phone,5,600)
 verify_code(phone,x.code)
 with db() as c:
  identity=c.execute('SELECT users.* FROM verified_phones JOIN users ON users.id=verified_phones.user_id WHERE phone=?',(phone,)).fetchone()
  if identity:
   if identity['banned']:raise HTTPException(403,'Akkaunt cheklangan')
   uid=identity['id']
  else:
   # Never attach an unverified legacy phone account just because its text matches.
   if c.execute('SELECT 1 FROM users WHERE contact=?',(phone,)).fetchone():raise HTTPException(409,'Eski akkauntga parol bilan kiring va Sozlamalarda telefonni tasdiqlang.')
   try:
    cur=c.execute('INSERT INTO users(username,contact,password_hash,created) VALUES(?,?,?,?)',('tona_'+secrets.token_hex(6),phone,'!',now()))
    uid=cur.lastrowid
    c.execute('INSERT INTO verified_phones VALUES(?,?,?)',(phone,uid,now()))
   except sqlite3.IntegrityError:raise HTTPException(409,'Qayta urinib ko‘ring')
  token=issue_token(c,uid)
 set_session(response,request,token)
 return {'ok':True}

@app.post('/api/account/phone/verify')
def link_legacy_phone(x:PhoneCode,request:Request,u=Depends(current_user)):
 phone=normalized_phone(x.phone)
 if phone!=u['contact']:raise HTTPException(400,'Faqat akkauntingizdagi eski telefonni tasdiqlang')
 rate_limit('phone-link:'+str(u['id']),5,600)
 verify_code(phone,x.code)
 with db() as c:
  try:c.execute('INSERT INTO verified_phones VALUES(?,?,?)',(phone,u['id'],now()))
  except sqlite3.IntegrityError:raise HTTPException(409,'Telefon allaqachon ulangan')
 return {'ok':True}

@app.post('/api/account/email/request')
def request_account_email(x:VerificationRequest,request:Request,u=Depends(current_user)):
 email=normalize_contact(x.contact)
 if email.startswith('+'):raise HTTPException(400,'Email manzilini kiriting')
 rate_limit('email-link:'+str(u['id']),5,3600)
 result=request_code(VerificationRequest(contact=email),request)
 with db() as c:c.execute('INSERT OR REPLACE INTO pending_emails VALUES(?,?,?)',(u['id'],email,now()))
 return result

class EmailCode(BaseModel):
 code:str=Field(pattern=r'^[0-9]{6}$')
@app.post('/api/account/email/verify')
def link_account_email(x:EmailCode,u=Depends(current_user)):
 rate_limit('email-check:'+str(u['id']),5,600)
 with db() as c:pending=c.execute('SELECT * FROM pending_emails WHERE user_id=?',(u['id'],)).fetchone()
 if not pending or pending['created']<now()-600:raise HTTPException(400,'Avval email kodini so‘rang')
 verify_code(pending['email'],x.code)
 with db() as c:
  try:c.execute('INSERT INTO account_emails VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET email=excluded.email,verified_at=excluded.verified_at',(u['id'],pending['email'],now()))
  except sqlite3.IntegrityError:raise HTTPException(409,'Email boshqa akkauntga ulangan')
  c.execute('DELETE FROM pending_emails WHERE user_id=?',(u['id'],))
 return {'ok':True}

class EmailLoginCode(BaseModel):
 email:str=Field(max_length=254)
 code:str=Field(pattern=r'^[0-9]{6}$')

@app.post('/api/auth/email/request')
def request_email_login(x:VerificationRequest,request:Request):
 email=normalize_contact(x.contact)
 if email.startswith('+'):raise HTTPException(400,'Email manzilini kiriting')
 return request_code(VerificationRequest(contact=email),request)

@app.post('/api/auth/email/verify')
def email_login(x:EmailLoginCode,request:Request,response:Response):
 email=normalize_contact(x.email)
 if email.startswith('+'):raise HTTPException(400,'Email manzilini kiriting')
 rate_limit('email-login-ip:'+request.client.host,30,600)
 rate_limit('email-login:'+email,5,600)
 verify_code(email,x.code)
 with db() as c:
  identity=c.execute('SELECT users.* FROM account_emails JOIN users ON users.id=account_emails.user_id WHERE email=?',(email,)).fetchone()
  if identity:
   if identity['banned']:raise HTTPException(403,'Akkaunt cheklangan')
   uid=identity['id']
  else:
   if c.execute('SELECT 1 FROM users WHERE contact=?',(email,)).fetchone():raise HTTPException(409,'Eski akkauntga parol bilan kiring va profil ichida emailni tasdiqlang.')
   try:
    cur=c.execute('INSERT INTO users(username,contact,password_hash,created) VALUES(?,?,?,?)',('tona_'+secrets.token_hex(6),email,'!',now()))
    uid=cur.lastrowid;c.execute('INSERT INTO account_emails VALUES(?,?,?)',(uid,email,now()))
   except sqlite3.IntegrityError:raise HTTPException(409,'Qayta urinib ko‘ring')
  token=issue_token(c,uid)
 set_session(response,request,token)
 return {'ok':True}
