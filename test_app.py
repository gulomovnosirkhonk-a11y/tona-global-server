import os,tempfile,hashlib
os.environ['TONA_DATA_DIR']=tempfile.mkdtemp(prefix='tona-test-')
from fastapi.testclient import TestClient
import main
client=TestClient(main.app)
def register(name):
 contact=name+'@example.com'
 with main.db() as c:c.execute('INSERT OR REPLACE INTO verification VALUES(?,?,?,0)',(contact,hashlib.sha256(b'123456').hexdigest(),main.now()+600))
 r=client.post('/api/register',json=dict(username=name,contact=contact,password='test-password-123',code='123456'))
 assert r.status_code==200,r.text
 return r.json(),{'Authorization':'Bearer '+r.json()['token']}
def test_private_chat_and_reels():
 a,ha=register('alice');b,hb=register('bob');c,hc=register('carol')
 ai=a['user']['id'];bi=b['user']['id']
 assert client.post('/api/messages',headers=ha,json={'recipient':bi,'body':'Hello'}).status_code==403
 assert client.post('/api/friends/request',headers=ha,json={'user_id':bi}).status_code==200
 assert client.post(f'/api/friends/{bi}/accept',headers=ha).status_code==404
 assert client.post(f'/api/friends/{ai}/accept',headers=hb).status_code==200
 with client.websocket_connect('/ws') as ws:
  ws.send_json({'token':b['token']})
  sent=client.post('/api/messages',headers=ha,json={'recipient':bi,'body':'Salom!'});assert sent.status_code==200
  assert ws.receive_json()['message']['body']=='Salom!'
 assert client.get(f'/api/messages/{ai}',headers=hb).json()[0]['body']=='Salom!'
 assert client.get(f'/api/messages/{ai}',headers=hc).status_code==403
 assert client.post('/api/messages',headers=ha,json={'recipient':bi,'body':'   '}).status_code==400
 upload=client.post('/api/upload',headers=ha,files={'file':('clip.mp4',b'test-private-video','video/mp4')})
 url=upload.json()['media_url']
 assert client.post('/api/posts',headers=hb,json={'kind':'reel','media_url':url}).status_code==403
 post=client.post('/api/posts',headers=ha,json={'kind':'reel','media_url':url,'caption':'Only friends'});assert post.status_code==200
 assert len(client.get('/api/feed',headers=hb).json())==1
 assert client.get('/api/feed',headers=hc).json()==[]
 assert client.get(url).status_code==401
 assert client.get(url,headers=hc).status_code==403
 assert client.get(url,headers=hb).status_code==200
 assert client.delete(f'/api/friends/{bi}',headers=ha).status_code==200
 assert client.get(url,headers=hb).status_code==403
 assert client.get('/api/feed',headers=hb).json()==[]
 assert client.delete('/api/posts/'+str(post.json()['id']),headers=ha).status_code==200
 assert client.get(url,headers=ha).status_code==404
 assert client.post('/api/logout',headers=ha).status_code==200
 assert client.get('/api/me',headers=ha).status_code==401

def test_bad_code_and_no_provider(monkeypatch):
 monkeypatch.setattr(main,'REQUIRE_VERIFICATION',True)
 assert client.post('/api/register',json=dict(username='invalid',contact='invalid@example.com',password='test-password-123',code='000000')).status_code==400
 assert client.post('/api/auth/request-code',json={'contact':'nobody@example.com'}).status_code==503
 assert client.post('/api/auth/request-code',json={'contact':'+998901234567'}).status_code==503
 assert client.get('/healthz').json()=={'status':'ok'}

def test_password_signup_without_provider():
 r=client.post('/api/register',json=dict(username='delta',contact='+998901111111',password='test-password-123'))
 assert r.status_code==200,r.text
 r=client.post('/api/login',json=dict(contact='+998901111111',password='test-password-123'))
 assert r.status_code==200
 assert client.get('/api/config').json()['verification_required'] is False
