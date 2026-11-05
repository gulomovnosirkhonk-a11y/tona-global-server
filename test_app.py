import os,tempfile,hashlib
os.environ['TONA_DATA_DIR']=tempfile.mkdtemp(prefix='tona-test-')
from fastapi.testclient import TestClient
import main
client=TestClient(main.app,headers={"X-Tona-Client":"web"})
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
 upload=client.post('/api/upload',headers=ha,files={'file':('clip.mp4',b'\x00\x00\x00\x18ftypmp42'+b'0'*30,'video/mp4')})
 url=upload.json()['media_url']
 assert client.post('/api/posts',headers=hb,json={'kind':'reel','media_url':url}).status_code==403
 post=client.post('/api/posts',headers=ha,json={'kind':'reel','media_url':url,'caption':'Only friends'});assert post.status_code==200
 assert len(client.get('/api/feed',headers=hb).json())==1
 assert client.get('/api/feed',headers=hc).json()==[]
 assert TestClient(main.app).get(url).status_code==401
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

def image_bytes():
 import io
 from PIL import Image
 b=io.BytesIO();Image.new('RGB',(32,32),'purple').save(b,format='PNG');return b.getvalue()

def test_profile_privacy_blocks_and_story_expiry():
 a,ha=register('eva');b,hb=register('felix');ai=a['user']['id'];bi=b['user']['id']
 assert client.patch('/api/profile',headers=ha,json={'display_name':'Eva','bio':'Hello <script>alert(1)</script>'}).status_code==200
 assert client.post('/api/profile/avatar',headers=ha,files={'file':('x.png',b'not an image','image/png')}).status_code==415
 assert client.post('/api/profile/avatar',headers=ha,files={'file':('x.png',image_bytes(),'image/png')}).status_code==200
 assert client.get(f'/api/avatar/{ai}',headers=hb).status_code==404
 assert client.post('/api/friends/request',headers=ha,json={'user_id':bi}).status_code==200
 assert client.post(f'/api/friends/{ai}/accept',headers=hb).status_code==200
 assert client.get(f'/api/avatar/{ai}',headers=hb).status_code==200
 profile=client.get(f'/api/profile/{ai}',headers=hb).json()
 assert profile['bio'].startswith('Hello') and 'contact' not in profile and 'password_hash' not in profile
 upload=client.post('/api/upload',headers=ha,files={'file':('image.png',image_bytes(),'image/png')}).json()
 post=client.post('/api/posts',headers=ha,json={'kind':'story','media_url':upload['media_url']}).json()
 assert len(client.get('/api/feed?kind=story',headers=hb).json())==1
 with main.db() as c:c.execute('UPDATE posts SET expires=? WHERE id=?',(main.now()-1,post['id']))
 assert client.get('/api/feed?kind=story',headers=hb).json()==[]
 assert client.get(upload['media_url'],headers=hb).status_code==404
 assert client.post(f'/api/blocks/{bi}',headers=ha).status_code==200
 assert client.get(f'/api/avatar/{ai}',headers=hb).status_code==404
 assert client.get(f'/api/profile/{ai}',headers=hb).status_code==404
 assert client.post('/api/messages',headers=hb,json={'recipient':ai,'body':'No'}).status_code==403
 assert client.post('/api/friends/request',headers=hb,json={'user_id':ai}).status_code==403
 assert client.delete(f'/api/blocks/{bi}',headers=ha).status_code==200
 assert client.get(f'/api/messages/{ai}',headers=hb).status_code==403
 assert client.patch('/api/settings',headers=ha,json={'discoverable':False,'allow_requests':False,'avatar_visibility':'nobody'}).status_code==200
 assert client.get('/api/users?q=eva',headers=hb).json()==[]
 assert client.post('/api/friends/request',headers=hb,json={'user_id':ai}).status_code==403

def test_cookie_csrf_sessions_and_password():
 local=TestClient(main.app,headers={'X-Tona-Client':'web'})
 r=local.post('/api/register',json={'username':'gina','contact':'gina@example.com','password':'testing-password'});assert r.status_code==200
 assert 'httponly' in r.headers['set-cookie'].lower()
 assert local.get('/api/me').status_code==200
 assert local.patch('/api/profile',headers={'Origin':'https://evil.test'},json={'bio':'bad'}).status_code==403
 unsafe=TestClient(main.app);unsafe.cookies.update(local.cookies)
 assert unsafe.patch('/api/profile',json={'bio':'bad'}).status_code==403
 other=TestClient(main.app,headers={'X-Tona-Client':'web'})
 other.post('/api/login',json={'contact':'gina@example.com','password':'testing-password'})
 assert len(local.get('/api/sessions').json())==2
 assert local.post('/api/password',json={'current_password':'wrong','new_password':'new-test-password'}).status_code==400
 assert local.post('/api/password',json={'current_password':'testing-password','new_password':'new-test-password'}).status_code==200
 assert other.get('/api/me').status_code==401
 assert local.get('/api/me').status_code==200
 assert 'password_hash' not in local.get('/api/me').json()
 assert local.get('/').headers['content-security-policy'].startswith("default-src 'self'")

def test_reports_and_owner_permissions(monkeypatch):
 owner,ho=register('nosirkhon');bad,hb=register('hank');oi=owner['user']['id'];bi=bad['user']['id']
 assert client.get('/api/moderation/reports',headers=ho).status_code==403
 monkeypatch.setenv('TONA_OWNER_KEY','testing-owner-key-'+'0'*32)
 assert client.post('/api/owner/claim',headers=hb,json={'key':'testing-owner-key-'+'0'*32}).status_code==403
 assert client.post('/api/owner/claim',headers=ho,json={'key':'testing-owner-key-'+'0'*32}).status_code==200
 assert client.get('/api/me',headers=ho).json()['is_admin']
 assert client.post('/api/friends/request',headers=ho,json={'user_id':bi}).status_code==200
 assert client.post(f'/api/friends/{oi}/accept',headers=hb).status_code==200
 msg=client.post('/api/messages',headers=hb,json={'recipient':oi,'body':'reported sample'}).json()
 report=client.post('/api/reports',headers=ho,json={'target':bi,'message_id':msg['id'],'category':'harassment','details':'Test report'})
 assert report.status_code==200
 assert client.post('/api/reports',headers=hb,json={'target':oi,'message_id':msg['id'],'category':'spam'}).status_code==403
 assert client.get('/api/moderation/reports',headers=hb).status_code==403
 assert client.post('/api/moderation/reports/'+str(report.json()['id']),headers=hb,json={'action':'ban'}).status_code==403
 assert client.post('/api/moderation/reports/'+str(report.json()['id']),headers=ho,json={'action':'ban'}).status_code==200
 assert client.get('/api/me',headers=hb).status_code==401
 assert client.post('/api/login',json={'contact':'hank@example.com','password':'test-password-123'}).status_code==403

def test_moderated_post_is_hidden_and_report_evidence_access():
 owner=client.post('/api/login',json={'contact':'nosirkhon@example.com','password':'test-password-123'}).json()
 user=client.post('/api/login',json={'contact':'gina@example.com','password':'new-test-password'}).json()
 ho={'Authorization':'Bearer '+owner['token']};hu={'Authorization':'Bearer '+user['token']}
 oi=owner['user']['id'];ui=user['user']['id']
 client.post('/api/friends/request',headers=ho,json={'user_id':ui})
 client.post(f'/api/friends/{oi}/accept',headers=hu)
 media=client.post('/api/upload',headers=hu,files={'file':('x.png',image_bytes(),'image/png')}).json()['media_url']
 post=client.post('/api/posts',headers=hu,json={'kind':'reel','media_url':media}).json()['id']
 r=client.post('/api/reports',headers=ho,json={'target':ui,'post_id':post,'category':'other'}).json()['id']
 assert client.get(f'/api/moderation/media/{r}',headers=hu).status_code==403
 assert client.get(f'/api/moderation/media/{r}',headers=ho).status_code==200
 assert client.post(f'/api/moderation/reports/{r}',headers=ho,json={'action':'hide_post'}).status_code==200
 assert client.get(media,headers=hu).status_code==404
 assert client.get(media,headers=ho).status_code==404
 assert all(p['id']!=post for p in client.get('/api/feed',headers=ho).json())

def test_global_phone_formats_and_multilingual_messages():
 # Each scenario gets an independent registration quota in the temporary test DB.
 with main.db() as c:c.execute("DELETE FROM rate_limits WHERE bucket='register:testclient'")
 for phone in ['+12025550123','+442079460123','+919876543210','+819012345678','+998901234567']:
  assert main.normalize_contact(phone)==phone
 a,ha=register('global_a');b,hb=register('global_b')
 ai=a['user']['id'];bi=b['user']['id']
 assert client.get('/api/me',headers=ha).json()['theme']=='dark'
 assert client.post('/api/friends/request',headers=ha,json={'user_id':bi}).status_code==200
 assert client.post(f'/api/friends/{ai}/accept',headers=hb).status_code==200
 body='Salom · Hello · Привет · مرحبًا · 你好 · नमस्ते 🌍'
 assert client.post('/api/messages',headers=ha,json={'recipient':bi,'body':body}).status_code==200
 assert client.get(f'/api/messages/{ai}',headers=hb).json()[0]['body']==body
 r=client.get('/i18n.js')
 assert r.status_code==200 and 'javascript' in r.headers['content-type']
 assert '<script src="/i18n.js?v=0.6.0" defer>' in client.get('/').text
 assert client.get('/app.js').headers['cache-control']=='no-cache, must-revalidate'
