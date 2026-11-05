"""Authorization and upgrade regressions for the incremental messenger milestone."""
import importlib.util
import json
import sqlite3
import uuid
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
import os, tempfile
os.environ.setdefault("TONA_DATA_DIR",tempfile.mkdtemp(prefix="tona-milestone-test-"))
import main
from migrations import upgrade

@pytest.fixture
def accounts():
 client=TestClient(main.app,client=('milestone-'+uuid.uuid4().hex,50001),headers={'X-Tona-Client':'web'})
 result=[]
 for prefix in ('sender','receiver','stranger'):
  name=prefix+'_'+uuid.uuid4().hex[:8]
  r=client.post('/api/register',json={'username':name,'contact':name+'@example.com','password':'milestone-password-123'})
  assert r.status_code==200,r.text
  result.append((r.json()['user']['id'],{'Authorization':'Bearer '+r.json()['token']}))
 a,ha=result[0];b,hb=result[1]
 assert client.post('/api/friends/request',headers=ha,json={'user_id':b}).status_code==200
 assert client.post(f'/api/friends/{a}/accept',headers=hb).status_code==200
 return client,result

def test_edit_reply_delete_authorization_and_sync(accounts):
 c,((a,ha),(b,hb),(z,hz))=accounts
 first=c.post('/api/messages',headers=ha,json={'recipient':b,'body':'Original 🌍'}).json()
 unrelated=c.post('/api/messages',headers=ha,json={'recipient':b,'body':'Another'}).json()
 assert c.patch(f'/api/messages/item/{first["id"]}',headers=hb,json={'body':'forged'}).status_code==404
 assert c.delete(f'/api/messages/item/{first["id"]}',headers=hz).status_code==404
 with c.websocket_connect('/ws') as ws:
  ws.send_json({'token':hb['Authorization'][7:]})
  r=c.patch(f'/api/messages/item/{first["id"]}',headers=ha,json={'body':'Edited 🌍'})
  assert r.status_code==200 and r.json()['edited_at']
  assert ws.receive_json()['message']['body']=='Edited 🌍'
 reply=c.post('/api/messages',headers=hb,json={'recipient':a,'body':'Reply','reply_to':first['id']})
 assert reply.status_code==200 and reply.json()['reply_to']==first['id']
 # A third-party conversation is never a valid quote source.
 c.post('/api/friends/request',headers=ha,json={'user_id':z});c.post(f'/api/friends/{a}/accept',headers=hz)
 private=c.post('/api/messages',headers=ha,json={'recipient':z,'body':'Private'}).json()
 assert c.post('/api/messages',headers=hb,json={'recipient':a,'body':'Leak','reply_to':private['id']}).status_code==404
 assert c.delete(f'/api/messages/item/{first["id"]}',headers=ha).status_code==200
 rows=c.get(f'/api/messages/{a}',headers=hb).json()
 deleted=next(x for x in rows if x['id']==first['id'])
 assert deleted['body']=='' and deleted['deleted_at']
 assert c.patch(f'/api/messages/item/{first["id"]}',headers=ha,json={'body':'resurrect'}).status_code==404
 assert c.post('/api/messages',headers=hb,json={'recipient':a,'body':'Reply again','reply_to':first['id']}).status_code==404

def test_reads_search_pagination_and_removed_contact(accounts):
 c,((a,ha),(b,hb),(z,hz))=accounts
 rows=[c.post('/api/messages',headers=ha,json={'recipient':b,'body':text}).json() for text in ['alpha','beta','alphabet']]
 assert c.post(f'/api/messages/{a}/read',headers=hz,json={'through_id':rows[-1]['id']}).status_code==403
 assert c.post(f'/api/messages/{a}/read',headers=hb,json={'through_id':rows[0]['id']}).status_code==200
 history=c.get(f'/api/messages/{b}',headers=ha).json()
 assert history[0]['read_at'] and history[-1]['read_at'] is None
 found=c.get(f'/api/messages/{a}',headers=hb,params={'q':'alpha'}).json()
 assert [x['body'] for x in found]==['alpha','alphabet']
 older=c.get(f'/api/messages/{a}',headers=hb,params={'before':rows[-1]['id'],'limit':1}).json()
 assert len(older)==1 and older[0]['body']=='beta'
 assert c.get(f'/api/messages/{a}',headers=hb,params={'limit':101}).status_code==422
 c.delete(f'/api/friends/{b}',headers=ha)
 assert c.get(f'/api/messages/{a}',headers=hb).status_code==403
 assert c.patch(f'/api/messages/item/{rows[-1]["id"]}',headers=ha,json={'body':'new'}).status_code==404
 # Sender can still erase their own original message after removal.
 assert c.delete(f'/api/messages/item/{rows[-1]["id"]}',headers=ha).status_code==200

def test_notes_preferences_bio_privacy_export(accounts):
 c,((a,ha),(b,hb),(z,hz))=accounts
 note=c.post('/api/saved',headers=ha,json={'body':'Personal note العربية'}).json()
 assert c.get('/api/saved',headers=hb).json()==[]
 assert c.delete('/api/saved/'+str(note['id']),headers=hb).status_code==404
 assert c.patch('/api/preferences/language',headers=ha,json={'language':'ar'}).status_code==200
 assert c.get('/api/me',headers=ha).json()['language']=='ar'
 assert c.patch('/api/preferences/language',headers=ha,json={'language':'unknown'}).status_code==422
 c.patch('/api/profile',headers=ha,json={'bio':'Private biography','display_name':'Profile'})
 c.patch('/api/settings',headers=ha,json={'bio_visibility':'contacts'})
 assert c.get(f'/api/profile/{a}',headers=hb).json()['bio']=='Private biography'
 assert c.get(f'/api/profile/{a}',headers=hz).json()['bio']==''
 c.patch('/api/settings',headers=ha,json={'bio_visibility':'nobody'})
 assert c.get(f'/api/profile/{a}',headers=hb).json()['bio']==''
 assert next(x for x in c.get('/api/friends',headers=hb).json() if x['id']==a)['bio']==''
 assert c.get('/api/me',headers=ha).json()['bio']=='Private biography'
 c.post('/api/messages',headers=ha,json={'recipient':b,'body':'Export this'})
 exported=c.get('/api/account/export',headers=ha)
 assert exported.status_code==200 and exported.headers['cache-control']=='no-store'
 assert 'attachment;' in exported.headers['content-disposition']
 data=exported.json();serialized=json.dumps(data)
 assert data['saved_notes'][0]['body']=='Personal note العربية'
 assert data['messages'][0]['body']=='Export this'
 for forbidden in ['password_hash','token_hash','milestone-password-123',hb['Authorization'][7:]]:assert forbidden not in serialized
 assert TestClient(main.app).get('/api/account/export').status_code==401
 assert c.delete('/api/saved/'+str(note['id']),headers=ha).status_code==200
 assert c.get('/api/saved',headers=ha).json()==[]

def test_additive_migration_keeps_legacy_data_and_is_idempotent(tmp_path):
 path=tmp_path/'old.db'
 with sqlite3.connect(path) as c:
  c.execute('CREATE TABLE users(id INTEGER PRIMARY KEY,username TEXT)')
  c.execute('CREATE TABLE messages(id INTEGER PRIMARY KEY,sender INTEGER,recipient INTEGER,body TEXT,created INTEGER)')
  c.execute("INSERT INTO users VALUES(7,'existing')")
  c.execute("INSERT INTO messages VALUES(9,7,8,'Keep me',100)")
  upgrade(c);upgrade(c)
  assert c.execute('SELECT body FROM messages WHERE id=9').fetchone()[0]=='Keep me'
  assert c.execute('SELECT username,language,bio_visibility FROM users WHERE id=7').fetchone()==('existing','','everyone')
  assert c.execute('SELECT count(*) FROM schema_migrations').fetchone()[0]==2


def test_read_receipts_are_idempotent_and_settings_patch_preserves_values(accounts,monkeypatch):
 c,((a,ha),(b,hb),_)=accounts
 events=[]
 async def capture(uid,event):events.append((uid,event))
 monkeypatch.setattr(main,'broadcast',capture)
 msg=c.post('/api/messages',headers=ha,json={'recipient':b,'body':'Read once'}).json()
 events.clear()
 for _ in range(2):assert c.post(f'/api/messages/{a}/read',headers=hb,json={'through_id':msg['id']}).status_code==200
 assert len(events)==1 and events[0][1]['type']=='read'
 assert c.patch('/api/settings',headers=ha,json={'theme':'dark','discoverable':False}).status_code==200
 assert c.patch('/api/settings',headers=ha,json={'bio_visibility':'nobody'}).status_code==200
 me=c.get('/api/me',headers=ha).json()
 assert me['theme']=='dark' and not me['discoverable']

@pytest.mark.parametrize('kind,mime,data',[('video','video/mp4',b'\0\0\0\x18ftypmp42'+b'0'*40),('round','video/webm',bytes.fromhex('1a45dfa3')+b'0'*40),('audio','audio/wav',b'RIFF\x24\0\0\0WAVEfmt '+b'0'*40),('gif','image/gif',__import__('base64').b64decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7'))])
def test_chat_media_privacy_delete_and_block(accounts,kind,mime,data):
 c,((a,ha),(b,hb),(z,hz))=accounts
 assert c.post(f'/api/messages/media/{z}',headers=ha,data={'kind':kind},files={'file':('media',data,mime)}).status_code==403
 r=c.post(f'/api/messages/media/{b}',headers=ha,data={'kind':kind},files={'file':('media',data,mime)})
 assert r.status_code==200,r.text
 m=r.json();url=f'/api/messages/media/file/{m["id"]}'
 assert c.get(url,headers=hb).content==data
 assert c.get(url,headers=hz).status_code==404
 assert c.get('/media/'+m['attachment'],headers=hb).status_code==404
 assert 'no-store' in c.get(url,headers=ha).headers['cache-control']
 assert c.post(f'/api/blocks/{a}',headers=hb).status_code==200
 assert c.get(url,headers=hb).status_code==404
 assert c.delete(f'/api/messages/item/{m["id"]}',headers=ha).status_code==200
 assert c.get(url,headers=ha).status_code==404

def test_invalid_media_does_not_create_message(accounts):
 c,((a,ha),(b,hb),_)=accounts
 for kind,mime,data in [('gif','image/gif',b'<script>alert(1)</script>'),('round','audio/mpeg',b'ID3fake')]:
  assert c.post(f'/api/messages/media/{b}',headers=ha,data={'kind':kind},files={'file':('bad',data,mime)}).status_code==415
 assert c.get(f'/api/messages/{b}',headers=ha).json()==[]


def test_recording_permissions_are_same_origin_only():
 r=TestClient(main.app).get('/')
 assert 'camera=(self)' in r.headers['permissions-policy']
 assert 'microphone=(self)' in r.headers['permissions-policy']
 assert "media-src 'self' blob:" in r.headers['content-security-policy']

def test_pwa_install_contract_and_assets():
 c=TestClient(main.app)
 m=c.get('/manifest.webmanifest')
 assert m.status_code==200 and 'application/manifest+json' in m.headers['content-type']
 manifest=m.json()
 assert manifest['start_url']=='/' and manifest['scope']=='/' and manifest['display']=='standalone'
 from PIL import Image
 import io
 for icon in manifest['icons']:
  image=c.get(icon['src']);assert image.status_code==200
  with Image.open(io.BytesIO(image.content)) as im:assert f'{im.width}x{im.height}'==icon['sizes']
 assert c.get('/install').status_code==200
 assert c.get('/pwa/main.py').status_code==404
 worker=c.get('/sw.js')
 assert worker.headers['service-worker-allowed']=='/'
 assert worker.headers['cache-control']=='no-cache'
 assert 'caches.open' not in worker.text and "['/', '/install']" in worker.text
 assert '/manifest.webmanifest' in c.get('/').text
