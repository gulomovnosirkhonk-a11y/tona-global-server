from pathlib import Path
import sqlite3
import pytest
from backup import backup,restore


def sample(tmp_path):
 root=tmp_path/'source';root.mkdir();(root/'media').mkdir()
 with sqlite3.connect(root/'tona.db') as c:
  c.execute('CREATE TABLE users(id INTEGER PRIMARY KEY,name TEXT)');c.execute("INSERT INTO users VALUES(1,'Preserved')")
 (root/'media'/'clip.webm').write_bytes(b'private attachment')
 return root


def test_backup_restore_preserves_rows_and_media_without_overwrite(tmp_path):
 source=sample(tmp_path);saved=tmp_path/'backup';target=tmp_path/'restored'
 backup(source,saved);restore(saved,target)
 with sqlite3.connect(target/'tona.db') as c:assert c.execute('SELECT name FROM users').fetchone()[0]=='Preserved'
 assert (target/'media'/'clip.webm').read_bytes()==b'private attachment'
 with pytest.raises(ValueError):restore(saved,source)
 with pytest.raises(ValueError):backup(source,saved)
 with pytest.raises(ValueError):backup(source,source/'nested')


def test_restore_rejects_tampering_and_symlinks(tmp_path):
 source=sample(tmp_path);saved=tmp_path/'backup';backup(source,saved)
 (saved/'media'/'clip.webm').write_bytes(b'changed')
 with pytest.raises(ValueError):restore(saved,tmp_path/'target')
 assert not (tmp_path/'target').exists()
 (source/'media'/'link').symlink_to(source/'tona.db')
 with pytest.raises(ValueError):backup(source,tmp_path/'bad')
