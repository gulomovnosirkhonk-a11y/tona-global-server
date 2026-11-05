"""Offline, non-destructive TONA backup/restore. Stop all writers first."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile


def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
 return h.hexdigest()


def validate(root):
 root=Path(root)
 if not (root/'tona.db').is_file():raise ValueError('tona.db missing')
 for path in root.rglob('*'):
  if path.is_symlink():raise ValueError('Symlinks are not allowed')
 with sqlite3.connect((root/'tona.db').as_uri()+'?mode=ro',uri=True) as c:
  if c.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise ValueError('Database integrity check failed')
  if not c.execute("SELECT 1 FROM sqlite_master WHERE name='users' AND type='table'").fetchone():raise ValueError('Not a TONA database')


def backup(source,destination):
 source=Path(source).resolve();destination=Path(destination).absolute()
 if destination.exists():raise ValueError('Destination already exists; nothing overwritten')
 if source==destination or source in destination.parents:raise ValueError('Backup destination must be outside source')
 validate(source)
 destination.parent.mkdir(parents=True,exist_ok=True)
 temp=Path(tempfile.mkdtemp(prefix='.tona-backup-',dir=destination.parent))
 try:
  with sqlite3.connect((source/'tona.db').as_uri()+'?mode=ro',uri=True) as src,sqlite3.connect(temp/'tona.db') as dst:src.backup(dst)
  if (source/'media').exists():shutil.copytree(source/'media',temp/'media')
  validate(temp)
  records={str(p.relative_to(temp)):digest(p) for p in temp.rglob('*') if p.is_file()}
  (temp/'backup-manifest.json').write_text(json.dumps({'format':1,'files':records},indent=2))
  for p in temp.rglob('*'):p.chmod(0o700 if p.is_dir() else 0o600)
  temp.chmod(0o700)
  # mkdir reservation prevents overwriting a concurrently created destination.
  destination.mkdir(mode=0o700)
  for p in temp.iterdir():shutil.move(str(p),str(destination/p.name))
 finally:shutil.rmtree(temp,ignore_errors=True)


def restore(source,destination):
 source=Path(source).resolve();destination=Path(destination).absolute()
 if destination.exists():raise ValueError('Restore destination must not exist')
 validate(source)
 manifest=json.loads((source/'backup-manifest.json').read_text())
 if manifest.get('format')!=1:raise ValueError('Unknown backup format')
 actual={str(p.relative_to(source)):digest(p) for p in source.rglob('*') if p.is_file() and p.name!='backup-manifest.json'}
 if actual!=manifest['files']:raise ValueError('Backup files changed or missing')
 backup(source,destination)


if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('action',choices=['backup','restore'])
 parser.add_argument('source');parser.add_argument('destination')
 parser.add_argument('--writers-stopped',action='store_true',help='Confirm app and all media/database writers are stopped')
 args=parser.parse_args()
 if not args.writers_stopped:parser.error('Stop the app and every writer, then pass --writers-stopped')
 (backup if args.action=='backup' else restore)(args.source,args.destination)
 print('Completed. Keep this private backup outside the application filesystem.')
