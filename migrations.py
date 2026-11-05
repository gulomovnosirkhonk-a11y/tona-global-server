"""Additive, transactional migrations for existing TONA databases."""
import sqlite3
from pathlib import Path

def upgrade_base(connection):
 connection.execute('CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)')
 if connection.execute('SELECT 1 FROM schema_migrations WHERE version=1').fetchone():return
 for table,columns in {
  'users':{'language':"TEXT NOT NULL DEFAULT ''",'bio_visibility':"TEXT NOT NULL DEFAULT 'everyone'"},
  'messages':{'reply_to':'INTEGER REFERENCES messages(id)','edited_at':'INTEGER','deleted_at':'INTEGER','read_at':'INTEGER'}
 }.items():
  existing={row[1] for row in connection.execute('PRAGMA table_info('+table+')')}
  for name,definition in columns.items():
   if name not in existing:connection.execute(f'ALTER TABLE {table} ADD COLUMN {name} {definition}')
 connection.execute('CREATE TABLE IF NOT EXISTS saved_notes(id INTEGER PRIMARY KEY,owner INTEGER NOT NULL REFERENCES users(id),body TEXT NOT NULL,created INTEGER NOT NULL,updated INTEGER NOT NULL)')
 connection.execute('CREATE INDEX IF NOT EXISTS idx_saved_owner ON saved_notes(owner,id)')
 connection.execute('CREATE INDEX IF NOT EXISTS idx_message_recipient_read ON messages(recipient,sender,read_at)')
 connection.execute('INSERT INTO schema_migrations(version) VALUES(1)')

def migrate(path):
 with sqlite3.connect(Path(path)) as c:upgrade(c)


def upgrade(connection):
 upgrade_base(connection)
 if connection.execute('SELECT 1 FROM schema_migrations WHERE version=2').fetchone():return
 existing={row[1] for row in connection.execute('PRAGMA table_info(messages)')}
 for name in ('attachment','attachment_kind'):
  if name not in existing:connection.execute(f"ALTER TABLE messages ADD COLUMN {name} TEXT NOT NULL DEFAULT ''")
 connection.execute('INSERT INTO schema_migrations(version) VALUES(2)')
