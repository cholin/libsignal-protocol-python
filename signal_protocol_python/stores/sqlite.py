from ..cffi import ffi, lib, invoke
from ..keys import RatchetIdentityKeyPair
from ..buffer import Buffer
from copy import copy
import sqlite3
from contextlib import closing
from . import ProtocolStore, IdentityKeyStore, PreKeyStore, SignedPreKeyStore,\
              SenderKeyStore, SessionStore


class SqliteProtocolStore(ProtocolStore):

    def __init__(self, ctx, uri):
        super(SqliteProtocolStore, self).__init__(ctx, uri)

    def get_session_store(self):
        if not hasattr(self, 'session_store'):
            self.session_store = SqliteSessionStore(self.uri)
        return self.session_store

    def get_pre_key_store(self):
        if not hasattr(self, 'pre_key_store'):
            self.pre_key_store = SqlitePreKeyStore(self.uri)
        return self.pre_key_store

    def get_sender_key_store(self):
        if not hasattr(self, 'sender_key_store'):
            self.sender_key_store = SqliteSenderKeyStore(self.uri)
        return self.sender_key_store

    def get_signed_pre_key_store(self):
        if not hasattr(self, 'signed_pre_key_store'):
            self.signed_pre_key_store = SqliteSignedPreKeyStore(self.uri)
        return self.signed_pre_key_store

    def get_identity_key_store(self):
        if not hasattr(self, 'identity_key_store'):
            self.identity_key_store = SqliteIdentityKeyStore(self.ctx, self.uri)
        return self.identity_key_store


class SqliteIdentityKeyStore(IdentityKeyStore):
    def __init__(self, ctx, uri):
        super(IdentityKeyStore, self).__init__()
        self.ctx = ctx
        self.conn = sqlite3.connect(uri)

        with closing(self.conn.cursor()) as cur:
            cur.execute('''CREATE TABLE IF NOT EXISTS kv_store
             (key TEXT NOT NULL UNIQUE, value TEXT NOT NULL)''')
            cur.execute('''CREATE TABLE IF NOT EXISTS trusted_identities
             (address TEXT PRIMARY KEY, pub_key TEXT NOT NULL UNIQUE)''')
            self.conn.commit()

    def get_identity_key_pair(self, public_data, private_data):
        key = 'identity'
        with closing(self.conn.cursor()) as cur:
            cur.execute('SELECT value FROM kv_store WHERE key=?', (key,))
            serialized = cur.fetchone()
            if serialized is None:
                identity = RatchetIdentityKeyPair.generate(self.ctx)
                cur.execute('INSERT INTO kv_store VALUES (?, ?)',
                            (key, identity.serialize().hex()))
                self.conn.commit()
            else:
                buf = Buffer.fromhex(serialized[0])
                identity = RatchetIdentityKeyPair.deserialize(self.ctx, buf)

        invoke('ec_public_key_serialize', public_data, identity.public_key.ptr)
        invoke('ec_private_key_serialize', private_data,
               identity.private_key.ptr)

        return 0

    def get_local_registration_id(self, registration_id):
        key = 'reg_id'
        with closing(self.conn.cursor()) as cur:
            cur.execute('SELECT value FROM kv_store WHERE key=?', (key,))
            reg_id = cur.fetchone()
            if reg_id is None:
                invoke('signal_protocol_key_helper_generate_registration_id',
                       registration_id, 0, self.ctx.value)
                cur.execute('INSERT INTO kv_store VALUES (?, ?)',
                            (key, registration_id[0]))
                self.conn.commit()
            else:
                registration_id[0] = int(reg_id[0])

        return 0

    @staticmethod
    def get_key_for(address):
        name = ffi.buffer(address.name, address.name_len)[:]
        return b'%s-%d' % (name, address.device_id)

    def save_identity(self, address, key_data, key_len):
        with closing(self.conn.cursor()) as cur:
            cur.execute('INSERT OR REPLACE INTO trusted_identities (address, pub_key) VALUES (?, ?)',
                        (self.get_key_for(address),
                         Buffer.create(key_data, key_len).hex()))
            self.conn.commit()
        return 0

    def is_trusted_identity(self, address, key_data, key_len):
        with closing(self.conn.cursor()) as cur:
            cur.execute('SELECT pub_key FROM trusted_identities WHERE address=?',
                        (self.get_key_for(address),))
            pub_key = cur.fetchone()
            serialized = Buffer.create(key_data, key_len).hex()
            if pub_key is not None and pub_key[0] == serialized:
                return 1
        return 0


class SqlitePreKeyStore(PreKeyStore):
    def __init__(self, uri):
        super(SqlitePreKeyStore, self).__init__()
        self.conn = sqlite3.connect(uri)

        with closing(self.conn.cursor()) as cur:
            cur.execute('''CREATE TABLE IF NOT EXISTS pre_keys
             (id INTEGER PRIMARY KEY, record TEXT NOT NULL)''')
            self.conn.commit()

    def load_pre_key(self, record, pre_key_id):
        with closing(self.conn.cursor()) as cur:
            cur.execute('SELECT record FROM pre_keys WHERE id=?',
                        (pre_key_id,))
            serialized = cur.fetchone()
            if serialized is None:
                return lib.SG_ERR_INVALID_KEY_ID
            record[0] = Buffer.fromhex(serialized[0]).release()
        return lib.SG_SUCCESS

    def store_pre_key(self, pre_key_id, record, record_len):
        with closing(self.conn.cursor()) as cur:
            cur.execute('INSERT OR REPLACE INTO pre_keys (id, record) VALUES (?, ?)',
                        (pre_key_id, Buffer.create(record, record_len).hex()))
            self.conn.commit()
        return 1

    def contains_pre_key(self, pre_key_id):
        with closing(self.conn.cursor()) as cur:
            cur.execute('SELECT record FROM pre_keys WHERE id=?',
                        (pre_key_id,))
            serialized = cur.fetchone()
            if serialized is not None:
                return 1
        return 0

    def remove_pre_key(self, pre_key_id):
        try:
            cur = self.conn.cursor()
            cur.execute('DELETE FROM pre_keys WHERE id=?', (pre_key_id,))
            self.conn.commit()
            cur.close()
            return lib.SG_SUCCESS
        except sqlite3.Error:
            pass
        return 1

    def _get_all_pre_key_ids(self):
        with closing(self.conn.cursor()) as cur:
            cur.execute('SELECT id FROM pre_keys')
            rows = cur.fetchall()
            if rows is not None:
                return [row[0] for row in rows]
        return []

    def get_all_pre_key_ids(self):
        return [i for i in self._get_all_pre_key_ids() if i > 0]


class SqliteSignedPreKeyStore(SignedPreKeyStore, SqlitePreKeyStore):

    def load_signed_pre_key(self, record, signed_pre_key_id):
        return self.load_pre_key(record, -signed_pre_key_id)

    def store_signed_pre_key(self, signed_pre_key_id, record, record_len):
        return self.store_pre_key(-signed_pre_key_id, record, record_len)

    def contains_signed_pre_key(self, signed_pre_key_id):
        return self.contains_pre_key(-signed_pre_key_id)

    def remove_signed_pre_key(self, signed_pre_key_id):
        return self.remove_pre_key(-signed_pre_key_id)

    def get_all_signed_pre_key_ids(self):
        return [abs(i) for i in self._get_all_pre_key_ids() if i < 0]


class SqliteSenderKeyStore(SenderKeyStore):

    def __init__(self, uri):
        super(SqliteSenderKeyStore, self).__init__()

    def store_sender_key(self, sender_key_name, record, record_len,
                         user_record, user_record_len):
        raise NotImplementedError

    def load_sender_key(self, record, user_record, sender_key_name):
        raise NotImplementedError


def join_address(address):
    name = ffi.buffer(address.name, address.name_len)[:]
    return name + b'_' + bytes([address.device_id])


class SqliteSessionStore(SessionStore):

    def __init__(self, uri):
        super(SqliteSessionStore, self).__init__()

        self.conn = sqlite3.connect(uri)

        with closing(self.conn.cursor()) as cur:
            cur.execute('''CREATE TABLE IF NOT EXISTS sessions
             (address TEXT PRIMARY KEY, record TEXT NOT NULL, user TEXT)''')
            self.conn.commit()

    def load_session_func(self, record, user_record, address):
        with closing(self.conn.cursor()) as cur:
            key = join_address(address)
            cur.execute('SELECT record, user FROM sessions WHERE address=?',
                        (key,))
            serialized = cur.fetchone()
            if serialized is None:
                return 0
            record[0] = Buffer.fromhex(serialized[0]).release()
            # user_record[0] = Buffer.fromhex(serialized[1]).release()
        return 1

    def get_sub_device_sessions_func(self, sessions, name, name_len):
        raise NotImplementedError

    def store_session_func(self, address, record, record_len, user_record,
                           user_record_len):
        with closing(self.conn.cursor()) as cur:
            key = join_address(address)
            record_hex = Buffer.create(record, record_len).hex()
            # user_hex = Buffer.create(user_record, user_record_len).hex()
            cur.execute('INSERT OR REPLACE INTO sessions (address, record) VALUES (?, ?)',
                        (key, record_hex))
            self.conn.commit()
        return 0

    def contains_session_func(self, address):
        with closing(self.conn.cursor()) as cur:
            cur.execute('SELECT record, user FROM sessions WHERE address=?',
                        (join_address(address),))
            serialized = cur.fetchone()
            if serialized is not None:
                return 1
        return 0

    def delete_session_func(self, address):
        try:
            cur = self.conn.cursor()
            cur.execute('DELETE FROM sessions WHERE address=?',
                        (join_address(address),))
            self.conn.commit()
            cur.close()
            return 1
        except sqlite3.Error:
            pass
        return 0

    def delete_all_sessions_func(self, name, name_len):
        try:
            cur = self.conn.cursor()
            cur.execute('DELETE FROM sessions')
            self.conn.commit()
            cur.close()
            return 1
        except sqlite3.Error:
            pass
        return 0
