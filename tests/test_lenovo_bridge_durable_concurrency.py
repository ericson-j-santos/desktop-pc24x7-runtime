"""SQLite local: disputa de chave e retomada. Nao valida failover entre PCs."""
from __future__ import annotations

import importlib.util
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier

SOURCE = Path(__file__).resolve().parents[1] / 'scripts' / 'lenovo_inventory_api_bridge.py'
spec = importlib.util.spec_from_file_location('lenovo_bridge_concurrency', SOURCE)
bridge = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(bridge)
SHA = 'b038a770117e0d3d4d1297a3f4bec112ff68a744'
KEY = 'a' * 64


def test_two_independent_connections_reserve_once():
    gate = Barrier(2)
    with TemporaryDirectory() as tmp:
        dbpath = Path(tmp) / 'state.sqlite'

        def worker():
            with bridge.database(dbpath) as db:
                gate.wait(timeout=5)
                try:
                    return bridge.reserve(db, KEY, SHA, 'same-approved-request')
                except bridge.Blocked as exc:
                    return str(exc)

        with ThreadPoolExecutor(max_workers=2) as executor:
            f1 = executor.submit(worker)
            f2 = executor.submit(worker)
            results = [f1.result(timeout=10), f2.result(timeout=10)]
        assert sum(x is None for x in results) == 1
        assert results.count('reserved_or_unknown_outcome_needs_reconciliation') == 1
        with bridge.database(dbpath) as db:
            assert db.execute('SELECT COUNT(*) FROM dispatches').fetchone()[0] == 1


def test_crash_reopen_fails_closed_and_never_forgets_key():
    with TemporaryDirectory() as tmp:
        dbpath = Path(tmp) / 'state.sqlite'
        with bridge.database(dbpath) as db:
            assert bridge.reserve(db, KEY, SHA, 'approved-request') is None
        with bridge.database(dbpath) as db:
            try:
                bridge.reserve(db, KEY, SHA, 'approved-request')
            except bridge.Blocked as exc:
                assert str(exc) == 'reserved_or_unknown_outcome_needs_reconciliation'
            else:
                raise AssertionError('replay_did_not_block')
            assert db.execute('SELECT COUNT(*) FROM dispatches').fetchone()[0] == 1


def test_connection_is_explicitly_closed_after_context():
    """A transacao commitada nao basta: no Windows, o handle precisa fechar."""
    with TemporaryDirectory() as tmp:
        path = Path(tmp) / 'state.sqlite'
        with bridge.database(path) as db:
            bridge.reserve(db, KEY, SHA, 'approved-request')
        try:
            db.execute('SELECT COUNT(*) FROM dispatches')
        except sqlite3.ProgrammingError:
            pass
        else:
            raise AssertionError('sqlite_connection_was_not_closed')
        with bridge.database(path) as db2:
            assert db2.execute('SELECT COUNT(*) FROM dispatches').fetchone()[0] == 1
