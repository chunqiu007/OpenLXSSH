#!/usr/bin/env python3
"""Observational wrappers for three ORIGINAL relay module functions. No I/O on import.

Only fixed stage/event/monotonic timing is emitted on stderr. Original parameters, call
count, return value and exception object are untouched; no relay method/Flow/PIPE changes.
"""
import json
import os
import time
import threading

STAGES = {'remote_bridge_alive': 'remote-bridge-alive', 'tcp_state': 'tcp-state',
          'drain_pending_arm': 'drain-pending-arm'}
TAG = 'native-relay-observation-v1'
MAX_RECORDS = 128


class RelayObservations:
    def __init__(self, *, clock=time.monotonic, write=None):
        self.clock = clock
        self.write = write if write is not None else lambda raw: os.write(2, raw)
        self.count = 0
        self.lock = threading.Lock()
        self.originals = {}
        self.module = None

    def emit(self, stage, event, started, now):
        # Diagnostics must never replace an original result/exception or create arbitrary text.
        acquired = False
        try:
            # Never wait on diagnostics in a measured protocol path. Contention may drop a
            # record; classification then stays unknown rather than delaying the relay.
            acquired = self.lock.acquire(blocking=False)
            if not acquired or self.count >= MAX_RECORDS or stage not in STAGES.values() or event not in ('begin', 'end', 'error'): return
            record = {'tag': TAG, 'sequence': self.count, 'stage': stage, 'event': event,
                      'at': now, 'elapsed': max(0.0, now - started)}
            self.count += 1
            raw = (json.dumps(record, separators=(',', ':'), sort_keys=True, allow_nan=False) + '\n').encode()
            if len(raw) <= 512: self.write(raw)
        except Exception:
            pass
        finally:
            if acquired: self.lock.release()

    def wrap(self, function, stage):
        def observe(*args, **kwargs):
            try: started = self.clock()
            except Exception: started = 0.0
            self.emit(stage, 'begin', started, started)
            try:
                value = function(*args, **kwargs)
            except BaseException:
                try: now = self.clock()
                except Exception: now = started
                self.emit(stage, 'error', started, now)
                raise
            try: now = self.clock()
            except Exception: now = started
            self.emit(stage, 'end', started, now)
            return value
        return observe

    def install(self, module):
        if self.module is not None: raise ValueError('observation-already-installed')
        self.module = module
        for name, stage in STAGES.items():
            function = getattr(module, name)
            self.originals[name] = function
            setattr(module, name, self.wrap(function, stage))

    def restore(self):
        if self.module is None: return
        for name, function in self.originals.items(): setattr(self.module, name, function)
        self.originals.clear(); self.module = None
