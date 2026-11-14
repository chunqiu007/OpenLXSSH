#!/usr/bin/env python3
"""Offline R3 observer/drain regressions. No subprocess, relay, server or network execution."""
import copy
import json
import types
import unittest
from unittest.mock import patch

from diagnostics import (RelayCommandRefused, classify_relay_observations, collect_failed_close,
                         safe_refusal)
from relay_native import load_original
from relay_observations import MAX_RECORDS, RelayObservations, STAGES, TAG
from supervise_native import relay_query


class FakeClock:
    def __init__(self): self.now = 100.0
    def __call__(self): return self.now


class R3DiagnosticsTests(unittest.TestCase):
    def test_all_observers_call_original_once_with_same_arguments_and_result(self):
        for name, stage in STAGES.items():
            output = []; clock = FakeClock(); observations = RelayObservations(clock=clock, write=output.append)
            marker = object(); argument = object(); calls = []
            def original(*args, **kwargs):
                calls.append((args, kwargs)); clock.now += .25; return marker
            wrapped = observations.wrap(original, stage)
            self.assertIs(wrapped(argument, key=argument), marker)
            self.assertEqual(calls, [((argument,), {'key': argument})])
            events = [json.loads(raw) for raw in output]
            self.assertEqual([item['event'] for item in events], ['begin', 'end'])
            self.assertTrue(all(item['stage'] == stage and item['tag'] == TAG for item in events))
            self.assertEqual(events[-1]['elapsed'], .25)
            self.assertTrue(all(set(item) == {'tag', 'sequence', 'stage', 'event', 'at', 'elapsed'} for item in events))

    def test_all_observers_preserve_exception_identity_and_no_arbitrary_text(self):
        for name, stage in STAGES.items():
            output = []; exception = RuntimeError('not-safe-for-log'); calls = []
            def original(*args, **kwargs): calls.append(1); raise exception
            with self.assertRaises(RuntimeError) as captured:
                RelayObservations(write=output.append).wrap(original, stage)(object())
            self.assertIs(captured.exception, exception); self.assertEqual(calls, [1])
            self.assertEqual(json.loads(output[-1])['event'], 'error')
            self.assertNotIn(b'not-safe-for-log', b''.join(output))
            self.assertEqual(classify_relay_observations(b''.join(output)), stage + '-error')

    def test_observer_output_failure_bound_and_lock_never_change_original(self):
        marker = object()
        def bad_write(_): raise OSError('disk unavailable')
        observations = RelayObservations(write=bad_write)
        self.assertIs(observations.wrap(lambda: marker, 'tcp-state')(), marker)
        output = []; observations = RelayObservations(write=output.append)
        for _ in range(MAX_RECORDS): observations.wrap(lambda: marker, 'tcp-state')()
        self.assertEqual(len(output), MAX_RECORDS)
        self.assertLessEqual(sum(map(len, output)), MAX_RECORDS * 512)
        observations.lock.acquire()
        try: self.assertIs(observations.wrap(lambda: marker, 'tcp-state')(), marker)
        finally: observations.lock.release()

    def test_install_restores_only_three_functions_and_core_methods_stay_identical(self):
        original = load_original()
        functions = {name: getattr(original, name) for name in STAGES}
        methods = {name: getattr(original.Relay, name) for name in ('__init__', 'worker', 'dispatch', 'serve')}
        drop = original.drop_pump; arm = original.Flow.arm
        observations = RelayObservations(write=lambda _: None)
        try:
            observations.install(original)
            for name in STAGES: self.assertIsNot(getattr(original, name), functions[name])
            for name, method in methods.items(): self.assertIs(getattr(original.Relay, name), method)
            self.assertIs(original.drop_pump, drop); self.assertIs(original.Flow.arm, arm)
        finally: observations.restore()
        for name, function in functions.items(): self.assertIs(getattr(original, name), function)

    def test_relay_refusal_saves_exact_static_reply_and_clock_before_throw(self):
        for failure in ('worker-control-refused', 'closed-management-refusal'):
            raw = {'ok': False, 'failure': failure}
            reader = types.SimpleNamespace(read=lambda _: raw)
            with patch('supervise_native.send') as send, patch('supervise_native.time.monotonic', side_effect=[1.0, 1.2]):
                with self.assertRaises(RelayCommandRefused) as captured:
                    relay_query(object(), reader, {'op': 'arm'})
            self.assertEqual(captured.exception.observation, {'operation': 'arm', 'sentAt': 1.0, 'receivedAt': 1.2, 'response': raw})
            send.assert_called_once()
        self.assertEqual(safe_refusal({'ok': False, 'failure': 'arbitrary raw error', 'secret': 'not emitted'}),
                         {'ok': False, 'failure': 'unrecognized-safe-response-schema'})

    def frame(self, op, stamp, *, session='01234567-89ab-cdef-0123-456789abcdef'):
        return {'op': op, 'sequence': {'failed': -1, 'case-result': 2, 'closed': 3}[op], 'run': 'a' * 32,
                'role': 'blackhole', 'session': session, 'stamp': stamp,
                'report': {'taskID': 'NATIVE-LIVENESS-SUPERVISOR-R2', 'run': 'a' * 32, 'role': 'blackhole',
                           'session': session, 'failure': 'deadline', 'closed': op == 'closed'}}

    def drain(self, frames, clock=None):
        result = {'status': 'failed-retain-no-retry', 'failureStage': 'relay-arm'}
        queue = list(frames); calls = []
        def read(seconds):
            calls.append(seconds)
            if not queue: raise EOFError()
            return queue.pop(0)
        collect_failed_close(types.SimpleNamespace(read=read), run='a' * 32, role='blackhole',
            session='01234567-89ab-cdef-0123-456789abcdef', result=result, clock=clock or FakeClock())
        return result, calls

    def test_failure_drain_keeps_failed_and_following_closed_without_upgrading(self):
        result, calls = self.drain([self.frame('failed', 1), self.frame('closed', 2)])
        self.assertEqual(len(result['failureDrainFrames']), 2)
        self.assertTrue(result['closedReport']['closed'])
        self.assertEqual(result['failureDrainStage'], 'closed-observed')
        self.assertEqual(result['status'], 'failed-retain-no-retry'); self.assertEqual(len(calls), 2)
        self.assertTrue(all(seconds <= 15 for seconds in calls))

    def test_failure_drain_rejects_wrong_owner_replay_nonmonotonic_and_extra_schema(self):
        for changed in [dict(self.frame('closed', 2), session='11234567-89ab-cdef-0123-456789abcdef'),
                        dict(self.frame('closed', 2), run='b' * 32), dict(self.frame('closed', 2), sequence=True),
                        dict(self.frame('closed', 2), extra='forbidden')]:
            result, _ = self.drain([changed]); self.assertNotIn('closedReport', result)
        result, _ = self.drain([self.frame('failed', 2), self.frame('closed', 1)])
        self.assertNotIn('closedReport', result)
        result, _ = self.drain([self.frame('failed', 1), self.frame('failed', 2), self.frame('closed', 3)])
        self.assertNotIn('closedReport', result)
        changed = self.frame('closed', 2); changed['report']['secret'] = 'forbidden'
        result, _ = self.drain([changed]); self.assertNotIn('closedReport', result)

    def test_unknown_later_flow_failure_is_not_guessed_as_runtime_timeout(self):
        output = []; observation = RelayObservations(write=output.append)
        observation.wrap(lambda: object(), 'tcp-state')()
        self.assertEqual(classify_relay_observations(b''.join(output)), 'unknown-after-tcp-state')
        self.assertEqual(classify_relay_observations(b''), 'unknown')
        self.assertEqual(classify_relay_observations(b'{"extra":"not allowed"}\n'), 'unknown')

    def test_failure_drain_uses_one_fifteen_second_budget_not_per_frame(self):
        clock = FakeClock(); queue = [self.frame('failed', 1), self.frame('closed', 2)]; budgets = []
        def read(seconds):
            budgets.append(seconds); clock.now += 8
            return queue.pop(0)
        result = {'status': 'failed-retain-no-retry'}
        collect_failed_close(types.SimpleNamespace(read=read), run='a' * 32, role='blackhole',
            session='01234567-89ab-cdef-0123-456789abcdef', result=result, seconds=15, clock=clock)
        self.assertEqual(budgets, [15, 7])
        self.assertEqual(result['failureDrainStage'], 'deadline'); self.assertNotIn('closedReport', result)
        self.assertEqual(result['status'], 'failed-retain-no-retry')


if __name__ == '__main__': unittest.main()
