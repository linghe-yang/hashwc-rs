# Copyright(C) Facebook, Inc. and its affiliates.
# Adapted for the weighted common coin benchmark.
from pathlib import Path


class BenchError(Exception):
    def __init__(self, message, error=None):
        self.message = message
        self.cause = error
        super().__init__(message if error is None else '{}: {}'.format(message, error))


class PathMaker:
    ROOT = Path(__file__).resolve().parents[2]
    BENCHMARK = ROOT / 'benchmark'

    @staticmethod
    def binary_path():
        return PathMaker.ROOT / 'target' / 'release'

    @staticmethod
    def node_crate_path():
        return PathMaker.ROOT

    @staticmethod
    def parameters_file():
        return '.parameters.json'

    @staticmethod
    def key_file(i):
        return '.node-{}.json'.format(i)

    @staticmethod
    def logs_path():
        return PathMaker.BENCHMARK / 'logs'

    @staticmethod
    def primary_log_file(i):
        return Path('logs') / 'primary-{}.log'.format(i)

    @staticmethod
    def results_path():
        return PathMaker.BENCHMARK / 'results'

    @staticmethod
    def result_file(protocol, faults, nodes):
        return '{}-{}-{}.txt'.format(protocol, faults, nodes)


class Print:
    @staticmethod
    def heading(message):
        print(message, flush=True)

    @staticmethod
    def info(message):
        print(message, flush=True)

    @staticmethod
    def warn(message):
        print('WARN: {}'.format(message), flush=True)

    @staticmethod
    def error(error):
        print('ERROR: {}'.format(error), flush=True)
