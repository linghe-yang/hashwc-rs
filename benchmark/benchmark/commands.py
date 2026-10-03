# Copyright(C) Facebook, Inc. and its affiliates.
# Commands use argument lists; no shell interpolation or feature-specific binaries.
import sys
from benchmark.utils import PathMaker


class CommandMaker:
    @staticmethod
    def compile(protocol='commoncoin'):
        if protocol != 'commoncoin':
            raise ValueError('Unsupported protocol')
        return ['cargo', 'build', '--release', '--locked', '-p', 'node']

    @staticmethod
    def generate_confs(policy, target):
        return [sys.executable, '-m', 'benchmark.config', '--policy', str(policy), '--target', str(target)]

    @staticmethod
    def run_primary(keys, parameters, debug=False):
        return [str(PathMaker.binary_path() / 'node')] + (['-v'] if debug else []) + [
            'run', '--config', str(keys), '--parameters', str(parameters), '--synchronize']

    @staticmethod
    def check_config(keys, parameters):
        return [str(PathMaker.binary_path() / 'node'), 'check-config',
                '--config', str(keys), '--parameters', str(parameters)]

    @staticmethod
    def run_synchronizer(config, parameters, debug=False):
        return [str(PathMaker.binary_path() / 'node')] + (['-v'] if debug else []) + [
            'synchronizer', '--config', str(config), '--parameters', str(parameters)]
