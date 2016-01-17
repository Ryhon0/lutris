import os
from lutris import settings
from lutris.runners.runner import Runner


class ppsspp(Runner):
    human_name = "PPSSPP"
    description = "Sony PSP emulator"
    platform = "Sony PSP"
    game_options = [
        {
            'option': 'main_file',
            'type': 'file',
            'label': 'ISO file',
            'default_path': 'game_path'
        }
    ]

    runner_options = [
        {
            'option': 'fullscreen',
            'type': 'bool',
            'label': 'Fullscreen',
            'default': False,
        }
    ]

    def get_executable(self):
        return os.path.join(settings.RUNNER_DIR, 'ppsspp/PPSSPPSDL')

    def play(self):
        arguments = [self.get_executable()]

        if self.runner_config.get('fullscreen'):
            arguments.append('--fullscreen')

        iso = self.game_config.get('main_file') or ''
        if not os.path.exists(iso):
            return {'error': 'FILE_NOT_FOUND', 'file': iso}
        arguments.append(iso)
        return {'command': arguments}