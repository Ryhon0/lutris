"""The DiscordIPC class."""

import os
import platform
import re
import json
import struct
import socket
import uuid
import requests
import base64
from lutris.util.log import logger
from lutris import settings


class DiscordIPC(object):
    """Docstring for DiscordIPC."""

    def _get_discord_appid(self):
        appid = settings.read_setting("discord_appid")
        if appid: return appid
        else: return ""

    def _get_discord_token(self):
        token = settings.read_setting("discord_token")
        if token: return token
        else: return ""

    def _get_discord_enabled(self):
        enabled = settings.read_setting("discord_enabled")
        if enabled is None: return False
        else: return enabled

    def __init__(self):
        """Docstring for __init__."""
        super(DiscordIPC, self).__init__()

        # Your computer's platform.
        self.platform = self._get_platform()
        # The connection path to Discord IPC Socket.
        self.ipc_path = self._get_ipc_path()
        # Your Application's ID (a.k.a. Client ID).
        self.client_id = self._get_discord_appid()
        # The process ID of the running process.
        self.pid = os.getpid()
        # It's not connected to Discord Client at this point.
        self.connected = False
        # The User Activity that's to be sent to Discord Client.
        self.activity = None
        # The Discord IPC Socket.
        self.socket = None
        self.token = self._get_discord_token()

    def _get_platform(self):
        """Get the system's platformself."""
        system = platform.system().lower()
        # Supported Discord platforms are Linux, macOS (darwin) and Windows.
        if system in ['darwin', 'linux', 'windows']:
            return system
        else:
            raise Exception('Discord IPC doesn\'t support {0}.'.format(system))

    def _get_ipc_path(self, id=0):
        """Get the path to IPC Socket connection."""
        if self.platform == 'windows':
            # IPC path for Windows.
            return '\\\\?\\pipe\\discord-ipc-{0}'.format(id)
        else:
            # IPC path for unix based systems (Linux, macOS).
            path = os.environ.get('XDG_RUNTIME_DIR') or os.environ.get('TMPDIR') or os.environ.get('TMP') or os.environ.get('TEMP') or '/tmp'
            return re.sub(r'\/$', '', path) + '/discord-ipc-{0}'.format(id)

    def _encode(self, opcode, payload):
        """Encode the payload to send to the IPC Socket."""
        payload = json.dumps(payload)
        payload = payload.encode('utf-8')
        return struct.pack('<ii', opcode, len(payload)) + payload

    def _decode(self):
        """Decode the data received from Discord."""
        if self.platform == 'windows':
            encoded_header = b""
            header_size = 8

            while header_size:
                encoded_header += self.socket.read(header_size)
                header_size -= len(encoded_header)

            decoded_header = struct.unpack('<ii', encoded_header)
            encoded_data = b''
            remaining_packet_size = int(decoded_header[1])

            while remaining_packet_size:
                encoded_data += self.socket.read(remaining_packet_size)
                remaining_packet_size -= len(encoded_data)
        else:
            recived_data = self.socket.recv(1024)
            encoded_header = recived_data[:8]
            decoded_header = struct.unpack('<ii', encoded_header)
            encoded_data = recived_data[8:]

        return json.loads(encoded_data.decode('utf-8'))

    def _send(self, opcode, payload):
        """Send the payload to Discord via Discord IPC Socket."""
        encoded_payload = self._encode(opcode, payload)

        try:
            if self.platform == 'windows':
                self.socket.write(encoded_payload)
                self.socket.flush()
            else:
                self.socket.send(encoded_payload)
        except Exception:
            raise Exception('Can\'t send data to Discord via IPC.')

    def connect(self):
                """Connect to Discord Client via IPC."""
                if self.connected:
                    # Already Connected to the Discord Client.
                    pass
                else:
                    # Let's connect to Discord Client via Discord IPC Socket.
                    try:
                        if self.platform == 'windows':
                            self.socket = open(self.ipc_path, 'w+b')
                        else:
                            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                            self.socket.connect(self.ipc_path)
                    except Exception:
                        raise Exception('Can\'t connect to Discord Client.')

                    # Let's handshake with Discord...
                    self._send(0, {
                        'v': 1,
                        'client_id': self.client_id
                    })
                    # ...and see it's respond.
                    self._decode()

                    # Since it respond and we're connected
                    self.connected = True
                    # TODO: And if activity is defined, set it.
                    # if self.activity:
                    #     ipc.set_activity(self.activity)

    def disconnect(self):
        try:
            """Terminate connection to Discord IPC Socket."""
            # Let's let Discord know that we're going to disconnect.
            self._send(2, {})

            # Bye Discord!
            if self.platform != 'windows':
                self.socket.shutdown(socket.SHUT_RDWR)

            # See you soon!
            self.socket.close()
            self.socket = None
            # We are not connected to Discord anymore, so...
            self.connected = False
            self.activity = None
        except: logger.debug('Failed to disconnect from IPC')

    def update_activity(self, activity):
        """Update User's Discord activity."""
        payload = {
            'cmd': 'SET_ACTIVITY',
            'args': {
                'activity': activity,
                'pid': self.pid
                },
            'nonce': str(uuid.uuid4())
            }

        # Send activity data to Discord Client.
        self._send(1, payload)
        self._decode()
    
    def set_app_name(self, newname):
        url = 'https://discordapp.com/api/oauth2/applications/' + self.client_id
        payload = '{"name": "' + newname + '"}'
        headers = {'authorization': self.token, 'Content-Type': 'application/json'}
        r = requests.patch(url, payload, headers = headers)

    def getAssetList(self):
        url = 'https://discordapp.com/api/oauth2/applications/{}/assets'.format(str(self.client_id))
        headers = {'authorization': self.token, 'Content-Type': 'application/json'}
        r = requests.get(url, headers = headers)
        data = r.json()
        return data

    def addAsset(self, name, image):
        if os.path.isfile(image):
            with open(image, "rb") as image_file:
                encoded_string = base64.b64encode(image_file.read())
        else: encoded_string = base64.b64encode(requests.get('http://ryhon.ga/Files/lutris.png').content)
        url = 'https://discordapp.com/api/oauth2/applications/' + str(self.client_id) + '/assets'
        payload = '{"name": "' + str(name) + '", "type": "1", "image" : "data:image/png;base64,' + str(encoded_string)[2 : : ][:-1:] + '"}'
        headers = {'authorization': self.token, 'Content-Type': 'application/json'}
        r = requests.post(url, payload, headers = headers)
        data = r.json()

    def removeAsset(self, name):
        encoded_string = base64.b64encode(image)
        url = 'https://discordapp.com/api/oauth2/applications/' + str(self.client_id) + '/assets' + str(id)
        headers = {'authorization': self.token, 'Content-Type': 'application/json'}
        r = requests.delete(url, headers = headers)
        data = r.json()

    def doesAssetExists(self, AssetList, name):
        for i in AssetList:
            if str(i['name']) == str(name): return True
        return False
