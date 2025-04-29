#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : AloneMonkey (modified to support PID attach fallback)
# blog: www.alonemonkey.com

from __future__ import print_function, unicode_literals
import sys
import codecs
import frida
import threading
import os
import shutil
import time
import argparse
import tempfile
import subprocess
import re
import paramiko
from paramiko import SSHClient
from scp import SCPClient
from tqdm import tqdm
import traceback

IS_PY2 = sys.version_info[0] < 3
if IS_PY2:
    reload(sys)
    sys.setdefaultencoding('utf8')

script_dir = os.path.dirname(os.path.realpath(__file__))

DUMP_JS = os.path.join(script_dir, 'dump.js')

User = 'root'
Password = 'alpine'
Host = 'localhost'
Port = 2222
KeyFileName = None

TEMP_DIR = tempfile.gettempdir()
PAYLOAD_DIR = 'Payload'
PAYLOAD_PATH = os.path.join(TEMP_DIR, PAYLOAD_DIR)
file_dict = {}

finished = threading.Event()


def get_usb_iphone():
    Type = 'usb'
    if int(frida.__version__.split('.')[0]) < 12:
        Type = 'tether'
    device_manager = frida.get_device_manager()
    changed = threading.Event()

    def on_changed():
        changed.set()

    device_manager.on('changed', on_changed)

    device = None
    while device is None:
        devices = [dev for dev in device_manager.enumerate_devices() if dev.type == Type]
        if len(devices) == 0:
            print('Waiting for USB device...')
            changed.wait()
        else:
            device = devices[0]

    device_manager.off('changed', on_changed)
    return device


def generate_ipa(path, display_name):
    ipa_filename = display_name + '.ipa'
    print('Generating "{}"'.format(ipa_filename))
    try:
        app_name = file_dict['app']
        for key, value in file_dict.items():
            from_dir = os.path.join(path, key)
            to_dir = os.path.join(path, app_name, value)
            if key != 'app':
                shutil.move(from_dir, to_dir)
        target_dir = './' + PAYLOAD_DIR
        zip_args = ('zip', '-qr', os.path.join(os.getcwd(), ipa_filename), target_dir)
        subprocess.check_call(zip_args, cwd=TEMP_DIR)
        shutil.rmtree(PAYLOAD_PATH)
    except Exception as e:
        print(e)
        finished.set()


def on_message(message, data):
    t = tqdm(unit='B', unit_scale=True, unit_divisor=1024, miniters=1)
    last_sent = [0]

    def progress(filename, size, sent):
        baseName = os.path.basename(filename)
        if IS_PY2 or isinstance(baseName, bytes):
            t.desc = baseName.decode('utf-8')
        else:
            t.desc = baseName
        t.total = size
        t.update(sent - last_sent[0])
        last_sent[0] = 0 if size == sent else sent

    if 'payload' in message:
        payload = message['payload']
        if 'dump' in payload:
            origin_path = payload['path']
            dump_path = payload['dump']
            scp_from = dump_path
            scp_to = PAYLOAD_PATH + '/'
            with SCPClient(ssh.get_transport(), progress=progress, socket_timeout=60) as scp:
                scp.get(scp_from, scp_to)
            chmod_dir = os.path.join(PAYLOAD_PATH, os.path.basename(dump_path))
            subprocess.call(('chmod', '655', chmod_dir))
            index = origin_path.find('.app/')
            file_dict[os.path.basename(dump_path)] = origin_path[index + 5:]
        if 'app' in payload:
            app_path = payload['app']
            scp_from = app_path
            scp_to = PAYLOAD_PATH + '/'
            with SCPClient(ssh.get_transport(), progress=progress, socket_timeout=60) as scp:
                scp.get(scp_from, scp_to, recursive=True)
            chmod_dir = os.path.join(PAYLOAD_PATH, os.path.basename(app_path))
            subprocess.call(('chmod', '755', chmod_dir))
            file_dict['app'] = os.path.basename(app_path)
        if 'done' in payload:
            finished.set()
    t.close()


def compare_applications(a, b):
    a_is_running = a.pid != 0
    b_is_running = b.pid != 0
    if a_is_running == b_is_running:
        return (a.name > b.name) - (a.name < b.name)
    return -1 if a_is_running else 1


def cmp_to_key(mycmp):
    class K:
        def __init__(self, obj): self.obj = obj
        def __lt__(self, other): return mycmp(self.obj, other.obj) < 0
        def __gt__(self, other): return mycmp(self.obj, other.obj) > 0
        def __eq__(self, other): return mycmp(self.obj, other.obj) == 0
        def __le__(self, other): return mycmp(self.obj, other.obj) <= 0
        def __ge__(self, other): return mycmp(self.obj, other.obj) >= 0
        def __ne__(self, other): return mycmp(self.obj, other.obj) != 0
    return K


def get_applications(device):
    try:
        return device.enumerate_applications()
    except Exception as e:
        sys.exit(f'Failed to enumerate applications: {e}')


def list_applications(device):
    apps = get_applications(device)
    pid_w = max((len(str(a.pid)) for a in apps), default=0)
    name_w = max((len(a.name) for a in apps), default=0)
    id_w = max((len(a.identifier) for a in apps), default=0)
    print(f"{'PID':>{pid_w}}  {'Name':<{name_w}}  {'Identifier':<{id_w}}")
    print(f"{'-'*pid_w}  {'-'*name_w}  {'-'*id_w}")
    for app in sorted(apps, key=cmp_to_key(compare_applications)):
        pid_s = '-' if app.pid == 0 else str(app.pid)
        print(f"{pid_s:>{pid_w}}  {app.name:<{name_w}}  {app.identifier:<{id_w}}")


def load_js_file(session, filename):
    with codecs.open(filename, 'r', 'utf-8') as f:
        source = f.read()
    script = session.create_script(source)
    script.on('message', on_message)
    script.load()
    return script


def create_dir(path):
    if os.path.exists(path): shutil.rmtree(path)
    os.makedirs(path, exist_ok=True)


def open_target_app(device, name_or_bundleid):
    print(f"Start or attach to target '{name_or_bundleid}'")
    session = None
    pid = None
    display_name = ''
    bundle_identifier = ''

    # PID fallback
    if name_or_bundleid.isdigit():
        pid = int(name_or_bundleid)
        try:
            session = device.attach(pid)
            print(f"  attached by PID = {pid}")
            return session, str(pid), None
        except Exception as e:
            print(f"  ❌ failed to attach to PID {pid}: {e}")
            sys.exit(1)

    # find running app
    for app in get_applications(device):
        if name_or_bundleid in (app.identifier, app.name):
            pid = app.pid
            display_name = app.name
            bundle_identifier = app.identifier
            break

    # spawn if not running
    if not pid and bundle_identifier:
        try:
            pid = device.spawn([bundle_identifier])
            print(f"  spawned, pid = {pid}")
            session = device.attach(pid)
            device.resume(pid)
        except Exception as e:
            print(f"  spawn failed: {e}")

    # attach if needed
    if not session and pid:
        try:
            print("  attaching to existing process…")
            session = device.attach(pid)
            print(f"  attached, pid = {session.pid}")
        except Exception as e:
            print(f"  attach failed: {e}")

    return session, display_name, bundle_identifier


def start_dump(session, ipa_name):
    print(f"Dumping {ipa_name} to {TEMP_DIR}")
    script = load_js_file(session, DUMP_JS)
    script.post('dump')
    finished.wait()
    generate_ipa(PAYLOAD_PATH, ipa_name)
    if session:
        session.detach()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='frida-ios-dump (modified with PID attach)')
    parser.add_argument('-l', '--list', action='store_true', dest='list_applications', help='List installed apps')
    parser.add_argument('-o', '--output', dest='output_ipa', help='Name of the decrypted IPA')
    parser.add_argument('-H', '--host', dest='ssh_host', help='SSH hostname')
    parser.add_argument('-p', '--port', dest='ssh_port', help='SSH port')
    parser.add_argument('-u', '--user', dest='ssh_user', help='SSH username')
    parser.add_argument('-P', '--password', dest='ssh_password', help='SSH password')
    parser.add_argument('-K', '--key_filename', dest='ssh_key_filename', help='SSH key file path')
    parser.add_argument('target', nargs='?', help='Bundle ID, app name, or PID of target')

    args = parser.parse_args()
    if not args.target and not args.list_applications:
        parser.print_help()
        sys.exit(0)

    # override SSH settings
    if args.ssh_host: Host = args.ssh_host
    if args.ssh_port: Port = int(args.ssh_port)
    if args.ssh_user: User = args.ssh_user
    if args.ssh_password: Password = args.ssh_password
    if args.ssh_key_filename: KeyFileName = args.ssh_key_filename

    device = get_usb_iphone()
    ssh = None
    exit_code = 0
    try:
        if args.list_applications:
            list_applications(device)
        else:
            ssh = SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(Host, port=Port, username=User, password=Password, key_filename=KeyFileName)
            create_dir(PAYLOAD_PATH)
            session, display_name, bundle_identifier = open_target_app(device, args.target)
            ipa_name = args.output_ipa or display_name or args.target
            start_dump(session, re.sub(r'\.ipa$', '', ipa_name))
    except paramiko.ssh_exception.NoValidConnectionsError as e:
        print(e)
        print('Try specifying -H/--host and/or -p/--port')
        exit_code = 1
    except paramiko.AuthenticationException as e:
        print(e)
        print('Try specifying -u/--user and/or -P/--password')
        exit_code = 1
    except Exception as e:
        print(f'*** Caught exception: {e.__class__.__name__}: {e}')
        traceback.print_exc()
        exit_code = 1
    finally:
        if ssh: ssh.close()
        if os.path.exists(PAYLOAD_PATH): shutil.rmtree(PAYLOAD_PATH)
        sys.exit(exit_code)
