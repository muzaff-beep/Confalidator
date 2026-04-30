#!/usr/bin/env python3
"""
Config Validator for NapsternetV — Pylon-Forged
Part 1: Threaded Scanner + Performance-Tuned App Skeleton
"""

# --- Performance Configurations (MUST be before any Kivy import) ---
from kivy.config import Config
Config.set('graphics', 'maxfps', '30')
Config.set('graphics', 'multisamples', '0')

import sys
import socket
import ssl
import time
import base64
import re
import threading
from urllib.parse import urlparse
from urllib.request import urlopen, Request

from kivy.app import App
from kivy.clock import Clock
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.progressbar import ProgressBar
from kivy.uix.scrollview import ScrollView
from kivy.uix.filechooser import FileChooserListView
from kivy.properties import StringProperty, NumericProperty, BooleanProperty

# --- Constants ---
TIMEOUT = 5  # seconds per test
USER_AGENT = 'Pylon-Validator/2.0'

# --- Validator Core (unchanged logic, adapted for threading) ---
def parse_uri(uri):
    """Extract host, port, scheme from a proxy URI."""
    uri = uri.strip()
    if not uri:
        return None, None, None
    match = re.match(r'(vmess|vless|ss|trojan|socks5?)://', uri.lower())
    if match:
        scheme = match.group(1)
        if scheme == 'vmess':
            try:
                b64part = uri.split('://')[1]
                decoded = base64.b64decode(b64part + '==').decode('utf-8')
                import json
                cfg = json.loads(decoded)
                return cfg.get('add'), int(cfg.get('port', 443)), scheme
            except:
                return None, None, None
        elif scheme in ('vless', 'ss', 'trojan'):
            try:
                parsed = urlparse(uri)
                host = parsed.hostname
                port = parsed.port or (443 if scheme in ('vless','trojan') else 8388)
                return host, port, scheme
            except:
                return None, None, None
        elif scheme.startswith('socks'):
            try:
                parsed = urlparse(uri)
                host = parsed.hostname
                port = parsed.port or 1080
                return host, port, scheme
            except:
                return None, None, None
    else:
        parts = uri.split(':')
        if len(parts) == 2:
            try:
                host = parts[0].strip()
                port = int(parts[1].strip())
                return host, port, 'unknown'
            except:
                pass
    return None, None, None

def tcp_ping(host, port, timeout=TIMEOUT):
    """Return latency in ms or None."""
    try:
        start = time.time()
        sock = socket.create_connection((host, port), timeout=timeout)
        latency = (time.time() - start) * 1000
        sock.close()
        return round(latency, 1)
    except:
        return None

def tls_test(host, port, timeout=TIMEOUT):
    """Attempt TLS handshake, return latency or None."""
    try:
        start = time.time()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((host, port), timeout=timeout)
        with context.wrap_socket(sock, server_hostname=host) as tls_sock:
            latency = (time.time() - start) * 1000
        return round(latency, 1)
    except:
        return None

def fetch_subscription(url):
    """Fetch a subscription link, return list of URIs."""
    try:
        req = Request(url, headers={'User-Agent': USER_AGENT})
        with urlopen(req, timeout=TIMEOUT) as resp:
            data = resp.read()
        try:
            decoded = base64.b64decode(data).decode('utf-8')
        except:
            decoded = data.decode('utf-8')
        return [line.strip() for line in decoded.split('\n') if line.strip()]
    except Exception as e:
        return []

# --- Threaded Scanner ---
class ScanWorker(threading.Thread):
    """Runs the validator in a background thread, updating progress via callbacks."""

    def __init__(self, configs, update_ui_callback, finished_callback):
        super().__init__(daemon=True)
        self.configs = configs
        self.update_ui = update_ui_callback
        self.finished = finished_callback
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def run(self):
        working = []
        total = len(self.configs)
        for i, raw in enumerate(self.configs):
            if self._stop_event.is_set():
                break
            host, port, scheme = parse_uri(raw)
            if host is None:
                Clock.schedule_once(lambda dt, idx=i, r=raw: self.update_ui(idx, 'SKIP', None, r, 'Invalid syntax', total), 0)
                continue
            latency = tcp_ping(host, port)
            if latency is None:
                Clock.schedule_once(lambda dt, idx=i, h=host, p=port, r=raw: self.update_ui(idx, 'DEAD', None, r, f'TCP {h}:{p}', total), 0)
                continue
            tls_lat = None
            if port == 443 or scheme in ('vless', 'trojan', 'vmess'):
                tls_lat = tls_test(host, port)
            status = 'ALIVE'
            detail = f'TCP {latency}ms'
            if tls_lat:
                status = 'ALIVE (TLS)'
                detail = f'TLS {tls_lat}ms'
            working.append(raw)
            Clock.schedule_once(lambda dt, idx=i, h=host, p=port, r=raw, st=status, det=detail: self.update_ui(idx, st, (h, p), r, det, total), 0)
        Clock.schedule_once(lambda dt: self.finished(working), 0)

# --- App Skeleton ---
class ValidatorLayout(BoxLayout):
    status_text = StringProperty('Select a config file and tap Validate.')
    progress_value = NumericProperty(0)
    progress_max = NumericProperty(100)
    btn_disabled = BooleanProperty(False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.worker = None

    def validate_file(self):
        selected = self.ids.file_chooser.selection
        if not selected:
            self.status_text = '[color=#ff4444]No file selected.[/color]'
            return
        filepath = selected[0]
        try:
            with open(filepath, 'r') as f:
                lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            self.status_text = f'[color=#ff4444]Error reading file: {e}[/color]'
            return

        configs = []
        for line in lines:
            if re.match(r'https?://', line.lower()):
                configs.extend(fetch_subscription(line))
            else:
                configs.append(line)

        if not configs:
            self.status_text = '[color=#ff4444]No valid configs found in file.[/color]'
            return

        self.progress_max = len(configs)
        self.progress_value = 0
        self.btn_disabled = True
        self.status_text = f'Testing 0/{len(configs)}...'

        self.worker = ScanWorker(configs, self.update_progress, self.scan_finished)
        self.worker.start()

    def update_progress(self, index, status, addr, raw, detail, total):
        self.progress_value = index + 1
        host = addr[0] if addr else 'N/A'
        port = addr[1] if addr else 'N/A'
        color = '#44ff44' if 'ALIVE' in status else '#ff4444'
        line = f'[color={color}][{status}][/color] {host}:{port} — {detail}'
        self.status_text = f'Testing {index+1}/{total}...\n{line}'
        # Accumulate log in a hidden buffer for final export (implementation in Part 2)
        if not hasattr(self, '_log_buffer'):
            self._log_buffer = []
        self._log_buffer.append((status, raw))

    def scan_finished(self, working):
        self.progress_value = self.progress_max
        self.btn_disabled = False
        alive_count = len(working)
        total = int(self.progress_max)
        self.status_text = f'[b]Done.[/b] {alive_count}/{total} configs alive.'
        # Store working configs for export
        self._working = working

    def stop_scan(self):
        if self.worker and self.worker.is_alive():
            self.worker.stop()
            self.status_text = '[color=#ffaa44]Scan stopped by user.[/color]'
            self.btn_disabled = False

class ValidatorApp(App):
    def build(self):
        # Dark theme via global styling (KV will apply most)
        from kivy.core.window import Window
        Window.clearcolor = (0.12, 0.12, 0.12, 1)
        return ValidatorLayout()

if __name__ == '__main__':
    ValidatorApp().run()

# Part 2 of 2: KV Layout + Enhanced UI Logic
# Merge this block with the end of Part 1, inside the same file, replacing the
# placeholder class bodies and adding the new methods.

from kivy.lang import Builder

KV = '''
<ValidatorLayout>:
    orientation: 'vertical'
    padding: 10
    spacing: 6
    canvas.before:
        Color:
            rgba: 0.12, 0.12, 0.12, 1
        Rectangle:
            pos: self.pos
            size: self.size

    FileChooserListView:
        id: file_chooser
        path: '/storage/emulated/0/Download'
        size_hint_y: 0.45
        color: 0.9, 0.9, 0.9, 1
        background_color: 0.08, 0.08, 0.08, 1

    BoxLayout:
        size_hint_y: 0.08
        spacing: 5
        Button:
            id: btn_validate
            text: 'Validate'
            on_press: root.validate_file()
            disabled: root.btn_disabled
            background_color: 0.2, 0.6, 0.2, 1
            color: 1, 1, 1, 1
        Button:
            id: btn_stop
            text: 'Stop'
            on_press: root.stop_scan()
            disabled: not root.btn_disabled
            background_color: 0.8, 0.2, 0.2, 1
            color: 1, 1, 1, 1
        Button:
            id: btn_export
            text: 'Export'
            on_press: root.export_working()
            disabled: root.btn_disabled
            background_color: 0.2, 0.2, 0.6, 1
            color: 1, 1, 1, 1

    ProgressBar:
        id: progress_bar
        max: root.progress_max
        value: root.progress_value
        size_hint_y: 0.03
        background_color: 0.05, 0.05, 0.05, 1
        color: 0.2, 0.8, 0.2, 1

    ScrollView:
        size_hint_y: 0.44
        canvas.before:
            Color:
                rgba: 0.05, 0.05, 0.05, 1
            Rectangle:
                pos: self.pos
                size: self.size
        Label:
            id: log_label
            size_hint_y: None
            height: max(self.texture_size[1], self.parent.height)
            text: root.status_text
            markup: True
            color: 0.9, 0.9, 0.9, 1
            font_name: 'RobotoMono-Regular.ttf'
            padding: 6, 6
'''

class ValidatorLayout(BoxLayout):
    status_text = StringProperty('Select a config file and tap Validate.')
    progress_value = NumericProperty(0)
    progress_max = NumericProperty(100)
    btn_disabled = BooleanProperty(False)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._log_lines = []         # accumulate full log
        self._working = []           # alive configs
        self.worker = None
        self._input_file = None

    def validate_file(self):
        selected = self.ids.file_chooser.selection
        if not selected:
            self.status_text = '[color=#ff4444]No file selected.[/color]'
            return
        self._input_file = filepath = selected[0]
        try:
            with open(filepath, 'r') as f:
                lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            self.status_text = f'[color=#ff4444]Error reading file: {e}[/color]'
            return

        configs = []
        for line in lines:
            if re.match(r'https?://', line.lower()):
                configs.extend(fetch_subscription(line))
            else:
                configs.append(line)

        if not configs:
            self.status_text = '[color=#ff4444]No valid configs found in file.[/color]'
            return

        self.progress_max = len(configs)
        self.progress_value = 0
        self.btn_disabled = True
        self._log_lines = []
        self._working = []
        self.status_text = f'Starting scan of {len(configs)} configs...'
        self.ids.log_label.text = ''

        self.worker = ScanWorker(configs, self.update_progress, self.scan_finished)
        self.worker.start()

    def update_progress(self, index, status, addr, raw, detail, total):
        self.progress_value = index + 1
        host = addr[0] if addr else 'N/A'
        port = addr[1] if addr else 'N/A'
        color = '#44ff44' if 'ALIVE' in status else '#ff4444'
        line = f'[color={color}][{status}][/color] {host}:{port} — {detail}'
        self._log_lines.append(line)
        # Keep log text crisp without rebuilding all on every line (join only)
        self.ids.log_label.text = '\n'.join(self._log_lines)
        self.status_text = f'Testing {index+1}/{total}...'

    def scan_finished(self, working):
        self.progress_value = self.progress_max
        self.btn_disabled = False
        alive_count = len(working)
        total = int(self.progress_max)
        self._working = working
        self.status_text = f'[b]Done.[/b] {alive_count}/{total} configs alive.'
        # Append summary to log
        summary = f'\n[color=#aaaaaa]--- Scan finished, {alive_count} working ---[/color]'
        self._log_lines.append(summary)
        self.ids.log_label.text = '\n'.join(self._log_lines)

    def stop_scan(self):
        if self.worker and self.worker.is_alive():
            self.worker.stop()
            self.status_text = '[color=#ffaa44]Scan stopped by user.[/color]'
            self._log_lines.append('[color=#ffaa44]--- Scan aborted ---[/color]')
            self.ids.log_label.text = '\n'.join(self._log_lines)
            self.btn_disabled = False

    def export_working(self):
        if not self._working:
            self.status_text = '[color=#ffaa44]Nothing to export.[/color]'
            return
        if not self._input_file:
            self.status_text = '[color=#ffaa44]No input file reference.[/color]'
            return
        out_path = self._input_file + '.alive.txt'
        try:
            with open(out_path, 'w') as f:
                f.write('\n'.join(self._working))
            self.status_text = f'[color=#44ff44]Saved {len(self._working)} configs to {out_path}[/color]'
            # Optional: share via Android intent
            self._share_file(out_path)
        except Exception as e:
            self.status_text = f'[color=#ff4444]Export error: {e}[/color]'

    def _share_file(self, filepath):
        """Attempt to share the file using Android's intent system."""
        try:
            from jnius import autoclass, cast
            PythonActivity = autoclass('org.kivy.android.PythonActivity')
            Intent = autoclass('android.content.Intent')
            File = autoclass('java.io.File')
            Uri = autoclass('android.net.Uri')
            Context = autoclass('android.content.Context')
            FileProvider = autoclass('android.support.v4.content.FileProvider')

            activity = PythonActivity.mActivity
            file_obj = File(filepath)
            if not file_obj.exists():
                return
            uri = FileProvider.getUriForFile(activity, activity.getPackageName() + '.provider', file_obj)
            intent = Intent()
            intent.setAction(Intent.ACTION_SEND)
            intent.setType('text/plain')
            intent.putExtra(Intent.EXTRA_STREAM, uri)
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            activity.startActivity(Intent.createChooser(intent, 'Share alive configs'))
        except Exception:
            pass  # sharing is optional

class ValidatorApp(App):
    def build(self):
        from kivy.core.window import Window
        Window.clearcolor = (0.12, 0.12, 0.12, 1)
        Builder.load_string(KV)   # inject the KV layout
        return ValidatorLayout()

if __name__ == '__main__':
    ValidatorApp().run()
