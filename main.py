#!/usr/bin/env python3
import os, sys
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.popup import Popup
from kivy.clock import Clock

# Paste your entire validator code here, or import it.
# For simplicity, we'll define a function that reads a file and returns a string of alive configs.
def run_validator(input_path):
    import socket, ssl, time, base64, re
    from urllib.parse import urlparse
    # ... copy the entire body of your validator, but instead of printing, collect results.
    # Modified to return a string rather than print.
    TIMEOUT = 5
    output_lines = []
    with open(input_path, 'r') as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    configs = []
    for line in lines:
        if re.match(r'https?://', line.lower()):
            # handle subscriptions (simplified, you may want to keep the fetching code)
            pass
        else:
            configs.append(line)
    working = []
    for raw in configs:
        host, port, scheme = parse_uri(raw)
        if host is None:
            continue
        lat = tcp_ping(host, port)
        if lat is None:
            continue
        working.append(raw)
        output_lines.append(f"ALIVE {host}:{port} [{scheme}] {lat}ms")
    return "\n".join(working) if working else "No working configs found.", "\n".join(output_lines)

# Vanilla Kivy layout
class ValidatorLayout(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation='vertical', **kwargs)
        self.add_widget(Label(text="Config Validator", size_hint_y=0.1))
        self.file_chooser = FileChooserListView(path='/storage/emulated/0/Download', size_hint_y=0.6)
        self.add_widget(self.file_chooser)
        self.run_btn = Button(text="Validate Selected File", size_hint_y=0.1)
        self.run_btn.bind(on_press=self.validate_file)
        self.add_widget(self.run_btn)
        self.output = TextInput(text='', readonly=True, size_hint_y=0.2)
        self.add_widget(self.output)

    def validate_file(self, instance):
        selected = self.file_chooser.selection
        if not selected:
            popup = Popup(title='Error', content=Label(text='No file selected'), size_hint=(0.6,0.3))
            popup.open()
            return
        filepath = selected[0]
        try:
            alive_str, log_str = run_validator(filepath)
            self.output.text = log_str
            if alive_str != "No working configs found.":
                # save to same directory
                out_path = filepath + ".alive.txt"
                with open(out_path, 'w') as f:
                    f.write(alive_str)
                self.output.text += f"\n\nSaved alive configs to {out_path}"
        except Exception as e:
            self.output.text = f"Error: {e}"

class ValidatorApp(App):
    def build(self):
        return ValidatorLayout()

if __name__ == '__main__':
    ValidatorApp().run()
