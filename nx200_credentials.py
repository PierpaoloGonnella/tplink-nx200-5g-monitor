"""Read local credentials without logging their content."""
import json
import re
from pathlib import Path


def read_credentials(path):
    text = Path(path).read_text(encoding='utf-8-sig').strip()
    try:
        config = json.loads(text)
    except json.JSONDecodeError:
        config = {}
        for line in text.splitlines():
            match = re.fullmatch(r'''\s*["']?(host|username|password)["']?\s*[:=]\s*(.*?)\s*''', line)
            if match:
                config[match[1]] = match[2]
        if config and all(value.startswith('{') and value.endswith('}') for value in config.values()):
            config = {key: value[1:-1] for key, value in config.items()}
    if not isinstance(config, dict) or not all(isinstance(config.get(key), str) and config[key] for key in ('host', 'password')):
        raise ValueError('Credentials must contain nonempty host and password strings')
    return config

