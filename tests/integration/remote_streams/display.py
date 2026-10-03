# SPDX-License-Identifier: Apache-2.0
"""Own one small software-emulated display in a private libvirt session."""

import json
import os
import subprocess
import time

from contributor_tls.authority import private


class Display:
    def __init__(self, directory):
        self.directory = directory / "display"
        self.directory.mkdir(mode=0o700)
        self.env = dict(os.environ)
        self.paths = {}
        self.process = self.log = None
        self.started = False
        for variable, child in (("XDG_RUNTIME_DIR", "run"), ("XDG_CONFIG_HOME", "config"),
                                ("XDG_CACHE_HOME", "cache"), ("XDG_DATA_HOME", "data")):
            path = self.directory / child
            path.mkdir(mode=0o700)
            self.paths[variable] = str(path)
        self.env.update(self.paths)
        self.bin = self.directory / "bin"
        self.bin.mkdir(mode=0o700)
        wrapper = self.bin / "python3"
        private(wrapper, "#!/usr/bin/python3\nimport os,sys\n"
            f"os.execve('/usr/bin/python3',['/usr/bin/python3',*sys.argv[1:]],dict(os.environ)|{self.paths!r})\n")
        wrapper.chmod(0o700)

    def virsh(self, *args):
        result = subprocess.run(["/usr/bin/virsh", "-c", "qemu:///session", *args], env=self.env,
                                capture_output=True, text=True, timeout=20)
        assert result.returncode == 0, f"Private libvirt command failed: {args[0]}."
        return result.stdout

    def start(self):
        configuration = self.directory / "daemon.conf"
        private(configuration, 'auth_unix_rw = "none"\nauth_unix_ro = "none"\n')
        self.log = (self.directory / "daemon.log").open("wb")
        self.process = subprocess.Popen(["/usr/sbin/libvirtd", "-f", str(configuration),
            "-p", str(self.directory / "pid"), "--timeout", "5"], env=self.env,
            stdout=self.log, stderr=self.log)
        for _ in range(100):
            assert self.process.poll() is None, "The private libvirt daemon exited."
            if (self.directory / "run/libvirt/libvirt-sock").exists():
                break
            time.sleep(0.05)
        else:
            raise AssertionError("The private libvirt socket did not start.")
        assert "ficc-remote-display" not in self.virsh("list", "--all")
        source = self.directory / "boot.s"
        private(source, ".code16\n.global _start\n_start:\n xor %ax,%ax\n mov %ax,%ds\n"
            " mov %ax,%ss\n mov $0x7c00,%sp\n mov $3,%ax\n int $0x10\n mov $message,%si\n"
            "next:\n lodsb\n test %al,%al\n jz input\n mov $0x0e,%ah\n mov $7,%bx\n int $0x10\n jmp next\n"
            "input:\n xor %ax,%ax\n int $0x16\n mov $0x0e,%ah\n mov $7,%bx\n int $0x10\n jmp input\n"
            'message:\n .asciz "FICC REMOTE DISPLAY - TYPE TO VERIFY INPUT\\r\\n"\n .org 510\n .word 0xaa55\n')
        obj, image = self.directory / "boot.o", self.directory / "boot.img"
        subprocess.run(["/usr/bin/as", "--32", "-o", str(obj), str(source)],
                       check=True, capture_output=True, timeout=10)
        subprocess.run(["/usr/bin/ld", "-m", "elf_i386", "-Ttext", "0x7c00", "--oformat", "binary",
                        "-o", str(image), str(obj)], check=True, capture_output=True, timeout=10)
        assert image.stat().st_size == 512
        with image.open("ab") as stream:
            stream.truncate(1474560)
        definition = self.directory / "vm.xml"
        private(definition, '<domain type="qemu"><name>ficc-remote-display</name>'
            '<memory unit="MiB">64</memory><vcpu>1</vcpu><os><type arch="x86_64" machine="pc">hvm</type>'
            '<boot dev="fd"/></os><devices><emulator>/usr/bin/qemu-system-x86_64</emulator>'
            f'<disk type="file" device="floppy"><driver name="qemu" type="raw"/><source file="{image}"/>'
            '<target dev="fda"/><readonly/></disk><graphics type="vnc"><listen type="none"/></graphics>'
            '<video><model type="vga"/></video><memballoon model="none"/></devices></domain>')
        self.virsh("create", str(definition))
        self.started = True
        self.uuid = self.virsh("domuuid", "ficc-remote-display").strip().replace("-", "")
        assert len(self.uuid) == 32

    def close(self):
        if self.started:
            self.virsh("destroy", "ficc-remote-display")
            self.started = False
        if self.process:
            # Session daemons exit after their last domain and client close.
            # Use that bounded path without altering the host signal policy.
            self.process.wait(timeout=20)
        if self.log:
            self.log.close()

    def metadata(self):
        return json.dumps({"uuid": self.uuid, "memory_mib": 64, "vcpus": 1})
