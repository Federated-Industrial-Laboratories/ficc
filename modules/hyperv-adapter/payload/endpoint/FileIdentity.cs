// SPDX-License-Identifier: Apache-2.0
// Read provider-selected configuration identity without changing its contents.
using System;
using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

public static class FICCFileIdentity {
    [StructLayout(LayoutKind.Sequential)]
    struct BasicInfo { public long Created, Accessed, Written, Changed; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    struct FileId { public ulong Volume, Low, High; }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security,
                                            uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int kind, out FileId info, uint size);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int kind, out BasicInfo info, uint size);
    static string Hex(byte[] bytes) { return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant(); }
    public static string[] Read(string path) {
        path = Path.GetFullPath(path);
        if (!path.EndsWith(".vmcx", StringComparison.OrdinalIgnoreCase)) throw new IOException("Unsupported configuration.");
        for (string part = path; part != null; part = Path.GetDirectoryName(part)) {
            if ((File.GetAttributes(part) & FileAttributes.ReparsePoint) != 0) throw new IOException("Configuration link refused.");
            if (part == Path.GetPathRoot(part)) break;
        }
        using (SafeFileHandle handle = CreateFile(path, 0x80000000, 7, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero)) {
            if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            FileId id;
            BasicInfo before, after;
            if (!GetFileInformationByHandleEx(handle, 18, out id, 24) ||
                !GetFileInformationByHandleEx(handle, 0, out before, (uint)Marshal.SizeOf(typeof(BasicInfo))))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            if ((id.Low == 0 && id.High == 0) || before.Created <= 0) throw new IOException("Configuration identity absent.");
            if ((before.Attributes & 0x410) != 0) throw new IOException("Configuration type refused.");
            using (FileStream stream = new FileStream(handle, FileAccess.Read)) {
                long length = stream.Length;
                if (length < 1 || length > 16 * 1024 * 1024) throw new IOException("Configuration size refused.");
                using (SHA256 hash = SHA256.Create()) {
                    string revision = Hex(hash.ComputeHash(stream));
                    if (!GetFileInformationByHandleEx(handle, 0, out after, (uint)Marshal.SizeOf(typeof(BasicInfo))) ||
                        stream.Length != length || before.Created != after.Created || before.Changed != after.Changed ||
                        before.Written != after.Written) throw new IOException("Configuration changed during read.");
                    string identity = id.Volume.ToString("x16") + id.Low.ToString("x16") + id.High.ToString("x16") + before.Created.ToString("x16");
                    return new string[] { identity, revision };
                }
            }
        }
    }
}
