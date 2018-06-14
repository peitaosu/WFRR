using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace FSHook
{
    class WinAPI
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate IntPtr CreateFileW_Delegate(
            string InFileName,
            int InDesiredAccess,
            int InShareMode,
            IntPtr InSecurityAttributes,
            int InCreationDisposition,
            int InFlagsAndAttributes,
            IntPtr InTemplateFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        internal static extern IntPtr CreateFile(
            string InFileName,
            int InDesiredAccess,
            int InShareMode,
            IntPtr InSecurityAttributes,
            int InCreationDisposition,
            int InFlagsAndAttributes,
            IntPtr InTemplateFile);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate bool ReadFileEx_Delegate(
            IntPtr hFile,
            [Out] byte[] lpBuffer,
            uint nNumberOfBytesToRead,
            [In] ref System.Threading.NativeOverlapped lpOverlapped,
            System.Threading.IOCompletionCallback lpCompletionRoutine);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        internal static extern bool ReadFileEx(
            IntPtr hFile,
            [Out] byte[] lpBuffer,
            uint nNumberOfBytesToRead,
            [In] ref System.Threading.NativeOverlapped lpOverlapped,
            System.Threading.IOCompletionCallback lpCompletionRoutine);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate bool GetFileSizeEx_Delegate(
            IntPtr hFile,
            out long lpFileSize);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        internal static extern bool GetFileSize(
            IntPtr hFile,
            out long lpFileSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate bool GetFileTime_Delegate(
            IntPtr hFile,
            IntPtr lpCreationTime,
            IntPtr lpLastAccessTime,
            IntPtr lpLastWriteTime);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        internal static extern bool GetFileTime(
            IntPtr hFile,
            IntPtr lpCreationTime,
            IntPtr lpLastAccessTime,
            IntPtr lpLastWriteTime);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate IntPtr DeleteFileW_Delegate(
            string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        internal static extern IntPtr DeleteFile(
            string lpFileName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate bool CopyFileW_Delegate(
            string lpExistingFileName,
            string lpNewFileName,
            bool bFailIfExists);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        internal static extern bool CopyFileW(
            string lpExistingFileName,
            string lpNewFileName,
            bool bFailIfExists);

    }
}
