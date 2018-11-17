using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace RegHook
{
    class WinAPI
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Auto, SetLastError = true)]
        internal delegate IntPtr RegOpenKeyEx_Delegate(
            IntPtr hKey,
            string subKey,
            int ulOptions,
            int samDesired,
            ref IntPtr hkResult);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "RegOpenKeyExW")]
        internal static extern IntPtr RegOpenKeyExW(
            IntPtr hKey,
            string subKey,
            int ulOptions,
            int samDesired,
            ref IntPtr hkResult);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Auto, SetLastError = true)]
        internal delegate IntPtr RegCreateKeyEx_Delegate(
            IntPtr hKey,
            string subKey,
            ref IntPtr hkResult);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "RegCreateKeyEx")]
        internal static extern IntPtr RegCreateKeyEx(
            IntPtr hKey,
            string subKey,
            ref IntPtr hkResult);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Auto, SetLastError = true)]
        internal delegate IntPtr RegDeleteKeyEx_Delegate(
            IntPtr hKey,
            string subKey,
            int samDesired,
            int Reserved);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "RegDeleteKeyEx")]
        internal static extern IntPtr RegDeleteKeyEx(
            IntPtr hKey,
            string subKey,
            int samDesired,
            int Reserved);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Auto, SetLastError = true)]
        internal delegate IntPtr RegSetValueEx_Delegate(
            IntPtr hKey,
            [MarshalAs (UnmanagedType.LPStr)]
            string lpValueName,
            int lpReserved,
            Microsoft.Win32.RegistryValueKind type,
            IntPtr lpData,
            int lpcbData);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Auto, SetLastError = true)]
        internal delegate IntPtr RegQueryValueEx_Delegate(
            IntPtr hKey,
            string lpValueName,
            int lpReserved,
            ref Microsoft.Win32.RegistryValueKind type,
            IntPtr lpData,
            ref int lpcbData);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "RegQueryValueExW")]
        internal static extern IntPtr RegQueryValueExW(
            IntPtr hKey,
            string lpValueName,
            int lpReserved,
            ref Microsoft.Win32.RegistryValueKind type,
            IntPtr lpData,
            ref int lpcbData);


        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        internal delegate IntPtr RegCloseKey_Delegate(
            IntPtr hKey);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "RegCloseKey")]
        internal static extern IntPtr RegCloseKey(
            IntPtr hKey);

    }
}
