using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace RegHook {

    public class ServerInterface : MarshalByRefObject {
        public void IsInstalled (int clientPID) {
            Console.WriteLine ("RegHook has been injected into process {0}.\r\n", clientPID);
        }

        public void ReportMessages (int clientPID, string[] messages) {
            for (int i = 0; i < messages.Length; i++) {
                Console.WriteLine (messages[i], clientPID);
            }
        }

        public void ReportMessage (int clientPID, string message) {
            Console.WriteLine (message);
        }

        public void ReportException (Exception e) {
            Console.WriteLine ("The target process has reported an error:\r\n" + e.ToString ());
        }

        public void Ping () { }
    }

    public class InjectionEntryPoint : EasyHook.IEntryPoint {

        ServerInterface _server = null;

        Queue<string> _messageQueue = new Queue<string> ();

        public InjectionEntryPoint (
            EasyHook.RemoteHooking.IContext context,
            string channelName) {
            _server = EasyHook.RemoteHooking.IpcConnectClient<ServerInterface> (channelName);
            _server.Ping ();
        }

        public void Run (
            EasyHook.RemoteHooking.IContext context,
            string channelName) {

            _server.IsInstalled (EasyHook.RemoteHooking.GetCurrentProcessId ());

            var openRegKeyHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegOpenKeyExW"),
                new RegOpenKeyExW_Delegate(RegOpenKeyExW_Hook),
                this);
            
            var queryRegValueHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegQueryValueExW"),
                new RegQueryValueExW_Delegate(RegQueryValueExW_Hook),
                this);

            var setRegValueHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegSetValueExW"),
                new RegSetValueExW_Delegate(RegSetValueExW_Hook),
                this);
            
            openRegKeyHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            queryRegValueHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            setRegValueHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });

            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "RegOpenKeyExW hook installed");
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "RegQueryValueExW hook installed");
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "RegSetValueExW hook installed");

            EasyHook.RemoteHooking.WakeUpProcess ();

            try {
                while (true) {
                    System.Threading.Thread.Sleep (500);

                    string[] queued = null;

                    lock (_messageQueue) {
                        queued = _messageQueue.ToArray ();
                        _messageQueue.Clear ();
                    }

                    if (queued != null && queued.Length > 0) {
                        _server.ReportMessages (EasyHook.RemoteHooking.GetCurrentProcessId (), queued);
                    } else {
                        _server.Ping ();
                    }
                }
            } catch { }

            openRegKeyHook.Dispose();
            queryRegValueHook.Dispose();
            setRegValueHook.Dispose();

            EasyHook.LocalHook.Release ();
        }

        #region RegOpenKeyExW Hook
        [UnmanagedFunctionPointer (CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate IntPtr RegOpenKeyExW_Delegate (
            UIntPtr hKey,
            string subKey,
            int ulOptions,
            int samDesired,
            UIntPtr hkResult);

        [DllImport ("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "RegOpenKeyExW")]
        public static extern IntPtr RegOpenKeyExW (
            UIntPtr hKey,
            string subKey,
            int ulOptions,
            int samDesired,
            UIntPtr hkResult);

        IntPtr RegOpenKeyExW_Hook (
            UIntPtr hKey,
            string subKey,
            int ulOptions,
            int samDesired,
            UIntPtr hkResult) {

            IntPtr result = RegOpenKeyExW (hKey, subKey, ulOptions, samDesired, hkResult);
            try {
                lock (this._messageQueue) {
                    if (this._messageQueue.Count < 1000) {

                        this._messageQueue.Enqueue (
                            string.Format ("[{0}:{1}]: Open {2} {3} return code: {4}",
                                EasyHook.RemoteHooking.GetCurrentProcessId (), EasyHook.RemoteHooking.GetCurrentThreadId (), hKey, subKey, result));
                    }
                }
            } catch { }

            return result;
        }

        #endregion

        #region RegSetValueExW Hook

        [UnmanagedFunctionPointer (CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate IntPtr RegSetValueExW_Delegate (
            UIntPtr hKey,
            string lpValueName,
            int lpReserved,
            IntPtr type,
            IntPtr lpData,
            int lpcbData);

        [DllImport ("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "RegSetValueExW")]
        public static extern IntPtr RegSetValueExW (
            UIntPtr hKey,
            string lpValueName,
            int lpReserved,
            IntPtr type,
            IntPtr lpData,
            int lpcbData);

        IntPtr RegSetValueExW_Hook (
            UIntPtr hKey,
            string lpValueName,
            int lpReserved,
            IntPtr type,
            IntPtr lpData,
            int lpcbData) {

            IntPtr result = RegSetValueExW (hKey, lpValueName, lpReserved, type, lpData, lpcbData);
            string data = Marshal.PtrToStringUni (Marshal.AllocHGlobal (lpcbData), lpcbData / sizeof (char)).TrimEnd ('\0');
            try {
                lock (this._messageQueue) {
                    if (this._messageQueue.Count < 1000) {

                        this._messageQueue.Enqueue (
                            string.Format ("[{0}:{1}]: Set {2} {3} return code: {4}",
                                EasyHook.RemoteHooking.GetCurrentProcessId (), EasyHook.RemoteHooking.GetCurrentThreadId (), lpValueName, data, result));
                    }
                }
            } catch { }

            return result;
        }

        #endregion

        #region RegQueryValueExW Hook

        [UnmanagedFunctionPointer (CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate IntPtr RegQueryValueExW_Delegate (
            UIntPtr hKey,
            string lpValueName,
            int lpReserved,
            IntPtr type,
            IntPtr lpData,
            ref int lpcbData);

        [DllImport ("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "RegQueryValueExW")]
        public static extern IntPtr RegQueryValueExW (
            UIntPtr hKey,
            string lpValueName,
            int lpReserved,
            IntPtr type,
            IntPtr lpData,
            ref int lpcbData
        );

        IntPtr RegQueryValueExW_Hook (
            UIntPtr hKey,
            string lpValueName,
            int lpReserved,
            IntPtr type,
            IntPtr lpData,
            ref int lpcbData) {

            IntPtr result = RegQueryValueExW (hKey, lpValueName, lpReserved, type, lpData, ref lpcbData);
            IntPtr ptr = Marshal.AllocHGlobal (lpcbData);
            RegQueryValueExW (hKey, lpValueName, lpReserved, type, ptr, ref lpcbData);
            string data = Marshal.PtrToStringUni (ptr, lpcbData / sizeof (char)).TrimEnd ('\0');
            try {
                lock (this._messageQueue) {
                    if (this._messageQueue.Count < 1000) {

                        this._messageQueue.Enqueue (
                            string.Format ("[{0}:{1}]: Query {2} {3} return code: {4}",
                                EasyHook.RemoteHooking.GetCurrentProcessId (), EasyHook.RemoteHooking.GetCurrentThreadId (), lpValueName, data, result));
                    }
                }
            } catch { }

            return result;
        }

        #endregion

    }

}