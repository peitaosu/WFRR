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

            var queryRegKeyHook = EasyHook.LocalHook.Create (
                EasyHook.LocalHook.GetProcAddress ("advapi32.dll", "RegQueryValueExW"),
                new RegQueryValueExW_Delegate (RegQueryValueExW_Hook),
                this);

            queryRegKeyHook.ThreadACL.SetExclusiveACL (new Int32[] { 0 });

            _server.ReportMessage (EasyHook.RemoteHooking.GetCurrentProcessId (), "RegQueryValueExW hook installed");

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

            queryRegKeyHook.Dispose ();

            EasyHook.LocalHook.Release ();
        }

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