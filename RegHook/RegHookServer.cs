using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using Newtonsoft.Json;
using System.Text;

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

        string vreg_path = @"V_REG.json";
        string vreg_json = null;
        VRegKey _vreg = null;

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

            try {
                vreg_json = new StreamReader (vreg_path).ReadToEnd ();
                _vreg = JsonConvert.DeserializeObject<VRegKey> (vreg_json);
            } catch (Exception e) {
                _server.ReportException (e);
            }

            var openRegKeyHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegOpenKeyExW"),
                new RegOpenKeyExW_Delegate(RegOpenKeyExW_Hook),
                this);

            var createRegKeyHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegCreateKeyW"),
                new RegCreateKeyW_Delegate(RegCreateKeyW_Hook),
                this);

            var queryRegValueHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegQueryValueExW"),
                new RegQueryValueExW_Delegate(RegQueryValueExW_Hook),
                this);

            var setRegValueHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegSetValueExW"),
                new RegSetValueExW_Delegate(RegSetValueExW_Hook),
                this);

            var closeRegKeyHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegCloseKey"),
                new RegCloseKey_Delegate(RegCloseKey_Hook),
                this);

            openRegKeyHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            createRegKeyHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            queryRegValueHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            setRegValueHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            closeRegKeyHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });

            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "RegOpenKeyExW hook installed");
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "RegCreateKeyW hook installed");
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "RegQueryValueExW hook installed");
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "RegSetValueExW hook installed");
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "RegCloseKey hook installed");

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
            createRegKeyHook.Dispose();
            queryRegValueHook.Dispose();
            setRegValueHook.Dispose();
            closeRegKeyHook.Dispose();

            EasyHook.LocalHook.Release ();
        }

        #region RegOpenKeyExW Hook
        [UnmanagedFunctionPointer (CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate IntPtr RegOpenKeyExW_Delegate (
            IntPtr hKey,
            string subKey,
            int ulOptions,
            int samDesired,
            ref IntPtr hkResult);

        [DllImport ("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "RegOpenKeyExW")]
        public static extern IntPtr RegOpenKeyExW (
            IntPtr hKey,
            string subKey,
            int ulOptions,
            int samDesired,
            ref IntPtr hkResult);

        IntPtr RegOpenKeyExW_Hook (
            IntPtr hKey,
            string subKey,
            int ulOptions,
            int samDesired,
            ref IntPtr hkResult) {

            IntPtr result = IntPtr.Zero;
            string keyOpened = "";

            switch (hKey.ToString())
            {
                case "-2147483648":
                    keyOpened = "HKEY_CLASSES_ROOT\\" + subKey;
                    break;
                case "-2147483643":
                    keyOpened = "HKEY_CURRENT_CONFIG\\" + subKey;
                    break;
                case "-2147483647":
                    keyOpened = "HKEY_CURRENT_USER\\" + subKey;
                    break;
                case "-2147483646":
                    keyOpened = "HKEY_LOCAL_MACHINE\\" + subKey;
                    break;
                case "-2147483645":
                    keyOpened = "HKEY_USERS\\" + subKey;
                    break;
            }

            keyOpened = keyOpened.ToLower ();

            VRegKey v_reg_key_iter = _vreg;

            try {
                foreach(string v_reg_key in keyOpened.Split('\\'))
                {
                    v_reg_key_iter = v_reg_key_iter.Keys[v_reg_key];
                }
                GCHandle gCHandle = GCHandle.Alloc(keyOpened, GCHandleType.Pinned);
                hkResult = gCHandle.AddrOfPinnedObject();
            }
            catch(Exception e)
            {
                this._messageQueue.Enqueue(e.Message);
                result = new IntPtr(0x2);
            }
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


        #region RegCreateKeyW Hook
        [UnmanagedFunctionPointer (CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate IntPtr RegCreateKeyW_Delegate (
            IntPtr hKey,
            string subKey,
            ref IntPtr hkResult);

        [DllImport ("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "RegCreateKeyW")]
        public static extern IntPtr RegCreateKeyW (
            IntPtr hKey,
            string subKey,
            ref IntPtr hkResult);

        IntPtr RegCreateKeyW_Hook (
            IntPtr hKey,
            string subKey,
            ref IntPtr hkResult) {

            IntPtr result = IntPtr.Zero;
            string keyCreated = "";

            switch (hKey.ToString ()) {
                case "-2147483648":
                    keyCreated = "HKEY_CLASSES_ROOT\\" + subKey;
                    break;
                case "-2147483643":
                    keyCreated = "HKEY_CURRENT_CONFIG\\" + subKey;
                    break;
                case "-2147483647":
                    keyCreated = "HKEY_CURRENT_USER\\" + subKey;
                    break;
                case "-2147483646":
                    keyCreated = "HKEY_LOCAL_MACHINE\\" + subKey;
                    break;
                case "-2147483645":
                    keyCreated = "HKEY_USERS\\" + subKey;
                    break;
            }

            keyCreated = keyCreated.ToLower ();

            VRegKey v_reg_key_iter = _vreg;
            string new_key_name = "";

            try {
                foreach (string v_reg_key in keyCreated.Split ('\\')) {
                    new_key_name = v_reg_key;
                    v_reg_key_iter = v_reg_key_iter.Keys[v_reg_key];
                }
                GCHandle gCHandle = GCHandle.Alloc (keyCreated, GCHandleType.Pinned);
                hkResult = gCHandle.AddrOfPinnedObject ();
            } catch (Exception e) {
                VRegKey new_key = new VRegKey ();
                v_reg_key_iter.Keys.Add (new_key_name, new_key);
                result = new IntPtr (0x0);
            }
            try {
                lock (this._messageQueue) {
                    if (this._messageQueue.Count < 1000) {

                        this._messageQueue.Enqueue (
                            string.Format ("[{0}:{1}]: Create {2} {3} return code: {4}",
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
            IntPtr hKey,
            [MarshalAs (UnmanagedType.LPStr)]
            string lpValueName,
            int lpReserved,
            Microsoft.Win32.RegistryValueKind type,
            IntPtr lpData,
            int lpcbData);

        [DllImport ("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "RegSetValueExW")]
        public static extern IntPtr RegSetValueExW (
            IntPtr hKey,
            [MarshalAs (UnmanagedType.LPStr)]
            string lpValueName,
            int lpReserved,
            Microsoft.Win32.RegistryValueKind type,
            IntPtr lpData,
            int lpcbData);

        IntPtr RegSetValueExW_Hook (
            IntPtr hKey,
            [MarshalAs (UnmanagedType.LPStr)]
            string lpValueName,
            int lpReserved,
            Microsoft.Win32.RegistryValueKind type,
            IntPtr lpData,
            int lpcbData) {

            IntPtr result = IntPtr.Zero;
            string reg_key = Marshal.PtrToStringUni (hKey);
            VRegKey v_reg_key_iter = _vreg;
            string data = "";
            try {
                foreach (string v_reg_key in reg_key.Split ('\\')) {
                    v_reg_key_iter = v_reg_key_iter.Keys[v_reg_key];
                }
                foreach (VRegValue value in v_reg_key_iter.Values) {
                    if (value.Name == lpValueName) {
                        switch (type) {
                            case Microsoft.Win32.RegistryValueKind.DWord:
                                value.Type = "REG_DWORD";
                                value.Data = Marshal.ReadInt32 (lpData).ToString ("X8");
                                data = value.Data;
                                break;
                            case Microsoft.Win32.RegistryValueKind.QWord:
                                value.Type = "REG_QWORD";
                                value.Data = Marshal.ReadInt64 (lpData).ToString ("X8");
                                data = value.Data;
                                break;
                            case Microsoft.Win32.RegistryValueKind.String:
                                value.Type = "REG_SZ";
                                value.Data = Marshal.PtrToStringAnsi (lpData);
                                data = value.Data;
                                break;
                        }
                    }
                }
            } catch (Exception e) {
                this._messageQueue.Enqueue(e.Message);
                result = new IntPtr (0x2);
            }

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
            IntPtr hKey,
            string lpValueName,
            int lpReserved,
            ref Microsoft.Win32.RegistryValueKind type,
            IntPtr lpData,
            ref int lpcbData);

        [DllImport ("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "RegQueryValueExW")]
        public static extern IntPtr RegQueryValueExW (
            IntPtr hKey,
            string lpValueName,
            int lpReserved,
            ref Microsoft.Win32.RegistryValueKind type,
            IntPtr lpData,
            ref int lpcbData
        );

        IntPtr RegQueryValueExW_Hook (
            IntPtr hKey,
            string lpValueName,
            int lpReserved,
            ref Microsoft.Win32.RegistryValueKind type,
            IntPtr lpData,
            ref int lpcbData) {

            IntPtr result = IntPtr.Zero;

            string reg_key = Marshal.PtrToStringUni(hKey);
            string data = "";
            VRegKey v_reg_key_iter = _vreg;
            try
            {
                foreach (string v_reg_key in reg_key.Split('\\'))
                {
                    v_reg_key_iter = v_reg_key_iter.Keys[v_reg_key];
                }
                foreach (VRegValue value in v_reg_key_iter.Values)
                {
                    if (value.Name == lpValueName)
                    {
                        switch (value.Type)
                        {
                            case "REG_DWORD":
                                lpcbData = Marshal.SizeOf(typeof(Int32));
                                Marshal.WriteInt32(lpData, Convert.ToInt32(value.Data, 16));
                                type = Microsoft.Win32.RegistryValueKind.DWord;
                                data = Marshal.ReadInt32(lpData).ToString();
                                break;
                            case "REG_QWORD":
                                lpcbData = Marshal.SizeOf(typeof(Int64));
                                Marshal.WriteInt64(lpData, Convert.ToInt64(value.Data, 16));
                                type = Microsoft.Win32.RegistryValueKind.QWord;
                                data = Marshal.ReadInt64(lpData).ToString();
                                break;
                            case "REG_SZ":
                                lpcbData = value.Data.Length + 1;
                                Marshal.Copy(Encoding.ASCII.GetBytes (value.Data), 0, lpData, value.Data.Length);
                                type = Microsoft.Win32.RegistryValueKind.String;
                                data = Marshal.PtrToStringAnsi(lpData);
                                break;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                this._messageQueue.Enqueue(e.Message);
                result = new IntPtr (0x2);
            }

            try {
                lock (this._messageQueue) {
                    if (this._messageQueue.Count < 1000) {

                        this._messageQueue.Enqueue (
                            string.Format ("[{0}:{1}]: Query {2} {3} {4} {5} return code: {6}",
                                EasyHook.RemoteHooking.GetCurrentProcessId (), EasyHook.RemoteHooking.GetCurrentThreadId (), lpValueName, data, lpcbData, Marshal.ReadInt32 (lpData), result));
                    }
                }
            } catch { }

            return result;
        }

        #endregion

        #region RegCloseKey Hook

        [UnmanagedFunctionPointer (CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate IntPtr RegCloseKey_Delegate (
            IntPtr hKey);

        [DllImport ("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "RegCloseKey")]
        public static extern IntPtr RegCloseKey (
            IntPtr hKey);

        IntPtr RegCloseKey_Hook (
            IntPtr hKey) {

            IntPtr result = IntPtr.Zero;
            try {
                lock (this._messageQueue) {
                    if (this._messageQueue.Count < 1000) {

                        this._messageQueue.Enqueue (
                            string.Format ("[{0}:{1}]: Close {2} return code: {3}",
                                EasyHook.RemoteHooking.GetCurrentProcessId (), EasyHook.RemoteHooking.GetCurrentThreadId (), hKey, result));
                    }
                }
            } catch { }

            return result;
        }

        #endregion
    }

}