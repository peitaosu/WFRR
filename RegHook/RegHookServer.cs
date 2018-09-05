using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using Newtonsoft.Json;
using System.Text;
using System.Reflection;

namespace RegHook {

    public class ServerInterface : MarshalByRefObject {
        public void IsInstalled (int clientPID) {
            Console.WriteLine ("RegHook has been injected into process {0}.\r\n", clientPID);
        }

        public void ReportMessages (int clientPID, string[] messages) {
            for (int i = 0; i < messages.Length; i++) {
                Console.WriteLine (messages[i].Replace("{", "{{").Replace("}", "}}"), clientPID);
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

        string vreg_path = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "V_REG.json");
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
                vreg_json = Environment.ExpandEnvironmentVariables(vreg_json);
                _vreg = JsonConvert.DeserializeObject<VRegKey> (vreg_json);
            } catch (Exception e) {
                _server.ReportException (e);
            }

            var regOpenKeyAHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegOpenKeyA"),
                new WinAPI.RegOpenKeyEx_Delegate(RegOpenKeyEx_Hook),
                this);
            regOpenKeyAHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "Registry: RegOpenKeyA hook installed");

            var regOpenKeyWHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegOpenKeyW"),
                new WinAPI.RegOpenKeyEx_Delegate(RegOpenKeyEx_Hook),
                this);
            regOpenKeyWHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "Registry: RegOpenKeyW hook installed");

            var regOpenKeyExAHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegOpenKeyExA"),
                new WinAPI.RegOpenKeyEx_Delegate(RegOpenKeyEx_Hook),
                this);
            regOpenKeyExAHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "Registry: RegOpenKeyExA hook installed");

            var regOpenKeyExWHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegOpenKeyExW"),
                new WinAPI.RegOpenKeyEx_Delegate(RegOpenKeyEx_Hook),
                this);
            regOpenKeyExWHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "Registry: RegOpenKeyExW hook installed");

            var regCreateKeyAHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegCreateKeyA"),
                new WinAPI.RegCreateKeyEx_Delegate(RegCreateKeyEx_Hook),
                this);
            regCreateKeyAHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "Registry: RegCreateKeyA hook installed");

            var regCreateKeyWHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegCreateKeyW"),
                new WinAPI.RegCreateKeyEx_Delegate(RegCreateKeyEx_Hook),
                this);
            regCreateKeyWHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "Registry: RegCreateKeyW hook installed");

            var regCreateKeyExAHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegCreateKeyExA"),
                new WinAPI.RegCreateKeyEx_Delegate(RegCreateKeyEx_Hook),
                this);
            regCreateKeyExAHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "Registry: RegCreateKeyExA hook installed");

            var regCreateKeyExWHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegCreateKeyExW"),
                new WinAPI.RegCreateKeyEx_Delegate(RegCreateKeyEx_Hook),
                this);
            regCreateKeyExWHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "Registry: RegCreateKeyExW hook installed");

            var regDeleteKeyAHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegDeleteKeyA"),
                new WinAPI.RegDeleteKeyEx_Delegate(RegDeleteKeyEx_Hook),
                this);
            regDeleteKeyAHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "Registry: RegDeleteKeyA hook installed");

            var regDeleteKeyWHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegDeleteKeyW"),
                new WinAPI.RegDeleteKeyEx_Delegate(RegDeleteKeyEx_Hook),
                this);
            regDeleteKeyWHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "Registry: RegDeleteKeyW hook installed");

            var regDeleteKeyExAHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegDeleteKeyExA"),
                new WinAPI.RegDeleteKeyEx_Delegate(RegDeleteKeyEx_Hook),
                this);
            regDeleteKeyExAHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "Registry: RegDeleteKeyExA hook installed");

            var regDeleteKeyExWHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegDeleteKeyExW"),
                new WinAPI.RegDeleteKeyEx_Delegate(RegDeleteKeyEx_Hook),
                this);
            regDeleteKeyExWHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "Registry: RegDeleteKeyExW hook installed");

            var regQueryValueAHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegQueryValueA"),
                new WinAPI.RegQueryValueEx_Delegate(RegQueryValueEx_Hook),
                this);
            regQueryValueAHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "Registry: RegQueryValueAhook installed");

            var regQueryValueWHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegQueryValueW"),
                new WinAPI.RegQueryValueEx_Delegate(RegQueryValueEx_Hook),
                this);
            regQueryValueWHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "Registry: RegQueryValueW hook installed");

            var regQueryValueExAHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegQueryValueExA"),
                new WinAPI.RegQueryValueEx_Delegate(RegQueryValueEx_Hook),
                this);
            regQueryValueExAHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "Registry: RegQueryValueExA hook installed");

            var regQueryValueExWHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegQueryValueExW"),
                new WinAPI.RegQueryValueEx_Delegate(RegQueryValueEx_Hook),
                this);
            regQueryValueExWHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "Registry: RegQueryValueExW hook installed");

            var regSetValueAHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegSetValueA"),
                new WinAPI.RegSetValueEx_Delegate(RegSetValueEx_Hook),
                this);
            regSetValueAHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "Registry: RegSetValueA hook installed");

            var regSetValueWHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegSetValueW"),
                new WinAPI.RegSetValueEx_Delegate(RegSetValueEx_Hook),
                this);
            regSetValueWHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "Registry: RegSetValueW hook installed");

            var regSetValueExAHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegSetValueExA"),
                new WinAPI.RegSetValueEx_Delegate(RegSetValueEx_Hook),
                this);
            regSetValueExAHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "Registry: RegSetValueExA hook installed");

            var regSetValueExWHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegSetValueExW"),
                new WinAPI.RegSetValueEx_Delegate(RegSetValueEx_Hook),
                this);
            regSetValueExWHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "Registry: RegSetValueExW hook installed");

            var regCloseKeyHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("advapi32.dll", "RegCloseKey"),
                new WinAPI.RegCloseKey_Delegate(RegCloseKey_Hook),
                this);
            regCloseKeyHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "Registry: RegCloseKey hook installed");

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

            regOpenKeyAHook.Dispose();
            regOpenKeyWHook.Dispose();
            regOpenKeyExAHook.Dispose();
            regOpenKeyExWHook.Dispose();
            regCreateKeyAHook.Dispose();
            regCreateKeyWHook.Dispose();
            regCreateKeyExAHook.Dispose();
            regCreateKeyExWHook.Dispose();
            regDeleteKeyAHook.Dispose();
            regDeleteKeyWHook.Dispose();
            regDeleteKeyExAHook.Dispose();
            regDeleteKeyExWHook.Dispose();
            regQueryValueAHook.Dispose();
            regQueryValueWHook.Dispose();
            regQueryValueExAHook.Dispose();
            regQueryValueExWHook.Dispose();
            regSetValueAHook.Dispose();
            regSetValueWHook.Dispose();
            regSetValueExAHook.Dispose();
            regSetValueExWHook.Dispose();
            regCloseKeyHook.Dispose();

            EasyHook.LocalHook.Release ();
        }

        IntPtr RegOpenKeyEx_Hook (
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
                result = WinAPI.RegOpenKeyExW(hKey, subKey, ulOptions, samDesired, ref hkResult);
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

        IntPtr RegCreateKeyEx_Hook (
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
            } catch {
                VRegKey new_key = new VRegKey ();
                v_reg_key_iter.Keys.Add (new_key_name, new_key);
                string vreg_output = JsonConvert.SerializeObject(_vreg);
                using (StreamWriter vreg_outfile = new StreamWriter(vreg_path, false))
                {
                    vreg_outfile.WriteLine(vreg_output);
                }
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

        IntPtr RegDeleteKeyEx_Hook(
            IntPtr hKey,
            string subKey,
            int samDesired,
            int Reserved)
        {
            IntPtr result = IntPtr.Zero;
            string keyDeleted = "";

            switch (hKey.ToString())
            {
                case "-2147483648":
                    keyDeleted = "HKEY_CLASSES_ROOT\\" + subKey;
                    break;
                case "-2147483643":
                    keyDeleted = "HKEY_CURRENT_CONFIG\\" + subKey;
                    break;
                case "-2147483647":
                    keyDeleted = "HKEY_CURRENT_USER\\" + subKey;
                    break;
                case "-2147483646":
                    keyDeleted = "HKEY_LOCAL_MACHINE\\" + subKey;
                    break;
                case "-2147483645":
                    keyDeleted = "HKEY_USERS\\" + subKey;
                    break;
            }

            keyDeleted = keyDeleted.ToLower();

            VRegKey v_reg_key_iter = _vreg;
            VRegKey v_reg_key_iter_parent = v_reg_key_iter;
            string new_key_name = "";

            try
            {
                foreach (string v_reg_key in keyDeleted.Split('\\'))
                {
                    new_key_name = v_reg_key;
                    v_reg_key_iter_parent = v_reg_key_iter;
                    v_reg_key_iter = v_reg_key_iter.Keys[v_reg_key];
                }
                v_reg_key_iter_parent.Keys.Remove(keyDeleted.Split('\\')[keyDeleted.Split('\\').Length - 1]);
                string vreg_output = JsonConvert.SerializeObject(_vreg);
                using (StreamWriter vreg_outfile = new StreamWriter(vreg_path, false))
                {
                    vreg_outfile.WriteLine(vreg_output);
                }
                result = new IntPtr(0x0);
            }
            catch
            {
                result = new IntPtr(0x2);
            }
            try
            {
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {

                        this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: Delete {2} {3} return code: {4}",
                                EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), hKey, subKey, result));
                    }
                }
            }
            catch { }

            return result;

        }

        IntPtr RegSetValueEx_Hook (
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
                            case Microsoft.Win32.RegistryValueKind.Binary:
                                value.Type = "REG_BINARY";
                                value.Data = Marshal.PtrToStringBSTR (lpData);
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

        IntPtr RegQueryValueEx_Hook (
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
                            case "REG_BINARY":
                                lpcbData = value.Data.Length + 1;
                                Marshal.Copy(Encoding.ASCII.GetBytes (value.Data), 0, lpData, value.Data.Length);
                                type = Microsoft.Win32.RegistryValueKind.Binary;
                                data = Marshal.PtrToStringBSTR(lpData);
                                break;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                this._messageQueue.Enqueue(e.Message);
                result = WinAPI.RegQueryValueExW(hKey, lpValueName, lpReserved, ref type, lpData, ref lpcbData);
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

        IntPtr RegCloseKey_Hook (
            IntPtr hKey) {

            IntPtr result = IntPtr.Zero;
            try {
                if (!Marshal.PtrToStringUni(hKey).StartsWith("HKEY"))
                {
                    result = WinAPI.RegCloseKey(hKey);
                }
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

    }

}