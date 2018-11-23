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
        IntPtr vreg_root = IntPtr.Zero;
        string vreg_root_str = null;
        string vreg_redirected = null;

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
                vreg_root_str = _vreg.VRegRedirected.Split('\\')[0];
                vreg_root = HKEY_StrToPtr(vreg_root_str);
                vreg_redirected = _vreg.VRegRedirected.Substring(vreg_root_str.Length + 1);
            }
            catch (Exception e) {
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

            EasyHook.LocalHook.Release ();
        }

        string HKEY_PtrToStr(IntPtr hkey)
        {
            switch (hkey.ToString())
            {
                case "-2147483648":
                    return "HKEY_CLASSES_ROOT";
                case "-2147483643":
                    return "HKEY_CURRENT_CONFIG";
                case "-2147483647":
                    return "HKEY_CURRENT_USER";
                case "-2147483646":
                    return "HKEY_LOCAL_MACHINE";
                case "-2147483645":
                    return "HKEY_USERS";
                default:
                    return "";
            }
        }

        IntPtr HKEY_StrToPtr(string hkey)
        {
            switch (hkey.ToString())
            {
                case "HKEY_CLASSES_ROOT":
                    return new IntPtr(-2147483648);
                case "HKEY_CURRENT_CONFIG":
                    return new IntPtr(-2147483643);
                case "HKEY_CURRENT_USER":
                    return new IntPtr(-2147483647);
                case "HKEY_LOCAL_MACHINE":
                    return new IntPtr(-2147483646);
                case "HKEY_USERS":
                    return new IntPtr(-2147483645);
                default:
                    return IntPtr.Zero;
            }
        }

        IntPtr RegOpenKeyEx_Hook (
            IntPtr hKey,
            string subKey,
            int ulOptions,
            int samDesired,
            ref IntPtr hkResult) {

            IntPtr result = IntPtr.Zero;
            string keyToOpen = HKEY_PtrToStr(hKey) + "\\" + subKey;
            bool callorigin = false;

            foreach (VRegKeyMapping map in _vreg.Mapping)
            {
                if (keyToOpen.ToUpper().Contains(map.Source.ToUpper()))
                {
                    keyToOpen = keyToOpen.ToUpper().Replace(map.Source.ToUpper(), vreg_redirected + "\\" + map.Destination);
                    result = WinAPI.RegOpenKeyEx(vreg_root, keyToOpen, ulOptions, samDesired, ref hkResult);
                    this._messageQueue.Enqueue(
                        string.Format("[{0}:{1}]: Open {2} {3} return code: {4}",
                            EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), HKEY_PtrToStr(vreg_root), keyToOpen, result));
                    if(result != IntPtr.Zero){
                        callorigin = true;
                        break;
                    }else{
                        return result;
                    }
                }
            }

            if(callorigin)
            {
                this._messageQueue.Enqueue("Calling original API...");
                result = WinAPI.RegOpenKeyEx(hKey, subKey, ulOptions, samDesired, ref hkResult);
                this._messageQueue.Enqueue(
                    string.Format("[{0}:{1}]: Open {2} {3} return code: {4}",
                        EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), HKEY_PtrToStr(hKey), subKey, result));
                return result;
            }
            return result;
        }

        IntPtr RegCreateKeyEx_Hook (
            IntPtr hKey,
            string subKey,
            ref IntPtr hkResult) {

            IntPtr result = IntPtr.Zero;
            string keyToCreate = HKEY_PtrToStr(hKey) + "\\" + subKey;
            bool callorigin = false;

            foreach (VRegKeyMapping map in _vreg.Mapping)
            {
                if (keyToCreate.ToUpper().Contains(map.Source.ToUpper()))
                {
                    keyToCreate = keyToCreate.ToUpper().Replace(map.Source.ToUpper(), vreg_redirected + "\\" + map.Destination);
                    result = WinAPI.RegCreateKeyEx(vreg_root, keyToCreate, ref hkResult);
                    this._messageQueue.Enqueue(
                        string.Format("[{0}:{1}]: Create {2} {3} return code: {4}",
                            EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), HKEY_PtrToStr(vreg_root), keyToCreate, result));
                    if(result != IntPtr.Zero){
                        callorigin = true;
                        break;
                    }else{
                        return result;
                    }
                }
            }

            if(callorigin)
            {
                this._messageQueue.Enqueue("Calling original API...");
                result = WinAPI.RegCreateKeyEx(hKey, subKey, ref hkResult);
                this._messageQueue.Enqueue(
                    string.Format("[{0}:{1}]: Create {2} {3} return code: {4}",
                        EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), HKEY_PtrToStr(hKey), subKey, result));
                return result;
            }

            return result;
        }

        IntPtr RegDeleteKeyEx_Hook(
            IntPtr hKey,
            string subKey,
            int samDesired,
            int Reserved)
        {
            IntPtr result = IntPtr.Zero;
            string keyToDelete = HKEY_PtrToStr(hKey) + "\\" + subKey;
            bool callorigin = false;

            foreach (VRegKeyMapping map in _vreg.Mapping)
            {
                if (keyToDelete.ToUpper().Contains(map.Source.ToUpper()))
                {
                    keyToDelete = keyToDelete.ToUpper().Replace(map.Source.ToUpper(), vreg_redirected + "\\" + map.Destination);
                    result = WinAPI.RegDeleteKeyEx(vreg_root, keyToDelete, samDesired, Reserved);
                    this._messageQueue.Enqueue(
                        string.Format("[{0}:{1}]: Delete {2} {3} return code: {4}",
                            EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), HKEY_PtrToStr(vreg_root), keyToDelete, result));
                    if(result != IntPtr.Zero){
                        callorigin = true;
                        break;
                    }else{
                        return result;
                    }
                }
            }

            if(callorigin)
            {
                this._messageQueue.Enqueue("Calling original API...");
                result = WinAPI.RegDeleteKeyEx(hKey, subKey, samDesired, Reserved);
                this._messageQueue.Enqueue(
                    string.Format("[{0}:{1}]: Delete {2} {3} return code: {4}",
                        EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), HKEY_PtrToStr(hKey), subKey, result));
                return result;

            }

            return result;

        }

    }

}