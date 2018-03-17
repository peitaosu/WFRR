using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using Newtonsoft.Json;
using System.Text;
using System.Reflection;

namespace FSHook {

    public class ServerInterface : MarshalByRefObject {
        public void IsInstalled (int clientPID) {
            Console.WriteLine ("FSHook has been injected into process {0}.\r\n", clientPID);
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

        string vfs_path = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "V_FS.json");
        string vfs_json = null;
        VDirectory _vfs = null;

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
                vfs_json = new StreamReader (vfs_path).ReadToEnd ();
                _vfs = JsonConvert.DeserializeObject<VDirectory> (vfs_json);
            } catch (Exception e) {
                _server.ReportException (e);
            }

            var fsCreateFileHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("kernel32.dll", "CreateFileW"),
                new CreateFileW_Delegate(CreateFile_Hook),
                this);

            fsCreateFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "CreateFileW hook installed");

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

            fsCreateFileHook.Dispose();
            EasyHook.LocalHook.Release ();
        }

        #region CreateFileW Hook

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate IntPtr CreateFileW_Delegate(
            string InFileName,
            int InDesiredAccess,
            int InShareMode,
            IntPtr InSecurityAttributes,
            int InCreationDisposition,
            int InFlagsAndAttributes,
            IntPtr InTemplateFile);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern IntPtr CreateFile(
            string InFileName,
            int InDesiredAccess,
            int InShareMode,
            IntPtr InSecurityAttributes,
            int InCreationDisposition,
            int InFlagsAndAttributes,
            IntPtr InTemplateFile);

        static IntPtr CreateFile_Hook(
            string InFileName,
            int InDesiredAccess,
            int InShareMode,
            IntPtr InSecurityAttributes,
            int InCreationDisposition,
            int InFlagsAndAttributes,
            IntPtr InTemplateFile)
        {
            
            try
            {
                Main This = (Main)HookRuntimeInfo.Callback;

                lock (This.Queue)
                {
                    This.Queue.Push("[" + RemoteHooking.GetCurrentProcessId() + ":" + 
                        RemoteHooking.GetCurrentThreadId() +  "]: \"" + InFileName + "\"");
                }
            }
            catch
            {
            }

            return CreateFile(
                InFileName,
                InDesiredAccess,
                InShareMode,
                InSecurityAttributes,
                InCreationDisposition,
                InFlagsAndAttributes,
                InTemplateFile);
        }

        #endregion

    }

}