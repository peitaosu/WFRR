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
        VFS _vfs = null;

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
                vfs_json = Environment.ExpandEnvironmentVariables(vfs_json);
                _vfs = JsonConvert.DeserializeObject<VFS> (vfs_json);
            } catch (Exception e) {
                _server.ReportException (e);
            }

            var fsCreateFileHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("kernel32.dll", "CreateFileW"),
                new WinAPI.CreateFileW_Delegate(CreateFile_Hook),
                this);
            fsCreateFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "File: CreateFileW hook installed");

            var fsDeleteFileHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("kernel32.dll", "DeleteFileW"),
                new WinAPI.DeleteFileW_Delegate(DeleteFile_Hook),
                this);
            fsDeleteFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "File: DeleteFileW hook installed");

            var fsCopyFileHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("kernel32.dll", "CopyFileW"),
                new WinAPI.CopyFileW_Delegate(CopyFile_Hook),
                this);
            fsCopyFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "File: CopyFileW hook installed");

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
            fsDeleteFileHook.Dispose();
            fsCopyFileHook.Dispose();
            EasyHook.LocalHook.Release ();
        }

        IntPtr CreateFile_Hook(
            string InFileName,
            int InDesiredAccess,
            int InShareMode,
            IntPtr InSecurityAttributes,
            int InCreationDisposition,
            int InFlagsAndAttributes,
            IntPtr InTemplateFile)
        {

            foreach (VFSMapping map in _vfs.Mapping)
            {
                if (InFileName.Contains(map.Source))
                {
                    string OriInFileName = InFileName;
                    InFileName = InFileName.Replace(map.Source, map.Destination);
                    this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: Original Path {2} has been redirected to {3}",
                                EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), OriInFileName, InFileName));
                    break;
                }
            }
            try
            {
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {

                        this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: Create {2}",
                                EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), InFileName));
                    }
                }
            }
            catch { }

            return WinAPI.CreateFile(
                InFileName,
                InDesiredAccess,
                InShareMode,
                InSecurityAttributes,
                InCreationDisposition,
                InFlagsAndAttributes,
                InTemplateFile);
        }

        bool ReadFileEx_Hook(
            IntPtr hFile,
            [Out] byte[] lpBuffer,
            uint nNumberOfBytesToRead,
            [In] ref System.Threading.NativeOverlapped lpOverlapped,
            System.Threading.IOCompletionCallback lpCompletionRoutine)
        {
            try
            {
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {

                        this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: Read {2}",
                                EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), hFile));
                    }
                }
            }
            catch { }

            return WinAPI.ReadFileEx(
                hFile,
                lpBuffer,
                nNumberOfBytesToRead,
                ref lpOverlapped,
                lpCompletionRoutine);

        }

        bool GetFileSize_Hook(
            IntPtr hFile,
            out long lpFileSize)
        {

            try
            {
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {

                        this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: Get Size {2}",
                                EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), hFile));
                    }
                }
            }
            catch { }

            return WinAPI.GetFileSize(
                hFile,
                out lpFileSize);
        }

        bool GetFileTime_Hook(
            IntPtr hFile,
            IntPtr lpCreationTime,
            IntPtr lpLastAccessTime,
            IntPtr lpLastWriteTime)
        {

            try
            {
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {

                        this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: Get Time {2} {3}",
                                EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), hFile, lpLastWriteTime));
                    }
                }
            }
            catch { }

            return WinAPI.GetFileTime(
                hFile,
                lpCreationTime,
                lpLastAccessTime,
                lpLastWriteTime);
        }

        IntPtr DeleteFile_Hook(
            string lpFileName)
        {

            foreach (VFSMapping map in _vfs.Mapping)
            {
                if (lpFileName.Contains(map.Source))
                {
                    string OrilpFileName = lpFileName;
                    lpFileName = lpFileName.Replace(map.Source, map.Destination);
                    this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: Original Path {2} has been redirected to {3}",
                                EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), OrilpFileName, lpFileName));
                    break;
                }
            }
            try
            {
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {

                        this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: Delete {2}",
                                EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), lpFileName));
                    }
                }
            }
            catch { }

            return WinAPI.DeleteFile(
                lpFileName);
        }

        bool CopyFile_Hook(
            string lpExistingFileName,
            string lpNewFileName,
            bool bFailIfExists)
        {
            foreach (VFSMapping map in _vfs.Mapping)
            {
                if (lpExistingFileName.Contains(map.Source))
                {
                    string OrilpExistingFileName = lpExistingFileName;
                    lpExistingFileName = lpExistingFileName.Replace(map.Source, map.Destination);
                    this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: Original Path {2} has been redirected to {3}",
                                EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), OrilpExistingFileName, lpExistingFileName));
                    break;
                }
            }
            foreach (VFSMapping map in _vfs.Mapping)
            {
                if (lpNewFileName.Contains(map.Source))
                {
                    string OrilpNewFileName = lpNewFileName;
                    lpNewFileName = lpNewFileName.Replace(map.Source, map.Destination);
                    this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: Original Path {2} has been redirected to {3}",
                                EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), OrilpNewFileName, lpNewFileName));
                    break;
                }

            }

            try
            {
                lock (this._messageQueue)
                {
                    if (this._messageQueue.Count < 1000)
                    {

                        this._messageQueue.Enqueue(
                            string.Format("[{0}:{1}]: Copy {2} {3}",
                                EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), lpExistingFileName, lpNewFileName));
                    }
                }
            }
            catch { }

            return WinAPI.CopyFileW(
                lpExistingFileName,
                lpNewFileName,
                bFailIfExists);
        }

    }

}