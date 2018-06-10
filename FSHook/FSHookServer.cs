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
                _vfs = JsonConvert.DeserializeObject<VFS> (vfs_json);
            } catch (Exception e) {
                _server.ReportException (e);
            }

            var fsCreateFileHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("kernel32.dll", "CreateFileW"),
                new CreateFileW_Delegate(CreateFile_Hook),
                this);

            var fsDeleteFileHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("kernel32.dll", "DeleteFileW"),
                new DeleteFileW_Delegate(DeleteFile_Hook),
                this);

            var fsReadFileHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("kernel32.dll", "ReadFileEx"),
                new ReadFileEx_Delegate(ReadFileEx_Hook),
                this);

            var fsGetFileSizeHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("kernel32.dll", "GetFileSizeEx"),
                new GetFileSizeEx_Delegate(GetFileSize_Hook),
                this);

            var fsGetFileTimeHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("kernel32.dll", "GetFileTime"),
                new GetFileTime_Delegate(GetFileTime_Hook),
                this);
            
            var fsCopyFileHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("kernel32.dll", "CopyFileW"),
                new CopyFileW_Delegate(CopyFile_Hook),
                this);
                
            fsCreateFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            fsDeleteFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            fsReadFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            fsGetFileSizeHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            fsGetFileTimeHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            fsCopyFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "CreateFileW hook installed");
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "DeleteFileW hook installed");
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "ReadFileEx hook installed");
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "GetFileSizeEx hook installed");
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "GetFileTime hook installed");
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "CopyFileEx hook installed");

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
            fsReadFileHook.Dispose();
            fsGetFileSizeHook.Dispose();
            fsGetFileTimeHook.Dispose();
            fsCopyFileHook.Dispose();
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

        IntPtr CreateFile_Hook(
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

        #region ReadFileEx Hook

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool ReadFileEx_Delegate(
            IntPtr hFile,
            [Out] byte[] lpBuffer,
            uint nNumberOfBytesToRead,
            [In] ref System.Threading.NativeOverlapped lpOverlapped,
            System.Threading.IOCompletionCallback lpCompletionRoutine);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern bool ReadFileEx(
            IntPtr hFile,
            [Out] byte[] lpBuffer,
            uint nNumberOfBytesToRead, 
            [In] ref System.Threading.NativeOverlapped lpOverlapped,
            System.Threading.IOCompletionCallback lpCompletionRoutine);

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

            return ReadFileEx(
                hFile,
                lpBuffer,
                nNumberOfBytesToRead,
                ref lpOverlapped,
                lpCompletionRoutine);

        }
        #endregion

        #region GetFileSizeEx Hook

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool GetFileSizeEx_Delegate(
            IntPtr hFile,
            out long lpFileSize);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern bool GetFileSize(
            IntPtr hFile,
            out long lpFileSize);

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

            return GetFileSize(
                hFile,
                out lpFileSize);
        }

        #endregion

        #region GetFileTime Hook
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool GetFileTime_Delegate(
            IntPtr hFile,
            IntPtr lpCreationTime,
            IntPtr lpLastAccessTime,
            IntPtr lpLastWriteTime);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern bool GetFileTime(
            IntPtr hFile,
            IntPtr lpCreationTime,
            IntPtr lpLastAccessTime,
            IntPtr lpLastWriteTime);

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

            return GetFileTime(
                hFile,
                lpCreationTime,
                lpLastAccessTime,
                lpLastWriteTime);
        }

        #endregion

        #region DeleteFileW Hook

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate IntPtr DeleteFileW_Delegate(
            string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern IntPtr DeleteFile(
            string lpFileName);

        IntPtr DeleteFile_Hook(
            string lpFileName)
        {

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

            return DeleteFile(
                lpFileName);
        }

        #endregion

        #region CopyFileEx Hook

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        delegate bool CopyFileW_Delegate(
            string lpExistingFileName,
            string lpNewFileName,
            bool bFailIfExists);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        static extern bool CopyFileEx(
            string lpExistingFileName,
            string lpNewFileName,
            bool bFailIfExists);

        bool CopyFile_Hook(
            string lpExistingFileName,
            string lpNewFileName,
            bool bFailIfExists)
        {

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

            return CopyFileEx(
                lpExistingFileName,
                lpNewFileName,
                bFailIfExists);
        }

        #endregion
    }

}