using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using Newtonsoft.Json;
using log4net;

namespace FSHook
{

    public class ServerInterface : MarshalByRefObject
    {
        private static readonly ILog _log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

        public void IsInstalled(int clientPID)
        {
            _log.Info("[WFRR:FSHook] FSHook has been injected into process: " + clientPID);
        }

        public void ReportMessages(int clientPID, string[] messages)
        {
            for (int i = 0; i < messages.Length; i++)
            {
                _log.Info("[WFRR:FSHook] " + messages[i].Replace("{", "{{").Replace("}", "}}"));
            }
        }

        public void ReportMessage(int clientPID, string message)
        {
            _log.Info("[WFRR:FSHook] " + message);
        }

        public void ReportException(Exception e)
        {
            _log.Error("[WFRR:FSHook] " + e.ToString());
        }

        public void Ping() { }
    }

    public class InjectionEntryPoint : EasyHook.IEntryPoint
    {

        ServerInterface _server = null;

        Queue<string> _messageQueue = new Queue<string>();

        string vfs_path = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "V_FS.json");
        string vfs_json = null;
        VFS _vfs = null;

        public InjectionEntryPoint(
            EasyHook.RemoteHooking.IContext context,
            string channelName)
        {
            _server = EasyHook.RemoteHooking.IpcConnectClient<ServerInterface>(channelName);
            _server.Ping();
        }

        public void Run(
            EasyHook.RemoteHooking.IContext context,
            string channelName)
        {

            _server.IsInstalled(EasyHook.RemoteHooking.GetCurrentProcessId());

            try
            {
                vfs_json = new StreamReader(vfs_path).ReadToEnd();
                _vfs = JsonConvert.DeserializeObject<VFS>(vfs_json);
            }
            catch (Exception e)
            {
                _server.ReportException(e);
            }

            var fsCreateFileHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("kernel32.dll", "CreateFileW"),
                new WinAPI.CreateFileW_Delegate(CreateFile_Hook),
                this);
            fsCreateFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "CreateFileW hook installed");

            var fsDeleteFileHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("kernel32.dll", "DeleteFileW"),
                new WinAPI.DeleteFileW_Delegate(DeleteFile_Hook),
                this);
            fsDeleteFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "DeleteFileW hook installed");

            var fsCopyFileHook = EasyHook.LocalHook.Create(
                EasyHook.LocalHook.GetProcAddress("kernel32.dll", "CopyFileW"),
                new WinAPI.CopyFileW_Delegate(CopyFile_Hook),
                this);
            fsCopyFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            _server.ReportMessage(EasyHook.RemoteHooking.GetCurrentProcessId(), "CopyFileW hook installed");

            EasyHook.RemoteHooking.WakeUpProcess();

            try
            {
                while (true)
                {
                    System.Threading.Thread.Sleep(500);

                    string[] queued = null;

                    lock (_messageQueue)
                    {
                        queued = _messageQueue.ToArray();
                        _messageQueue.Clear();
                    }

                    if (queued != null && queued.Length > 0)
                    {
                        _server.ReportMessages(EasyHook.RemoteHooking.GetCurrentProcessId(), queued);
                    }
                    else
                    {
                        _server.Ping();
                    }
                }
            }
            catch { }

            fsCreateFileHook.Dispose();
            fsDeleteFileHook.Dispose();
            fsCopyFileHook.Dispose();
            EasyHook.LocalHook.Release();
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

            this._messageQueue.Enqueue(
                string.Format("[{0}:{1}] Calling CreateFile {2}",
                    EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), InFileName));

            IntPtr result = IntPtr.Zero;
            string fileToCreate = InFileName;

            try
            {
                foreach (VFSMapping map in _vfs.Mapping)
                {
                    if (InFileName.Contains(map.Source))
                    {
                        fileToCreate = InFileName.Replace(map.Source, map.Destination);
                        result = WinAPI.CreateFile(fileToCreate, InDesiredAccess, InShareMode, InSecurityAttributes, InCreationDisposition, InFlagsAndAttributes, InTemplateFile);
                        this._messageQueue.Enqueue(
                                string.Format("[{0}:{1}] [Redirected] CreateFile {2} return code: {3}",
                                    EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), fileToCreate, result));
                        if (result == new IntPtr(-1))
                        {
                            break;
                        }
                        else
                        {
                            return result;
                        }
                    }
                }

                this._messageQueue.Enqueue(
                    string.Format("[{0}:{1}] Calling from original location...",
                        EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId()));
                result = WinAPI.CreateFile(InFileName, InDesiredAccess, InShareMode, InSecurityAttributes, InCreationDisposition, InFlagsAndAttributes, InTemplateFile);
                this._messageQueue.Enqueue(
                        string.Format("[{0}:{1}] [Origin] CreateFile {2} return code: {3}",
                            EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), InFileName, result));
                return result;
            }
            catch (Exception e)
            {
                this._messageQueue.Enqueue(e.Message);
            }
            return result;
        }

        bool DeleteFile_Hook(
            string lpFileName)
        {

            this._messageQueue.Enqueue(
                string.Format("[{0}:{1}] Calling DeleteFile {2}",
                    EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), lpFileName));

            bool result = false;
            string fileToDelete = lpFileName;

            try
            {
                foreach (VFSMapping map in _vfs.Mapping)
                {
                    if (lpFileName.Contains(map.Source))
                    {
                        fileToDelete = lpFileName.Replace(map.Source, map.Destination);
                        result = WinAPI.DeleteFile(fileToDelete);
                        this._messageQueue.Enqueue(
                                string.Format("[{0}:{1}] [Redirected] DeleteFile {2} return code: {3}",
                                    EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), fileToDelete, result));
                        if (!result)
                        {
                            break;
                        }
                        else
                        {
                            return result;
                        }
                    }
                }

                this._messageQueue.Enqueue(
                    string.Format("[{0}:{1}] Calling from original location...",
                        EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId()));
                result = WinAPI.DeleteFile(lpFileName);
                this._messageQueue.Enqueue(
                        string.Format("[{0}:{1}] [Origin] CreateFile {2} return code: {3}",
                            EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), lpFileName, result));
                return result;
            }
            catch (Exception e)
            {
                this._messageQueue.Enqueue(e.Message);
            }
            return result;
        }

        bool CopyFile_Hook(
            string lpExistingFileName,
            string lpNewFileName,
            bool bFailIfExists)
        {
            this._messageQueue.Enqueue(
                string.Format("[{0}:{1}] Calling CopyFile {2} to {3}",
                    EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), lpExistingFileName, lpNewFileName));

            bool result = false;
            string fileToCopy = lpExistingFileName;
            string fileCopyTo = lpNewFileName;

            try
            {
                foreach (VFSMapping map in _vfs.Mapping)
                {
                    if (lpExistingFileName.Contains(map.Source))
                    {
                        fileToCopy = lpExistingFileName.Replace(map.Source, map.Destination);
                    }
                    if (lpNewFileName.Contains(map.Source))
                    {
                        fileCopyTo = lpNewFileName.Replace(map.Source, map.Destination);
                    }
                }
                result = WinAPI.CopyFileW(fileToCopy, fileCopyTo, bFailIfExists);
                this._messageQueue.Enqueue(
                        string.Format("[{0}:{1}] [Redirected] CopyFile {2} to {3} return code: {4}",
                            EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), fileToCopy, fileCopyTo, result));
                if (result)
                    return result;

                result = WinAPI.CopyFileW(lpExistingFileName, fileCopyTo, bFailIfExists);
                this._messageQueue.Enqueue(
                        string.Format("[{0}:{1}] [Redirected] CopyFile {2} to {3} return code: {4}",
                            EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), lpExistingFileName, fileCopyTo, result));
                if (result)
                    return result;

                result = WinAPI.CopyFileW(fileToCopy, lpNewFileName, bFailIfExists);
                this._messageQueue.Enqueue(
                        string.Format("[{0}:{1}] [Redirected] CopyFile {2} to {3} return code: {4}",
                            EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), fileToCopy, lpNewFileName, result));
                if (result)
                    return result;

                result = WinAPI.CopyFileW(lpExistingFileName, lpNewFileName, bFailIfExists);
                this._messageQueue.Enqueue(
                        string.Format("[{0}:{1}] [Origin] CopyFile {2} to {3} return code: {4}",
                            EasyHook.RemoteHooking.GetCurrentProcessId(), EasyHook.RemoteHooking.GetCurrentThreadId(), lpExistingFileName, lpNewFileName, result));
                if (result)
                    return result;
            }
            catch (Exception e)
            {
                this._messageQueue.Enqueue(e.Message);
            }
            return result;
        }
    }
}