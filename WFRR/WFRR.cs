using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using System.Runtime.InteropServices;
using System.Reflection;
using NDesk.Options;
using log4net;
using log4net.Config;

namespace WFRR
{
    class WFRR
    {
        private static readonly ILog _log = LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

        static void Main(string[] args)
        {
            XmlConfigurator.Configure();

            Int32 targetPID = 0;
            string targetExe = null;
            string targetArg = "";
            string inject = "all";

            string regChannelName = null;
            string fsChannelName = null;

            bool isShowHelp = false;
            bool isBackground = false;
            var parser = new OptionSet() {
                { "e|exe=", "the executable file to launch and inject.",
                   v => { if (v != null) targetExe = v; } },
                { "a|arg=", "the arguments of executable file to launch and inject.",
                   v => { if (v != null) targetArg = v; } },
                { "n|pname=", "the name of process want to inject.",
                    v => { if (v != null) targetPID = FindProcessIdByName(v); } },
                { "i|pid=", "the id of process want to inject.",
                    v => { if (v != null) targetPID = Int32.Parse(v); } },
                { "all", "inject file hook and registry hook.",
                   v => { if (v != null) inject="all"; } },
                { "file", "inject file hook only.",
                   v => { if (v != null) inject="file"; } },
                { "reg", "inject registry hook only.",
                   v => { if (v != null) inject="reg"; } },
                { "b|bg", "runs in background.",
                   v => isBackground = v != null },
                { "h|help", "show help messages.",
                   v => isShowHelp = v != null },
            };

            GetInfo();

            try
            {
                parser.Parse(args);
                _log.Info("[WFRR] Arguments: " + string.Join(" ", args));
            }
            catch (OptionException e)
            {
                _log.Error("[WFRR] " + e.Message);
                Console.WriteLine();
                isShowHelp = true;
            }

            if (isBackground)
            {
                var hWnd = GetConsoleWindow();
                ShowWindow(hWnd, 0);
            }

            if (isShowHelp || (targetPID <= 0 && targetExe == null))
            {
                Console.WriteLine("Usage: WFRR.exe [OPTIONS]");
                Console.WriteLine();
                Console.WriteLine("Options:");
                parser.WriteOptionDescriptions(Console.Out);
                return;
            }

            if (targetPID <= 0 && string.IsNullOrEmpty(targetExe))
                return;
            
            if (targetPID <= 0)
            {
                string processArch = "32bit";
                if (System.Environment.Is64BitProcess)
                    processArch = "64bit";
                string exeArch = "32bit";
                if (GetMachineType(targetExe) == MachineType.x64)
                    exeArch = "64bit";
                if(processArch != exeArch)
                {
                    _log.Error("You are using " + processArch + " WFRR to execute " + exeArch + " executable file.");
                    return;
                }
            }

            EasyHook.RemoteHooking.IpcCreateServer<RegHook.ServerInterface>(ref regChannelName, System.Runtime.Remoting.WellKnownObjectMode.Singleton);

            EasyHook.RemoteHooking.IpcCreateServer<FSHook.ServerInterface>(ref fsChannelName, System.Runtime.Remoting.WellKnownObjectMode.Singleton);

            string injectionRegLibrary = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "RegHook.dll");
            string injectionFSLibrary = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "FSHook.dll");

            try
            {
                if (inject == "all" || inject == "reg")
                {
                    if (targetPID > 0)
                    {
                        _log.Info("[WFRR] Attempting to inject into process: " + targetPID);
                        EasyHook.RemoteHooking.Inject(
                            targetPID,
                            injectionRegLibrary,
                            injectionRegLibrary,
                            regChannelName
                        );
                    }
                    else if (!string.IsNullOrEmpty(targetExe))
                    {
                        _log.Info("[WFRR] Attempting to create and inject into: " + targetExe);
                        EasyHook.RemoteHooking.CreateAndInject(
                            targetExe,
                            targetArg,
                            0,
                            EasyHook.InjectionOptions.DoNotRequireStrongName,
                            injectionRegLibrary,
                            injectionRegLibrary,
                            out targetPID,
                            regChannelName
                        );
                    }
                }

                if (inject == "all" || inject == "file")
                {
                    if (targetPID > 0)
                    {
                        _log.Info("[WFRR] Attempting to inject into process: " + targetPID);
                        EasyHook.RemoteHooking.Inject(
                            targetPID,
                            injectionFSLibrary,
                            injectionFSLibrary,
                            fsChannelName
                        );
                    }
                    else if (!string.IsNullOrEmpty(targetExe))
                    {
                        _log.Info("[WFRR] Attempting to create and inject into: " + targetExe);
                        EasyHook.RemoteHooking.CreateAndInject(
                            targetExe,
                            targetArg,
                            0,
                            EasyHook.InjectionOptions.DoNotRequireStrongName,
                            injectionFSLibrary,
                            injectionFSLibrary,
                            out targetPID,
                            fsChannelName
                        );
                    }
                }
            }
            catch (Exception e)
            {
                _log.Error("[WFRR] There was an error while injecting into target: " + e.ToString());
            }

            while (ProcessAlive(targetPID))
            {
                Thread.Sleep(10000);
            }
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("<The process has exited, will auto exit in 5 seconds.>");
            Console.ResetColor();
            Thread.Sleep(5000);
        }

        static int FindProcessIdByName(string name)
        {
            _log.Info("[WFRR] Looking for process: " + name);
            while (true)
            {
                Process[] processlist = Process.GetProcesses();
                foreach (Process theprocess in processlist)
                {
                    if (string.Equals(name.Substring(0, name.Length - 4), theprocess.ProcessName, StringComparison.OrdinalIgnoreCase))
                    {
                        return theprocess.Id;
                    }
                }
            }
        }

        static bool ProcessAlive(int pid)
        {
            return Process.GetProcesses().Any(x => x.Id == pid);
        }

        static void GetInfo()
        {
            _log.Info("[WFRR] OS Version: " + System.Environment.OSVersion);
            _log.Info("[WFRR] OS 64bit: " + System.Environment.Is64BitOperatingSystem);
            _log.Info("[WFRR] WFRR Version: " + Assembly.GetExecutingAssembly().GetName().Version);
            _log.Info("[WFRR] WFRR 64bit: " + System.Environment.Is64BitProcess);
#if DEBUG
            _log.Debug("[WFRR] WFRR Debug: True");
#else
            _log.Info("[WFRR] WFRR Debug: False");
#endif
        }

        public enum MachineType
        {
            Native = 0, I386 = 0x014c, Itanium = 0x0200, x64 = 0x8664
        }

        public static MachineType GetMachineType(string fileName)
        {
            const int PE_POINTER_OFFSET = 60;
            const int MACHINE_OFFSET = 4;
            byte[] data = new byte[4096];
            using (Stream s = new FileStream(fileName, FileMode.Open, FileAccess.Read))
            {
                s.Read(data, 0, 4096);
            }
            // dos header is 64 bytes, last element, long (4 bytes) is the address of the PE header
            int PE_HEADER_ADDR = BitConverter.ToInt32(data, PE_POINTER_OFFSET);
            int machineUint = BitConverter.ToUInt16(data, PE_HEADER_ADDR + MACHINE_OFFSET);
            return (MachineType)machineUint;
        }

        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    }
}