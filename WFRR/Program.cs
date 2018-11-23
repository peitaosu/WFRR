using System;
using System.Diagnostics;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Runtime.InteropServices;
using NDesk.Options;

namespace WFRR {
    class Program {
        static void Main (string[] args) {
            Int32 targetPID = 0;
            string targetExe = null;
            string targetArg = "";
            string inject = "all";

            // Will contain the name of the IPC server channel
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

            try
            {
                parser.Parse(args);
            }
            catch (OptionException e)
            {
                Console.WriteLine("[ERROR]: " + e.Message);
                Console.WriteLine();
                isShowHelp = true;
            }

            if (isBackground)
            {
                var hWnd = GetConsoleWindow();
                ShowWindow(hWnd, 0);
            }

            if (isShowHelp || (targetPID <= 0 && targetExe == null) )
            {
                Console.WriteLine("Usage: WFRR.exe [OPTIONS]");
                Console.WriteLine();
                Console.WriteLine("Options:");
                parser.WriteOptionDescriptions(Console.Out);
                return;
            }

            if (targetPID <= 0 && string.IsNullOrEmpty (targetExe))
                return;

            // Create the IPC server using the RegHook.ServiceInterface class as a singleton
            EasyHook.RemoteHooking.IpcCreateServer<RegHook.ServerInterface>(ref regChannelName, System.Runtime.Remoting.WellKnownObjectMode.Singleton);

            // Create the IPC server using the FSHook.ServiceInterface class as a singleton
            EasyHook.RemoteHooking.IpcCreateServer<FSHook.ServerInterface>(ref fsChannelName, System.Runtime.Remoting.WellKnownObjectMode.Singleton);

            // Get the full path to the assembly we want to inject into the target process
            string injectionRegLibrary = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "RegHook.dll");
            string injectionFSLibrary = Path.Combine(Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location), "FSHook.dll");

            try
            {
                if (inject == "all" || inject == "reg")
                {
                    if (targetPID > 0)
                    {
                        // Injecting into existing process by Id
                        Console.WriteLine("Attempting to inject into process {0}", targetPID);

                        // inject into existing process
                        EasyHook.RemoteHooking.Inject(
                            targetPID, // ID of process to inject into
                            injectionRegLibrary, // 32-bit library to inject (if target is 32-bit)
                            injectionRegLibrary, // 64-bit library to inject (if target is 64-bit)
                            regChannelName // the parameters to pass into injected library
                                           // ...
                        );
                    }
                    else if (!string.IsNullOrEmpty(targetExe))
                    {
                        // Create a new process and then inject into it
                        Console.WriteLine("Attempting to create and inject into {0}", targetExe);

                        // start and inject into a new process
                        EasyHook.RemoteHooking.CreateAndInject(
                            targetExe, // executable to run
                            targetArg, // command line arguments for target
                            0, // additional process creation flags to pass to CreateProcess
                            EasyHook.InjectionOptions.DoNotRequireStrongName, // allow injectionLibrary to be unsigned
                            injectionRegLibrary, // 32-bit library to inject (if target is 32-bit)
                            injectionRegLibrary, // 64-bit library to inject (if target is 64-bit)
                            out targetPID, // retrieve the newly created process ID
                            regChannelName // the parameters to pass into injected library
                                           // ...
                        );
                    }
                }

                if (inject == "all" || inject == "file"){
                    if (targetPID > 0)
                    {
                        // Injecting into existing process by Id
                        Console.WriteLine("Attempting to inject into process {0}", targetPID);

                        // inject into existing process
                        EasyHook.RemoteHooking.Inject(
                            targetPID, // ID of process to inject into
                            injectionFSLibrary, // 32-bit library to inject (if target is 32-bit)
                            injectionFSLibrary, // 64-bit library to inject (if target is 64-bit)
                            fsChannelName // the parameters to pass into injected library
                                          // ...
                        );
                    }
                    else if (!string.IsNullOrEmpty(targetExe))
                    {
                        // Create a new process and then inject into it
                        Console.WriteLine("Attempting to create and inject into {0}", targetExe);

                        // start and inject into a new process
                        EasyHook.RemoteHooking.CreateAndInject(
                            targetExe, // executable to run
                            targetArg, // command line arguments for target
                            0, // additional process creation flags to pass to CreateProcess
                            EasyHook.InjectionOptions.DoNotRequireStrongName, // allow injectionLibrary to be unsigned
                            injectionFSLibrary, // 32-bit library to inject (if target is 32-bit)
                            injectionFSLibrary, // 64-bit library to inject (if target is 64-bit)
                            out targetPID, // retrieve the newly created process ID
                            fsChannelName // the parameters to pass into injected library
                                          // ...
                        );
                    }
                }
            } catch (Exception e) {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine ("There was an error while injecting into target:");
                Console.ResetColor ();
                Console.WriteLine (e.ToString ());
            }

            while (ProcessAlive(targetPID))
            {
                Thread.Sleep(10000);
            }
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine ("<The process has exited, will auto exit in 5 seconds.>");
            Console.ResetColor ();
            Thread.Sleep(5000);
        }

        static int FindProcessIdByName(string name)
        {
            Console.WriteLine("Find Process: " + name);
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

        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    }
}