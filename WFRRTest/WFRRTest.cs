using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace WFRRTest
{
    class WFRRTest
    {
        static bool is_bg = false;
        static string file_placeholder_txt = @"_placeholder_.txt";
        static string file_new_txt = @"_test_.txt";
        static string reg_key = @"Software\WFRR\Test";
        static string reg_value = @"TestValue";
        static string reg_data = @"TestData";
        static string reg_key_new = @"Software\WFRR\Test";
        static string reg_value_new = @"NewValue";
        static string reg_data_new = @"NewData";

        static void Main(string[] args)
        {
            while (true)
            {
                try
                {
                    string input = Console.ReadLine();
                    string[] command = input.Split('|');
                    if (command[0] == "exit")
                        break;
                    switch (command[0])
                    {
                        case "file":
                            file(command);
                            break;
                        case "reg":
                            reg(command);
                            break;
                        case "test":
                            test(command);
                            break;
                        case "bg":
                            is_bg = true;
                            break;
                        case "info":
                            info();
                            break;
                        default:
                            break;
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("[ERROR] {0} {1}", e.GetType().Name, e.Message);
                }
            }
        }

        static void info()
        {
            Console.WriteLine(@"file|exec\read\new\delete\write\load|path");
            Console.WriteLine(@"reg|get\set\new\delete|root|key|value|data");
            Console.WriteLine(@"test");
            Console.WriteLine(@"bg");
            Console.WriteLine(@"info");
            Console.WriteLine(@"exit");
        }

        static void file(string[] args)
        {
            string operation = args[1].ToLower();
            string path = args[2];
            switch (operation)
            {
                case "exec":
                    Process process = new Process();
                    process.StartInfo.FileName = path.Substring(0, path.IndexOf(".exe") + 4);
                    if (path.Split(' ').Length > 1)
                    {
                        process.StartInfo.Arguments = path.Substring(process.StartInfo.FileName.Length);
                    }
                    if (is_bg)
                    {
                        process.StartInfo.UseShellExecute = false;
                        process.StartInfo.CreateNoWindow = true;
                    }
                    process.Start();
                    if (is_bg)
                    {
                        Console.WriteLine(string.Format("Process {0}", path));
                    }
                    else
                    {
                        process.WaitForExit();
                        Console.WriteLine(string.Format("Process {0} Exit Code {1}", path, process.ExitCode));
                    }
                    break;
                case "read":
                    string text = File.ReadAllText(path);
                    Console.WriteLine(string.Format("File {0} Text Content {1}", path, text));
                    break;
                case "new":
                    File.Create(path).Dispose();
                    bool added = false;
                    if (File.Exists(path))
                    {
                        added = true;
                    }
                    Console.WriteLine(string.Format("File {0} Create Status {1}", path, added));
                    break;
                case "delete":
                    if (!File.Exists(path))
                    {
                        throw new FileNotFoundException();
                    }
                    File.Delete(path);
                    bool deleted = false;
                    if (!File.Exists(path))
                    {
                        deleted = true;
                    }
                    Console.WriteLine(string.Format("File {0} Delete Status {1}", path, deleted));
                    break;
                case "write":
                    if (!File.Exists(path))
                    {
                        throw new FileNotFoundException();
                    }
                    string test = Guid.NewGuid().ToString();
                    File.AppendAllText(path, test);
                    bool appended = false;
                    if (File.ReadAllText(path).EndsWith(test))
                    {
                        appended = true;
                    }
                    Console.WriteLine(string.Format("File {0} Write Status {1}", path, appended));
                    break;
                case "load":
                    bool loaded = false;
                    IntPtr module = LoadLibraryEx(path, IntPtr.Zero, 0);
                    loaded = true;
                    Console.WriteLine(string.Format("File {0} Load Status {1}", path, loaded));
                    break;
                default:
                    break;
            }
        }

        static void reg(string[] args)
        {
            string operation = args[1].ToLower();
            string reg_root = args[2].ToUpper();
            string reg_key = args[3];
            string reg_value = args[4];
            string reg_data = args[5];

            RegistryKey root;
            switch (reg_root)
            {
                case "HKEY_LOCAL_MACHINE":
                    root = Registry.LocalMachine;
                    break;
                case "HKEY_CURRENT_USER":
                    root = Registry.CurrentUser;
                    break;
                case "HKEY_CLASSES_ROOT":
                    root = Registry.ClassesRoot;
                    break;
                case "HKEY_USERS":
                    root = Registry.Users;
                    break;
                case "HKEY_CURRENT_CONFIG":
                    root = Registry.CurrentConfig;
                    break;
                default:
                    root = Registry.CurrentUser;
                    break;
            }
            switch (operation)
            {
                case "get":
                    RegistryKey get_key = root.OpenSubKey(reg_key, false);
                    var result = get_key.GetValue(reg_value);
                    Console.WriteLine(string.Format(@"Reg {0}\{1} {2} Get {3}", reg_root, reg_key, reg_value, result));
                    break;
                case "set":
                    RegistryKey set_key = root.OpenSubKey(reg_key, true);
                    set_key.SetValue(reg_value, reg_data);
                    Console.WriteLine(string.Format(@"Reg {0}\{1} {2} Set {3}", reg_root, reg_key, reg_value, reg_data));
                    break;
                case "new":
                    if (reg_value != "")
                    {
                        RegistryKey new_key = root.OpenSubKey(reg_key, true);
                        new_key.SetValue(reg_value, reg_data);
                    }
                    else
                    {
                        RegistryKey new_key = root.CreateSubKey(reg_key);
                    }
                    Console.WriteLine(string.Format(@"Reg New {0}\{1} {2} {3}", reg_root, reg_key, reg_value, reg_data));
                    break;
                case "delete":
                    if (reg_value != "")
                    {
                        RegistryKey del_key = root.OpenSubKey(reg_key, true);
                        del_key.DeleteValue(reg_value);
                    }
                    else
                    {
                        root.DeleteSubKey(reg_key);
                    }
                    Console.WriteLine(string.Format(@"Reg Delete {0}\{1} {2} {3}", reg_root, reg_key, reg_value, reg_data));
                    break;
                default:
                    break;
            }
        }

        static void test(string[] args)
        {

            Dictionary<string, string> vfs_paths = new Dictionary<string, string>();
            vfs_paths.Add("AppData", Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
            vfs_paths.Add("LocalAppData", Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
            vfs_paths.Add("CommonAppData", Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
            vfs_paths.Add("CommonDesktop", Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory));
            vfs_paths.Add("CommonDocuments", Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments));
            vfs_paths.Add("CommonPrograms", Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms));
            vfs_paths.Add("Fonts", Environment.GetFolderPath(Environment.SpecialFolder.Fonts));
            vfs_paths.Add("CommonProgramFiles", Environment.GetFolderPath(Environment.SpecialFolder.CommonProgramFiles));
            vfs_paths.Add("CommonProgramFilesX86", Environment.GetFolderPath(Environment.SpecialFolder.CommonProgramFilesX86));
            vfs_paths.Add("ProgramFiles", Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            vfs_paths.Add("ProgramFilesX86", Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
            vfs_paths.Add("System", Environment.GetFolderPath(Environment.SpecialFolder.System));
            vfs_paths.Add("Windows", Environment.GetFolderPath(Environment.SpecialFolder.Windows));

            Dictionary<string, Dictionary<string, string>> result = new Dictionary<string, Dictionary<string, string>>();
            Dictionary<string, string> ops;
            string status;

            foreach (var vfs_path in vfs_paths)
            {
                ops = new Dictionary<string, string>();
                status = "None";
                try
                {
                    string path = Path.Combine(vfs_path.Value, file_placeholder_txt);
                    file(new string[] { "file", "read", path });
                    status = "Success";
                }
                catch (FileNotFoundException)
                {
                    status = "File Not Found";
                }
                catch (UnauthorizedAccessException)
                {
                    status = "Access Denied";
                }
                ops.Add("Read", status);
                Console.WriteLine("{0} : {1} : {2}", vfs_path.Key, "Read", status);

                try
                {
                    string path = Path.Combine(vfs_path.Value, file_placeholder_txt);
                    file(new string[] { "file", "write", path });
                    status = "Success";
                }
                catch (FileNotFoundException)
                {
                    status = "File Not Found";
                }
                catch (UnauthorizedAccessException)
                {
                    status = "Access Denied";
                }
                ops.Add("Write", status);
                Console.WriteLine("{0} : {1} : {2}", vfs_path.Key, "Write", status);

                try
                {
                    string path = Path.Combine(vfs_path.Value, file_new_txt);
                    file(new string[] { "file", "new", path });
                    status = "Success";
                }
                catch (FileNotFoundException)
                {
                    status = "File Not Found";
                }
                catch (UnauthorizedAccessException)
                {
                    status = "Access Denied";
                }
                ops.Add("New", status);
                Console.WriteLine("{0} : {1} : {2}", vfs_path.Key, "New", status);

                try
                {
                    string path = Path.Combine(vfs_path.Value, file_new_txt);
                    file(new string[] { "file", "delete", path });
                    status = "Success";
                }
                catch (FileNotFoundException)
                {
                    status = "File Not Found";
                }
                catch (UnauthorizedAccessException)
                {
                    status = "Access Denied";
                }
                ops.Add("Delete", status);
                Console.WriteLine("{0} : {1} : {2}", vfs_path.Key, "Delete", status);

                result.Add(vfs_path.Key, ops);
            }

            foreach (string reg_root in new string[] { "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE" })
            {

                ops = new Dictionary<string, string>();

                status = "None";
                try
                {
                    reg(new string[] { "reg", "get", reg_root, reg_key, reg_value, reg_data });
                    status = "Success";
                }
                catch (UnauthorizedAccessException)
                {
                    status = "Access Denied";
                }
                catch (NullReferenceException)
                {
                    status = "Null Reference";
                }
                catch (SecurityException)
                {
                    status = "Security";
                }
                ops.Add("Get", status);
                Console.WriteLine("{0} : {1} : {2}", reg_root, "Get", status);

                status = "None";
                try
                {
                    reg(new string[] { "reg", "set", reg_root, reg_key, reg_value, reg_data_new });
                    status = "Success";
                }
                catch (UnauthorizedAccessException)
                {
                    status = "Access Denied";
                }
                catch (NullReferenceException)
                {
                    status = "Null Reference";
                }
                catch (SecurityException)
                {
                    status = "Security";
                }
                ops.Add("Set", status);
                Console.WriteLine("{0} : {1} : {2}", reg_root, "Set", status);

                status = "None";
                try
                {
                    reg(new string[] { "reg", "new", reg_root, reg_key_new, "", "" });
                    reg(new string[] { "reg", "new", reg_root, reg_key_new, reg_value_new, reg_value_new });
                    status = "Success";
                }
                catch (UnauthorizedAccessException)
                {
                    status = "Access Denied";
                }
                catch (NullReferenceException)
                {
                    status = "Null Reference";
                }
                catch (SecurityException)
                {
                    status = "Security";
                }
                ops.Add("New", status);
                Console.WriteLine("{0} : {1} : {2}", reg_root, "New", status);

                status = "None";
                try
                {
                    reg(new string[] { "reg", "delete", reg_root, reg_key_new, reg_value_new, reg_value_new });
                    reg(new string[] { "reg", "delete", reg_root, reg_key_new, "", "" });
                    status = "Success";
                }
                catch (UnauthorizedAccessException)
                {
                    status = "Access Denied";
                }
                catch (NullReferenceException)
                {
                    status = "Null Reference";
                }
                catch (SecurityException)
                {
                    status = "Security";
                }
                ops.Add("Delete", status);
                Console.WriteLine("{0} : {1} : {2}", reg_root, "Delete", status);

                result.Add(reg_root, ops);
            }
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

    }
}
