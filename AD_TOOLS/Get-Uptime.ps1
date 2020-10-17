<#
.SYNOPSIS
    Gets the uptime from a single computer or all computers from an organizationl unit. 

.DESCRIPTION
   Gets the uptime from a single computer or all computers from an organizationl unit.

.EXAMPLE
    Get the uptime from a single computer

    Get-Uptime -ComputerName pc1

    Get uptime from all computers from an organization unit

    Get-Uptime -OU   

.NOTES
    Author:Robert Allen
    https://activedirectorypro.com

    Change Log
    V1.0, 3/30/2019 - Initial version
#>

Function Get-Uptime {
 
    [CmdletBinding()]
 
    Param (
        [Parameter(ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true)]
 
        [string[]]$ComputerName,        
        [Switch]$ErrorLog,
        [string]$Logfile = 'c:\it\errorlog.txt',
        [Switch]$OU
     
        )
    
     if ($ou.IsPresent) {

     $oulist = Get-ADOrganizationalUnit -filter * | select DistinguishedName | Out-GridView -PassThru | Select-Object -ExpandProperty DistinguishedName
     $computers = Get-ADComputer -filter * -Properties * -SearchBase $oulist | select name -ExpandProperty name
        
     Foreach ($Computer in $computers) {
            Try{
                $OS = Get-WmiObject Win32_OperatingSystem -ComputerName $Computer -ErrorAction Stop -ErrorVariable CurrentError
                $Uptime = (Get-Date) - $OS.ConvertToDateTime($OS.LastBootUpTime)

                $Properties = @{ComputerName  = $Computer
                                LastBoot      = $OS.ConvertToDateTime($OS.LastBootUpTime)
                                Uptime        = ([String]$Uptime.Days + " Days " + $Uptime.Hours + " Hours " + $Uptime.Minutes + " Minutes")
                                }
 
                $Obj = New-Object -TypeName PSObject -Property $Properties | Select ComputerName, LastBoot, UpTime

                write-host "Added $Computer to report"

               
               [Array]$objs+=$Obj #Add it
             
 
                } 
            catch{

               Write-Warning "An error occured on $Computer"
               if ($ErrorLog) {
                    Get-Date | Out-File $LogFile -Append
                    $Computer | Out-File $LogFile -Append
                    $CurrentError | out-file $LogFile -Append
                 }
                
            } 
        }

        $Objs |Sort-Object LastBoot #Add it
    }

     else {

        Try{
                $OS = Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName -ErrorAction Stop -ErrorVariable CurrentError
                $Uptime = (Get-Date) - $OS.ConvertToDateTime($OS.LastBootUpTime)

                $Properties = @{ComputerName  = $ComputerName
                                LastBoot      = $OS.ConvertToDateTime($OS.LastBootUpTime)
                                Uptime        = ([String]$Uptime.Days + " Days " + $Uptime.Hours + " Hours " + $Uptime.Minutes + " Minutes")
                                }
 
                $Obj2 = New-Object -TypeName PSObject -Property $Properties | Select ComputerName, LastBoot, UpTime

                $obj2
             
           }

         catch{

               Write-Warning "Computer $ComputerName had the following error $CurrentError"
 
            
              }  

          }

}

