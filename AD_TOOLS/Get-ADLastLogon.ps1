<#
.SYNOPSIS
    Gets the last logon date for each user account in Active Directory. 

.DESCRIPTION
    The get-lastlogon command will connect to each domain controller and get the lastlogon value for each Active Directory User. 

    By default results will be displayed on the console but can easily be export to CSV or HTML. 

.EXAMPLES

    Example 1: Get a list of all users last logon date, displays grid

    Get-ADLastLogon

    Example 2: Get all users last logon and export to csv file

    Get-ADLastLogon -ExportCSV -ExportPath c:\it\exportcsv.csv

    Example 2: Get all users last logon convert and export to HTML   

    Get-ADLastLogon -ExportHTML -ExportPath c:\it\exporthtml.html

    Example 3: Set as a scheduled task to export to csv

    powershell.exe -command ". c:\pathto-getadlastlogon.ps1; get-adlastlogon -ExportCSV -exportPath c:\pathto-export.csv


.NOTES
    Author: Robert Allen
    https://activedirectorypro.com

    Change Log
    V1.00, 4/13/2019 - Initial version
#>

$Header = @"
<style>
TABLE {border-width: 1px; border-style: solid; border-color: black; border-collapse: collapse;}
TH {border-width: 1px; padding: 3px; border-style: solid; border-color: black; background-color: #6495ED;}
TD {border-width: 1px; padding: 3px; border-style: solid; border-color: black;}
</style>
"@

function Get-ADLastLogon{

[CmdletBinding()]
    param(
        [Parameter()]
        [switch]$ExportCSV,

        [Parameter()]
        [switch]$ExportHTML,

        [Parameter()]
        [string]$ExportPath
        )

    Begin{

        $data = @()
        try{ 
            Import-Module ActiveDirectory 
           } 
        catch{ 
            Write-Warning "The Active Directory module was not found. Make sure you have the RSAT tools installed." 
             } 
        Try{
            $DCs = Get-ADDomainController -filter * -ErrorAction Stop -ErrorVariable CurrentError | select -ExpandProperty Name
           }
        catch{
            Write-Warning "An error occured with domain controller $DCs"
             }
          }#end begin block

    Process{

         foreach($d in $DCs) # loops through each DC
            {
            write-host "Proccessing logons for $d"
              $allUsers = Get-ADUser -filter *  -properties LastLogon -Server $d | select Name,SamAccountName,LastLogon
              foreach($a in $allUsers)
              {
                #check if the SamAccountName already exists in the $data table
                if($data.SamAccountName -contains $a.SamAccountName)
                {
                  #Finds SamAccountName in table and sets it to $index (indexof does this)
                  $index = $data.SamAccountName.IndexOf($a.SamAccountName)
    
                 #is lastlogon of user in the table less than current user in the loop if so update table with currest user in the loop
                  if($data[$index].LastLogon -lt $a.LastLogon)
    
                  {
                     $data[$index].LastLogon = $a.LastLogon
                     $data[$index].LastDC = $d
                  }
                }
                else
                {
                #If user doesn't exist in the $data table then add the user
                  $data += [PSCustomObject]@{Name = $a.Name
                                           SamAccountName = $a.SamAccountName
                                           LastLogon = $a.LastLogon
                                           LastDC = $d
                                            }
                }
              }
              write-host "Done processing $d"
            }
            write-host "Done processing logons from all domain controllers"

       }#end process block

    End{
        if ($ExportCSV.IsPresent) {
             $data | select Name, samaccountname, LastDC, @{Name="Last Logon Date";Expression={ If ($_.lastLogon) { [datetime]::FromFileTime($_.lastLogon) } Else { "None" }}} | sort "Last Logon Date" | Export-Csv -Path $ExportPath -NoTypeInformation
            }
        elseif ($ExportHTML.IsPresent) {
             $data | select Name, samaccountname, LastDC, @{Name="Last Logon Date";Expression={ If ($_.lastLogon) { [datetime]::FromFileTime($_.lastLogon) } Else { "None" }}} | sort "Last Logon Date" | ConvertTo-Html -Head $Header | Out-File -FilePath $ExportPath
            }
        else {
             $data | select Name, samaccountname, LastDC, @{Name="Last Logon Date";Expression={ If ($_.lastLogon) { [datetime]::FromFileTime($_.lastLogon) } Else { "None" }}} | sort "Last Logon Date" | Out-GridView
            }
    }#end block

}#end function
 
   