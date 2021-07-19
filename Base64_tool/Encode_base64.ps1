# codificar en Base64
$Text = {echo ‘Hi Pentesting con Powershell’}
$Text
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText
powershell.exe -enc $EncodedText