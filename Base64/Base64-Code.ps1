function Base64-Code
{
<#

 - Example (Encode) : Base64-Code encode -string "Hello"
 - Example (Decode) : Base64-Code decode -string "SABlAGwAbABvAA=="

#>
    Param(
       [parameter(Mandatory=$true)]
       [String] $order,
       [parameter(Mandatory=$true)]
       [String] $string
    )            

    switch ( $order )
    {
        'Decode' { $DecodedText=([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($string)));(echo "result: $DecodedText") }
        'Encode' { $EncodedText=($Bytes=[System.Text.Encoding]::Unicode.GetBytes($string));($EncodedText=[Convert]::ToBase64String($Bytes));(echo "result: $EncodedText") }
    }

}






