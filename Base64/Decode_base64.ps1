# Decode test base64
$EncodedText =
“ZQBjAGgAbwAgABggSABpACAAUABlAG4AdABlAHMAdABpAG4AZwAgAGMAb
wBuACAAUABvAHcAZQByAHMAaABlAGwAbAAZIA==”
$DecodedText =
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedText))
$DecodedText