## Invocar site
$WebResponse = Invoke-WebRequest "http://www.contoso.com"
$WebResponse

## Se puede canalizar el objeto a Get-Member para obtener una descripción general de las propiedades del objeto
$WebResponse.GetType()
$WebResponse| Get-Member

## Parsear HTML. La propiedad RawContent, que incluye los campos de encabezado HTTP que devolvió el servidor web. 
$WebResponse.Content

## También puede leer solo los campos de encabezado HTTP
$WebResponse.Headers

## También puede resultar útil mostrar los códigos de estado de respuesta HTTP y sus descripciones:
$WebResponse.StatusCode
$WebResponse.StatusDescription

## La propiedad Vínculos es una matriz de objetos que contiene todos los hipervínculos de la página web.
## Las propiedades más interesantes de un objeto de enlace son innerHTML, innerText, outerHTML y href.
$WebResponse.Links | Select-Object href


## Almacena objetos con propiedades que contienen código HTML que hace referencia a las imágenes. 
## Las propiedades más interesantes son width, height, alt y src.
$WebResponse= Invoke-WebRequest "https://www.marca.com/multimedia/primeras/21/07/0719.html?intcmp=BOTONPORTADA&s_kw=portada-del-dia"
ForEach ($Image in $WebResponse.Images)
{
 $FileName = Split-Path $Image.src -Leaf
 Invoke-WebRequest $Image.src -OutFile $FileName
}

## AllElements contiene todos los elementos HTML que contiene la página.
$WebResponse.AllElements
$WebResponse.AllElements | Where-Object {$_.TagName -eq "a"}

## Envar un formulario HTML
Invoke-WebRequest "https://4sysops.com/index.php?s=powershell"

## Averiguar qué método se utiliza mostrando los objetos de formularios:
$WebResponse = Invoke-WebRequest "https://twitter.com"
$WebResponse.Forms

## Inspeccionar formulario y la columna Campos.
$WebResponse.Forms.Fields

## Determinar el campo de formulario de un sitio web Whois
#$Fields = @{"search_type" = "Whois";"query" = "134.170.185.46"}
$Fields = @{"searchString" = "134.170.185.46"}
$WebResponse = Invoke-WebRequest -Uri "https://who.is/domains/search" -Method Post -Body $Fields
$Pre = $WebResponse.AllElements | Where-Object {$_.TagName -eq "pre"}
If ($Pre -match "country:\s+(\w{2})")
{
 Write-Host "Country code:" $Matches[1]
}