$path = "web.config"
$xml = [xml](Get-Content $path)
$url = $xml.SelectSingleNode("/configuration/appSettings/add[@key='ida:FederationMetadataLocation']").Value

$dest = "App_Data/sts.xml"
Invoke-WebRequest -Uri $url -OutFile $dest 