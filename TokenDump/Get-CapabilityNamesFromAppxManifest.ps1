function Get-CapabilityNamesFromAppxManifest {
    [OutputType([System.Collections.Arraylist])]
    Param(
        [Parameter(Position=0, Mandatory=$True, ValueFromPipelineByPropertyName = $True)]
        [string]$XmlPath
    )

    $CapabilityNames = [System.Collections.Arraylist]@()

    try {
        $AppxManifestXml = [XML](Get-Content -Path $XmlPath)
        $AppxManifestXml.Package.Capabilities.Capability | %{ $CapabilityNames.Add($_.Name) | Out-Null }
    } catch {
        Write-Warning "The specified file may not be AppxManifest.xml"
    }

    [System.Collections.Arraylist]$CapabilityNames
}

$CapabilityList = [System.Collections.Arraylist]@()
$AppxManifestXmlPaths = Get-ChildItem -Recurse C:\Windows\SystemApps\ | ?{ $_.Name -ieq "appxmanifest.xml" } | %{ $_.FullName }

foreach ($ManifestXml in $AppxManifestXmlPaths) {
    $Capabilities = Get-CapabilityNamesFromAppxManifest -XmlPath $ManifestXml

    if ($Capabilities -ne $null) {
        if ($Capabilities.GetType() -eq [String]) {
            $CapabilityList.Add($Capabilities) | Out-Null
        } else {
            $CapabilityList.AddRange($Capabilities)
        }
    }
}

$Results = $CapabilityList | Sort-Object | Get-Unique

foreach ($CapabilityName in $Results) {
    Write-Host $CapabilityName
}