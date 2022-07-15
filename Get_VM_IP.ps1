function Get-IP {
    $mac = (Get-VM -Name CentOSVM).NetworkAdapters.MacAddress
    # If MAC is available find corresponding IP in ARP cache
    if($mac -ne "000000000000") {
        # Get-NetNeighbor returns MACs with '-' separator, so remove it during search
        # Select only last record if there are more than one
        return (Get-NetNeighbor | Where {$_.LinkLayerAddress -replace "-", "" -eq $mac} | Select-Object -Last 1).IPAddress
    }
}

$ip = Get-IP
if (-not $ip) {
    if ((Get-VM CentOSVM).State -eq 'Off') {
        Start-VM CentOSVM
    }
    while (-not $ip) {
        $ip = Get-IP
        Start-Sleep 5
    }
}
return $ip
