# https://stackoverflow.com/q/49063153
$wshell = New-Object -ComObject Wscript.Shell
$answer = $wshell.Popup("Сброс состояния ВМ! Продолжить?", 0, "Hyper-V", 48+4)
if($answer -eq 7) { exit }

if ((Get-VM CentOSVM).State -ne 'Off') {
    Stop-VM CentOSVM
}
$PathHDD = (Get-VMHardDiskDrive CentOSVM).Path
$PathParent = (Get-Item $PathHDD).Directory.FullName
while ([IO.Path]::GetExtension($PathHDD) -eq ".avhdx") {
    Write-Host("Ожидание окончания слияния...")
    Start-Sleep -s 5
    $PathHDD = (Get-VMHardDiskDrive CentOSVM).Path
}
Write-Host "Копирование шаблона виртуальной машины..."
Copy-Item "$PathParent\CentOSTemplate.vhdx" $PathHDD
# Start-VM CentOSVM
# vmconnect localhost CentOSVM
