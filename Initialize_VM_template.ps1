# Проверка перед инициализацией
if ((Get-VM CentOSVM -ErrorAction SilentlyContinue).Count -ne 0) {
    Write-Host "Перед инициализацией удалите виртуальную машину CentOSVM вручную"
    $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
    exit
}
$imgFilename = "CentOS-7-x86_64-Minimal-2003.iso"
if (-not (Test-Path $imgFilename -PathType Leaf)) {
    Write-Host "Не найден ISO-образ $imgFilename"
    $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
    exit
}

Write-Host "Создание шаблона виртуальной машины"
# Создание ВМ: 2 поколение, 2 Гб ОЗУ, сеть, новый диск 50 Гб
New-VM CentOSVM -Generation 2 -MemoryStartupBytes 2GB -SwitchName "Default Switch" -NewVHDPath "$(Get-VMHost | Select-Object -expand VirtualHardDiskPath)\CentOSDisk.vhdx" -NewVHDSizeBytes 50GB
if( -not $? ) { # https://stackoverflow.com/q/17461079
    $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
    exit
}
# Подключить новый виртуальный привод с указанным образом ISO
Add-VMDvdDrive CentOSVM -Path $imgFilename
# Загрузка с виртуального привода, шаблон безопасности "Центр сертификации Microsoft UEFI" (без этого не происходит загрузка из образа)
Set-VMFirmware CentOSVM -FirstBootDevice $(Get-VMDvdDrive CentOSVM) -SecureBootTemplate MicrosoftUEFICertificateAuthority
# Запуск ВМ
Start-VM CentOSVM
# Открыть ВМ в окне для продолжения ручной установки
vmconnect localhost CentOSVM

Write-Host "Для продолжения произведите инсталляцию и завершите работу ВМ"
Write-Host "Шаги установки:
* Install CentOS 7
* English > Continue
* Installation Destination > Done
* Network & Host Name > On > Done
* Begin Installation
* Root Password > (Указать пароль) > Done (нажать 2 раза, если пароль короткий)
* Reboot"

Write-Host "Ожидание завершения работы ВМ..."
while ((Get-VM CentOSVM).State -ne 'Off') {
    Start-Sleep -s 5
}
$PathHDD = (Get-VMHardDiskDrive CentOSVM).Path
$PathParent = (Get-Item $PathHDD).Directory.FullName
while ([IO.Path]::GetExtension($PathHDD) -eq ".avhdx") {
    Write-Host("Ожидание окончания слияния...")
    Start-Sleep -s 5
    $PathHDD = (Get-VMHardDiskDrive CentOSVM).Path
}
Write-Host "Копирование шаблона виртуальной машины..."
Copy-Item $PathHDD "$PathParent\CentOSTemplate.vhdx"
