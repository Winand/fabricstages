<# .SYNOPSIS
    Скрипт для запуска задач на указанном сервере из списка settings.json/servers
    .DESCRIPTION
    Вспомогательный скрипт для команды fab. Адрес сервера в settings.json может
    содержать вычисляемое выражение.
    Синтаксис: ./fabr server_alias task_name task_arguments...
#>

$server, $taskargs = $args # https://stackoverflow.com/a/53372181
$settings = Get-Content "settings.json" | ConvertFrom-Json  # PSCustomObject
# property by name: https://docs.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-pscustomobject#dynamically-accessing-properties
# args: https://www.red-gate.com/simple-talk/sysadmin/powershell/how-to-use-parameters-in-powershell/
# Split нужен в случае, если в строке подключения указаны несколько параметров
$conn = $ExecutionContext.InvokeCommand.ExpandString($settings.servers.($server)).Split()
Write-Host "Подключение к серверу $conn..."
if ($taskargs.Count -gt 0 -and $taskargs[0].StartsWith('-')) {  # Не указано имя задачи
    # Prepend array with element: https://stackoverflow.com/a/2201722
    $taskargs = ,"main" + $taskargs  # Добавляем название задачи по умолчанию
}
fab -H $conn $taskargs
