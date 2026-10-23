# =====================================================================
#  WinSecCheck - Instalador remoto
#  Uso:   irm https://raw.githubusercontent.com/lionstecnologia/winseccheck/main/install.ps1 | iex
#  Com parametros:
#         & ([scriptblock]::Create((irm https://raw.githubusercontent.com/lionstecnologia/winseccheck/main/install.ps1))) -Modo Auditoria
# =====================================================================
& {
    $ErrorActionPreference = 'Stop'

    # ---- AJUSTE ESTES ENDERECOS APOS PUBLICAR NO GITHUB ----
    $UrlInstalador = 'https://raw.githubusercontent.com/lionstecnologia/winseccheck/main/install.ps1'
    $UrlScript     = 'https://raw.githubusercontent.com/lionstecnologia/winseccheck/main/WinSecCheck.ps1'
    $HashEsperado  = ''   # Opcional: SHA256 do WinSecCheck.ps1 (recomendado)
    # ---------------------------------------------------------

    $UrlServidor   = 'https://raw.githubusercontent.com/lionstecnologia/winseccheck/main/WinSecServer.ps1'
    $HashServidor  = ''   # Opcional: SHA256 do WinSecServer.ps1

    $Destino      = Join-Path $env:ProgramData 'WinSecCheck\app\WinSecCheck.ps1'
    $ArgsRepassar = @($args)

    # -Servidor: baixa e executa a varredura de servidor (WinSecServer.ps1)
    if ($ArgsRepassar -contains '-Servidor') {
        $UrlScript    = $UrlServidor
        $HashEsperado = $HashServidor
        $Destino      = Join-Path $env:ProgramData 'WinSecCheck\app\WinSecServer.ps1'
        $ArgsSemFlag  = @($ArgsRepassar | Where-Object { $_ -ne '-Servidor' })
    } else {
        $ArgsSemFlag  = $ArgsRepassar
    }

    # TLS 1.2 (necessario em Windows/PowerShell mais antigos)
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    # ---- Verifica versao do PowerShell (o WinSecCheck exige 5.1) ----
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Host "PowerShell $($PSVersionTable.PSVersion) detectado. O WinSecCheck exige o PowerShell 5.1." -ForegroundColor Red
        Write-Host 'Instale o Windows Management Framework 5.1 (KB3191564) e reinicie o computador:' -ForegroundColor Yellow
        Write-Host '  https://www.microsoft.com/download/details.aspx?id=54616' -ForegroundColor Yellow
        return
    }

    # ---- Elevacao automatica para Administrador ----
    $identidade = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = ([Security.Principal.WindowsPrincipal]$identidade).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host 'Solicitando permissao de Administrador...' -ForegroundColor Yellow
        $argTexto = ($ArgsRepassar | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ' '
        $comando  = "[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; & ([scriptblock]::Create((Invoke-RestMethod '$UrlInstalador'))) $argTexto"
        $codificado = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($comando))
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -NoExit -EncodedCommand $codificado"
        return
    }

    # ---- Download do script principal (como arquivo, sem corromper) ----
    New-Item -ItemType Directory -Path (Split-Path $Destino) -Force | Out-Null
    Write-Host "Baixando $(Split-Path $Destino -Leaf)..." -ForegroundColor Cyan
    try {
        Invoke-WebRequest -Uri $UrlScript -OutFile $Destino -UseBasicParsing
    } catch {
        Write-Host "Falha no download: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # ---- Verificacao de integridade ----
    if ($HashEsperado) {
        $hash = (Get-FileHash -Path $Destino -Algorithm SHA256).Hash
        if ($hash -ne $HashEsperado.ToUpper()) {
            Remove-Item $Destino -Force
            Write-Host 'ATENCAO: o arquivo baixado nao confere com o hash esperado. Execucao cancelada.' -ForegroundColor Red
            return
        }
    }

    $erros = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($Destino, [ref]$null, [ref]$erros)
    if ($erros) {
        Write-Host "Arquivo baixado com erro de sintaxe (linha $($erros[0].Extent.StartLineNumber)): $($erros[0].Message)" -ForegroundColor Red
        return
    }

    Unblock-File -Path $Destino -ErrorAction SilentlyContinue

    # ---- Execucao (sempre no Windows PowerShell 5.1) ----
    Write-Host 'Iniciando WinSecCheck...' -ForegroundColor Green
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Destino @ArgsSemFlag
} @args
