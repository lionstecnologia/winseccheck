<#
    FASE 1 - CORRECOES SEGURAS - SERVIDOR PRODOCTOR
    Nenhuma destas mudancas afeta o acesso das estacoes ao ProDoctor/Ponto4.
    Cada item pede confirmacao. Execute como Administrador.
#>
#Requires -RunAsAdministrator

function Confirmar([string]$Texto) { (Read-Host "$Texto [S/N]") -match '^(s|sim)$' }
function Ok([string]$t)    { Write-Host "  [OK] $t" -ForegroundColor Green }
function Falha([string]$t) { Write-Host "  [FALHA] $t" -ForegroundColor Red }

Write-Host "`n=== 1. Area de Trabalho Remota: exigir NLA ===" -ForegroundColor Cyan
if (Confirmar 'Ativar autenticacao em nivel de rede (NLA)?') {
    try {
        Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1 -ErrorAction Stop
        Ok 'NLA ativado (vale para as proximas conexoes RDP).'
    } catch { Falha $_.Exception.Message }
}

Write-Host "`n=== 2. Servicos com caminho sem aspas ===" -ForegroundColor Cyan
$servicos = @{
    'CobianBackup11'                  = '"C:\Program Files (x86)\Cobian Backup 11\cbService.exe"'
    'FirebirdGuardianDefaultInstance' = '"C:\Program Files (x86)\Firebird\Firebird_2_0\bin\fbguard.exe" -s'
    'FirebirdServerDefaultInstance'   = '"C:\Program Files (x86)\Firebird\Firebird_2_0\bin\fbserver.exe" -s'
}
if (Confirmar 'Corrigir os 3 servicos (vale no proximo inicio do servico, nada e reiniciado agora)?') {
    foreach ($nome in $servicos.Keys) {
        $chave = "HKLM:\SYSTEM\CurrentControlSet\Services\$nome"
        try {
            $atual = (Get-ItemProperty $chave -ErrorAction Stop).ImagePath
            if ($atual -match '^\s*"') { Ok "$nome ja estava correto."; continue }
            Set-ItemProperty $chave -Name ImagePath -Value $servicos[$nome] -ErrorAction Stop
            Ok "$nome -> $($servicos[$nome])"
        } catch { Falha "$nome : $($_.Exception.Message)" }
    }
}

Write-Host "`n=== 3. Remover AnyDesk ===" -ForegroundColor Cyan
$anydesk = @('C:\Program Files (x86)\AnyDesk\AnyDesk.exe', 'C:\Program Files\AnyDesk\AnyDesk.exe') | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $anydesk) { Ok 'AnyDesk nao encontrado.' }
elseif (Confirmar 'Desinstalar o AnyDesk? (o MeshCentral continua funcionando)') {
    try {
        Start-Process -FilePath $anydesk -ArgumentList '--remove', '--silent' -Wait -ErrorAction Stop
        Start-Sleep -Seconds 5
        if (Test-Path $anydesk) { Falha 'AnyDesk ainda presente. Desinstale pelo Painel de Controle.' } else { Ok 'AnyDesk removido.' }
    } catch { Falha $_.Exception.Message }
}

Write-Host "`n=== 4. Como as estacoes acessam as pastas (diagnostico) ===" -ForegroundColor Cyan
$sessoes = @(Get-SmbSession -ErrorAction SilentlyContinue)
if ($sessoes.Count -eq 0) {
    Write-Host '  Nenhuma estacao conectada agora. Repita este diagnostico em horario de expediente:' -ForegroundColor Yellow
    Write-Host '  Get-SmbSession | Select-Object ClientComputerName, ClientUserName, Dialect' -ForegroundColor Yellow
} else {
    $sessoes | Select-Object ClientComputerName, ClientUserName, Dialect | Format-Table -AutoSize
    if ($sessoes | Where-Object { $_.ClientUserName -match 'Convidado|Guest|AN.NIMO|ANONYMOUS' }) {
        Write-Host '  ATENCAO: estacoes entram como Convidado. NAO desative o Convidado antes de criar um usuario para elas.' -ForegroundColor Yellow
    }
    if ($sessoes | Where-Object { "$($_.Dialect)" -like '1*' }) {
        Write-Host '  ATENCAO: ha estacoes usando SMBv1. NAO desative o SMBv1 ainda.' -ForegroundColor Yellow
    }
}

Write-Host "`nFase 1 concluida." -ForegroundColor Green
