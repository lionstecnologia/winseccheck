\xef\xbb\xbf<#
    FIREWALL FINAL - SERVIDOR PRODOCTOR (192.168.2.7)
    Revisado a partir da varredura WinSecServer de 23/10/2026.

    O que faz:
      1. Cria regras que liberam SOMENTE para a rede local (192.168.2.x):
         PostgreSQL (ProDoctor), Firebird (Ponto4), pastas compartilhadas,
         resolucao de nome, ping e Area de Trabalho Remota.
      2. Liga o firewall.
      3. SEGURANCA: se voce nao confirmar em 10 minutos que as estacoes
         funcionam, o firewall e desligado automaticamente.

    Bloqueado propositalmente: AnyDesk (7070), WinRM (5985/47001) e porta 8942.
    O MeshCentral continua funcionando (a conexao dele e de saida).

    Execute como Administrador, FORA do horario de atendimento.
    Para desfazer tudo:  Remove-NetFirewallRule -Group 'WinSecServer'; Set-NetFirewallProfile -All -Enabled False
#>
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$Grupo   = 'WinSecServer'
$Rede    = 'LocalSubnet'
$Tarefa  = 'WinSecServer-Rollback'
$Minutos = 10

function Add-Regra {
    param([string]$Nome, [string]$Protocolo, $Porta, [string]$Programa)
    $p = @{
        DisplayName = "WinSecServer - $Nome"; Group = $Grupo; Direction = 'Inbound'; Action = 'Allow'
        Protocol = $Protocolo; RemoteAddress = $Rede; Profile = 'Any'
    }
    if ($Porta)    { $p.LocalPort = $Porta }
    if ($Programa) {
        if (-not (Test-Path $Programa)) { Write-Host "  [AVISO] Programa nao encontrado: $Programa" -ForegroundColor Yellow }
        $p.Program = $Programa
    }
    New-NetFirewallRule @p | Out-Null
    Write-Host "  [OK] $Nome" -ForegroundColor Green
}

Write-Host "`n=== Criando regras (somente rede local) ===" -ForegroundColor Cyan
Remove-NetFirewallRule -Group $Grupo -ErrorAction SilentlyContinue

# Bancos de dados
Add-Regra 'PostgreSQL ProDoctor - TCP 5432' 'TCP' 5432 'C:\Program Files\PostgreSQL\9.4\bin\postgres.exe'
# Firebird sem porta fixa: cobre a 3050 e a porta auxiliar de eventos (aleatoria no Firebird 2.0)
Add-Regra 'Firebird Ponto4 - todas as portas do fbserver' 'TCP' $null 'C:\Program Files (x86)\Firebird\Firebird_2_0\bin\fbserver.exe'

# Pastas compartilhadas (ProDoctorCorp e Ponto4) e resolucao de nome
Add-Regra 'Compartilhamento de arquivos - TCP 445' 'TCP' 445
Add-Regra 'Sessao NetBIOS - TCP 139' 'TCP' 139
Add-Regra 'Nome e datagrama NetBIOS - UDP 137-138' 'UDP' @(137, 138)

# Administracao
Add-Regra 'Area de Trabalho Remota - TCP 3389' 'TCP' 3389
New-NetFirewallRule -DisplayName 'WinSecServer - Ping' -Group $Grupo -Direction Inbound -Action Allow `
    -Protocol ICMPv4 -IcmpType 8 -RemoteAddress $Rede -Profile Any | Out-Null
Write-Host '  [OK] Ping (ICMP)' -ForegroundColor Green

# ---- Reversao automatica de seguranca ----
Write-Host "`n=== Agendando reversao automatica em $Minutos minutos ===" -ForegroundColor Cyan
$quando = (Get-Date).AddMinutes($Minutos)
& schtasks.exe /Create /TN $Tarefa /TR 'powershell.exe -NoProfile -Command Set-NetFirewallProfile -All -Enabled False' `
    /SC ONCE /SD $quando.ToString('d') /ST $quando.ToString('HH:mm') /RU SYSTEM /RL HIGHEST /F | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host 'Nao foi possivel agendar a reversao automatica. Firewall NAO sera ligado.' -ForegroundColor Red
    return
}

# ---- Liga o firewall ----
Set-NetFirewallProfile -All -Enabled True
Write-Host "`nFIREWALL LIGADO." -ForegroundColor Green
Write-Host @"

Teste AGORA em uma estacao:
  1. Abra o ProDoctor e consulte um paciente.
  2. Abra o Ponto4 e registre/consulte algo.
  3. Abra \\PRODOCTOR\ProDoctorCorp e \\PRODOCTOR\Ponto4 no Explorer.

Se nao confirmar ate $($quando.ToString('HH:mm')), o firewall sera desligado sozinho.
"@ -ForegroundColor Yellow

$r = Read-Host 'Tudo funcionou? Digite SIM para manter o firewall ligado'
& schtasks.exe /Delete /TN $Tarefa /F 2>$null | Out-Null
if ($r -match '^(s|sim)$') {
    Write-Host "`nFirewall mantido LIGADO. Regras ativas:" -ForegroundColor Green
    Get-NetFirewallRule -Group $Grupo | Format-Table DisplayName, Enabled -AutoSize
} else {
    Set-NetFirewallProfile -All -Enabled False
    Write-Host "`nFirewall DESLIGADO novamente. As regras foram mantidas; informe o que falhou para ajustar." -ForegroundColor Yellow
}

<#
  ETAPA OPCIONAL - apos 1 semana sem problemas:
  desative as regras amplas antigas (liberadas para qualquer origem).
  As regras WinSecServer acima ja cobrem a rede local.

  Disable-NetFirewallRule -DisplayName 'PostgreSQL'
  Disable-NetFirewallRule -DisplayName 'Compartilhamento de Arquivo e Impressora (SMB-Entrada)'
  Disable-NetFirewallRule -DisplayName 'Compartilhamento de Arquivo e Impressora (NB-Sessão-Entrada)'
  Disable-NetFirewallRule -DisplayName 'Área de Trabalho Remota - Modo de Usuário (TCP-Entrada)'
  Disable-NetFirewallRule -DisplayName 'Gerenciamento Remoto do Windows (HTTP-In)'
#>
