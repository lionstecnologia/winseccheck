<#
.SYNOPSIS
    WinSecCheck - Auditoria de seguranca, correcao automatica e remocao de bloatware para Windows 10/11.

.DESCRIPTION
    Verifica: antivirus/Defender, firewall, Windows Update, UAC, SMBv1, PowerShell v2,
    conta Convidado, AutoRun, RDP/NLA, WDigest, Secure Boot, TPM, BitLocker, LSA,
    administradores locais, contas sem senha, servicos criticos, disco, uptime,
    travamentos, programas de inicializacao e aplicativos indesejados.
    Corrige o que for seguro corrigir automaticamente (sempre com confirmacao,
    a menos que -Forcar seja usado), cria ponto de restauracao antes das mudancas
    e gera relatorio HTML + CSV + log.

.EXAMPLE
    .\WinSecCheck.ps1
        Abre o menu interativo.
.EXAMPLE
    .\WinSecCheck.ps1 -Modo Auditoria
        Somente leitura. Gera relatorio, nao altera nada.
.EXAMPLE
    .\WinSecCheck.ps1 -Modo Corrigir -RemoverBloatware
        Auditoria + correcoes (pergunta antes de cada uma) + remocao de bloatware.
.EXAMPLE
    .\WinSecCheck.ps1 -Modo Completo -Forcar
        Tudo, sem perguntas (uso em tarefa agendada / implantacao).

.NOTES
    Execute como Administrador no Windows PowerShell 5.1 (powershell.exe):
    powershell.exe -ExecutionPolicy Bypass -File .\WinSecCheck.ps1
#>
#Requires -RunAsAdministrator
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Menu', 'Auditoria', 'Corrigir', 'Completo')]
    [string]$Modo = 'Menu',
    [switch]$Forcar,
    [switch]$RemoverBloatware,
    [switch]$IncluirProvisionados,
    [switch]$SemPontoRestauracao,
    [string]$PastaSaida = "$env:ProgramData\WinSecCheck"
)

# =====================================================================
#  CONFIGURACAO (ajuste conforme a politica da sua empresa)
# =====================================================================
$Config = @{
    DiasMaxAssinaturaDefender = 3
    DiasMaxSemAtualizacao     = 45
    DiasMaxSemVarredura       = 7
    PercentualMinDisco        = 15
    DiasArquivosTemp          = 7
    MaxAdminsLocais           = 2
    DiasMaxUptime             = 14
}

# Apps da Store considerados indesejados (aceita curingas)
$BloatwareAppx = @(
    'Microsoft.BingNews', 'Microsoft.BingWeather', 'Microsoft.BingSearch',
    'Microsoft.GetHelp', 'Microsoft.Getstarted', 'Microsoft.MicrosoftOfficeHub',
    'Microsoft.MicrosoftSolitaireCollection', 'Microsoft.People', 'Microsoft.SkypeApp',
    'Microsoft.WindowsFeedbackHub', 'Microsoft.WindowsMaps', 'Microsoft.MixedReality.Portal',
    'Microsoft.ZuneMusic', 'Microsoft.ZuneVideo', 'Microsoft.549981C3F5F10',
    'Microsoft.XboxApp', 'Microsoft.XboxGamingOverlay', 'Microsoft.XboxGameOverlay',
    'Microsoft.XboxSpeechToTextOverlay', 'Microsoft.Xbox.TCUI', 'Microsoft.GamingApp',
    'Microsoft.PowerAutomateDesktop', 'Microsoft.Todos', 'Microsoft.3DBuilder',
    'Microsoft.Microsoft3DViewer', 'Microsoft.Print3D', 'Microsoft.OneConnect',
    'MicrosoftTeams', 'Clipchamp.Clipchamp', 'MicrosoftCorporationII.MicrosoftFamily',
    'king.com.*', '*CandyCrush*', 'SpotifyAB.SpotifyMusic', 'Disney.*', 'Facebook.*',
    '*TikTok*', '*Instagram*', 'AmazonVideo.PrimeVideo', '*Netflix*', '*Twitter*',
    'BytedancePte.Ltd.TikTok', '*McAfee*', '*Duolingo*', '*HiddenCity*', '*MarchofEmpires*'
)

# Apps que NUNCA devem ser removidos (protecao contra erro na lista acima)
$AppxProtegidos = @(
    'Microsoft.WindowsStore', 'Microsoft.StorePurchaseApp', 'Microsoft.DesktopAppInstaller',
    'Microsoft.WindowsCalculator', 'Microsoft.Windows.Photos', 'Microsoft.WindowsNotepad',
    'Microsoft.WindowsTerminal', 'Microsoft.SecHealthUI', 'Microsoft.VCLibs*', 'Microsoft.NET*',
    'Microsoft.UI.Xaml*', 'Microsoft.WindowsAppRuntime*', 'Microsoft.Paint', 'Microsoft.ScreenSketch',
    'Microsoft.XboxIdentityProvider', 'Microsoft.HEIFImageExtension', 'Microsoft.WebMediaExtensions'
)

# Programas Win32 que merecem revisao manual (nao sao removidos automaticamente)
$Win32Suspeitos = @(
    '*McAfee*', '*WildTangent*', '*Booking.com*', '*Toolbar*', '*Driver Booster*',
    '*Driver Easy*', '*Driver Support*', '*PC Optimizer*', '*Reimage*', '*Restoro*',
    '*Segurazo*', '*SAntivirus*', '*WebDiscover*', '*Wave Browser*', '*OneLaunch*',
    '*Shift Browser*', '*ByteFence*', '*Advanced SystemCare*', '*MyPC Backup*'
)

# Servicos que precisam estar rodando
$ServicosCriticos = @('WinDefend', 'mpssvc', 'BFE', 'EventLog', 'wscsvc', 'CryptSvc')

# =====================================================================
#  INFRAESTRUTURA
# =====================================================================
$script:Resultados = New-Object System.Collections.Generic.List[object]
$script:Acoes      = New-Object System.Collections.Generic.List[object]
$Carimbo = Get-Date -Format 'yyyyMMdd_HHmmss'

if (-not (Test-Path $PastaSaida)) { New-Item -ItemType Directory -Path $PastaSaida -Force | Out-Null }
$ArquivoLog = Join-Path $PastaSaida "log_$Carimbo.txt"

if ($PSVersionTable.PSEdition -eq 'Core') {
    Write-Warning 'Recomendado executar no Windows PowerShell 5.1 (powershell.exe). Modulos Appx/Defender podem falhar no PowerShell 7.'
}

function Write-Etapa([string]$Texto) {
    Write-Host "`n=== $Texto ===" -ForegroundColor Cyan
}

function Add-Resultado {
    param(
        [string]$Categoria,
        [string]$Item,
        [ValidateSet('OK', 'Info', 'Alerta', 'Critico')][string]$Status,
        [string]$Detalhe,
        [string]$Correcao = ''
    )
    $script:Resultados.Add([pscustomobject]@{
        Categoria = $Categoria; Item = $Item; Status = $Status
        Detalhe = $Detalhe; Correcao = $Correcao
    })
    $cor = @{ OK = 'Green'; Info = 'Gray'; Alerta = 'Yellow'; Critico = 'Red' }[$Status]
    Write-Host ("  [{0,-7}] {1}: {2}" -f $Status, $Item, $Detalhe) -ForegroundColor $cor
}

function Add-Acao([string]$Acao, [string]$Resultado) {
    $script:Acoes.Add([pscustomobject]@{ Hora = (Get-Date -Format 'HH:mm:ss'); Acao = $Acao; Resultado = $Resultado })
}

function Confirmar([string]$Mensagem) {
    if ($Forcar) { return $true }
    $r = Read-Host "$Mensagem [S/N]"
    return ($r -match '^(s|sim|y|yes)$')
}

function Get-RegValor([string]$Caminho, [string]$Nome) {
    try { return (Get-ItemProperty -Path $Caminho -Name $Nome -ErrorAction Stop).$Nome } catch { return $null }
}

function Set-RegValor([string]$Caminho, [string]$Nome, $Valor, [string]$Tipo = 'DWord') {
    if (-not (Test-Path $Caminho)) { New-Item -Path $Caminho -Force | Out-Null }
    New-ItemProperty -Path $Caminho -Name $Nome -Value $Valor -PropertyType $Tipo -Force | Out-Null
}

# =====================================================================
#  VERIFICACOES
# =====================================================================
function Test-SistemaOperacional {
    Write-Etapa 'Sistema operacional'
    $os = Get-CimInstance Win32_OperatingSystem
    Add-Resultado 'Sistema' 'Versao' 'Info' "$($os.Caption) build $($os.BuildNumber)"
    if ($os.Caption -match 'Windows 10') {
        Add-Resultado 'Sistema' 'Suporte' 'Alerta' 'Windows 10 encerrou o suporte em 14/10/2025. Migre para Windows 11 ou use ESU.'
    }
    $uptime = (Get-Date) - $os.LastBootUpTime
    if ($uptime.TotalDays -gt $Config.DiasMaxUptime) {
        Add-Resultado 'Sistema' 'Tempo ligado' 'Alerta' ("{0:N0} dias sem reiniciar. Reinicie para aplicar atualizacoes." -f $uptime.TotalDays)
    } else {
        Add-Resultado 'Sistema' 'Tempo ligado' 'OK' ("{0:N1} dias" -f $uptime.TotalDays)
    }
}

function Test-Antivirus {
    Write-Etapa 'Antivirus / Microsoft Defender'
    $outrosAV = @()
    try {
        $av = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop
        $outrosAV = @($av | Where-Object { $_.displayName -notmatch 'Windows Defender|Microsoft Defender' })
        foreach ($a in $av) { Add-Resultado 'Antivirus' 'Produto registrado' 'Info' $a.displayName }
        if ($outrosAV.Count -gt 1) {
            Add-Resultado 'Antivirus' 'Multiplos antivirus' 'Alerta' 'Mais de um antivirus de terceiros instalado: conflitos e lentidao.'
        }
    } catch {
        Add-Resultado 'Antivirus' 'Security Center' 'Info' 'SecurityCenter2 indisponivel (normal em Windows Server).'
    }

    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
    } catch {
        if ($outrosAV.Count -eq 0) { Add-Resultado 'Antivirus' 'Defender' 'Critico' 'Defender inacessivel e nenhum outro antivirus encontrado.' }
        return
    }

    if ($mp.RealTimeProtectionEnabled) {
        Add-Resultado 'Antivirus' 'Protecao em tempo real' 'OK' 'Ativa'
    } elseif ($outrosAV.Count -gt 0) {
        Add-Resultado 'Antivirus' 'Protecao em tempo real' 'Info' 'Defender passivo (outro antivirus ativo).'
        return
    } else {
        Add-Resultado 'Antivirus' 'Protecao em tempo real' 'Critico' 'DESATIVADA' 'DefenderTempoReal'
    }

    if ($mp.AntivirusSignatureAge -gt $Config.DiasMaxAssinaturaDefender) {
        Add-Resultado 'Antivirus' 'Assinaturas' 'Alerta' "Desatualizadas ha $($mp.AntivirusSignatureAge) dias" 'DefenderAssinaturas'
    } else {
        Add-Resultado 'Antivirus' 'Assinaturas' 'OK' "Atualizadas ($($mp.AntivirusSignatureVersion))"
    }

    if ($mp.IsTamperProtected) {
        Add-Resultado 'Antivirus' 'Protecao contra violacao' 'OK' 'Ativa'
    } else {
        Add-Resultado 'Antivirus' 'Protecao contra violacao' 'Alerta' 'Desativada. Ative manualmente em Seguranca do Windows (nao pode ser feito por script).'
    }

    $ultima = $mp.QuickScanEndTime
    if (-not $ultima -or $ultima -lt (Get-Date).AddDays(-$Config.DiasMaxSemVarredura)) {
        Add-Resultado 'Antivirus' 'Ultima varredura' 'Alerta' "Nenhuma varredura nos ultimos $($Config.DiasMaxSemVarredura) dias" 'DefenderVarredura'
    } else {
        Add-Resultado 'Antivirus' 'Ultima varredura' 'OK' $ultima.ToString('dd/MM/yyyy HH:mm')
    }

    $ameacas = @(Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddDays(-30) })
    if ($ameacas.Count -gt 0) {
        $nomes = ($ameacas | ForEach-Object { (Get-MpThreat -ThreatID $_.ThreatID -ErrorAction SilentlyContinue).ThreatName } | Select-Object -Unique) -join ', '
        Add-Resultado 'Antivirus' 'Ameacas (30 dias)' 'Alerta' "$($ameacas.Count) deteccao(oes): $nomes"
    } else {
        Add-Resultado 'Antivirus' 'Ameacas (30 dias)' 'OK' 'Nenhuma'
    }

    $pref = Get-MpPreference
    $exclusoes = @($pref.ExclusionPath) + @($pref.ExclusionProcess) + @($pref.ExclusionExtension) | Where-Object { $_ }
    if ($exclusoes.Count -gt 0) {
        Add-Resultado 'Antivirus' 'Exclusoes do Defender' 'Alerta' ("Revise (malware costuma criar exclusoes): " + ($exclusoes -join '; '))
    } else {
        Add-Resultado 'Antivirus' 'Exclusoes do Defender' 'OK' 'Nenhuma'
    }

    if ($pref.PUAProtection -ne 1) {
        Add-Resultado 'Antivirus' 'Bloqueio de apps indesejados (PUA)' 'Alerta' 'Desativado' 'DefenderPUA'
    } else {
        Add-Resultado 'Antivirus' 'Bloqueio de apps indesejados (PUA)' 'OK' 'Ativo'
    }
}

function Test-Firewall {
    Write-Etapa 'Firewall'
    foreach ($p in Get-NetFirewallProfile) {
        if ("$($p.Enabled)" -eq 'True') {
            Add-Resultado 'Firewall' "Perfil $($p.Name)" 'OK' 'Ativo'
        } else {
            Add-Resultado 'Firewall' "Perfil $($p.Name)" 'Critico' 'DESATIVADO' 'Firewall'
        }
    }
}

function Test-Atualizacoes {
    Write-Etapa 'Windows Update'
    try {
        $ultimo = Get-HotFix -ErrorAction Stop | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($ultimo) {
            $dias = ((Get-Date) - $ultimo.InstalledOn).Days
            $st = if ($dias -gt $Config.DiasMaxSemAtualizacao) { 'Alerta' } else { 'OK' }
            Add-Resultado 'Atualizacoes' 'Ultima atualizacao' $st "$($ultimo.HotFixID) ha $dias dias"
        }
    } catch {}

    Write-Host '  Pesquisando atualizacoes pendentes (pode levar alguns minutos)...' -ForegroundColor DarkGray
    try {
        $sessao = New-Object -ComObject Microsoft.Update.Session
        $res = $sessao.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
        $n = $res.Updates.Count
        if ($n -gt 0) {
            $titulos = @(); foreach ($u in $res.Updates) { $titulos += $u.Title }
            Add-Resultado 'Atualizacoes' 'Pendentes' 'Alerta' "$n pendente(s): $(($titulos | Select-Object -First 3) -join ' | ')" 'WindowsUpdate'
        } else {
            Add-Resultado 'Atualizacoes' 'Pendentes' 'OK' 'Sistema atualizado'
        }
    } catch {
        Add-Resultado 'Atualizacoes' 'Pendentes' 'Info' "Nao foi possivel consultar: $($_.Exception.Message)"
    }

    $reboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
              (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
              ($null -ne (Get-RegValor 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' 'PendingFileRenameOperations'))
    if ($reboot) { Add-Resultado 'Atualizacoes' 'Reinicializacao' 'Alerta' 'Reinicializacao pendente' }
}

function Test-ConfiguracoesSeguranca {
    Write-Etapa 'Configuracoes de seguranca'

    # UAC
    $pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $lua = Get-RegValor $pol 'EnableLUA'
    $cp  = Get-RegValor $pol 'ConsentPromptBehaviorAdmin'
    if ($lua -ne 1)      { Add-Resultado 'Seguranca' 'UAC' 'Critico' 'Controle de Conta de Usuario desativado' 'UAC' }
    elseif ($cp -eq 0)   { Add-Resultado 'Seguranca' 'UAC' 'Alerta' 'UAC eleva privilegios sem perguntar' 'UAC' }
    else                 { Add-Resultado 'Seguranca' 'UAC' 'OK' 'Ativo' }

    # SMBv1
    try {
        $smb1 = (Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop).State
        if ($smb1 -eq 'Enabled') { Add-Resultado 'Seguranca' 'SMBv1' 'Critico' 'Habilitado (vetor do WannaCry)' 'SMB1' }
        else { Add-Resultado 'Seguranca' 'SMBv1' 'OK' 'Desabilitado' }
    } catch {}

    # PowerShell 2.0
    try {
        $ps2 = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop).State
        if ($ps2 -eq 'Enabled') { Add-Resultado 'Seguranca' 'PowerShell 2.0' 'Alerta' 'Habilitado (permite burlar logs e AMSI)' 'PSv2' }
        else { Add-Resultado 'Seguranca' 'PowerShell 2.0' 'OK' 'Desabilitado' }
    } catch {}

    # Conta Convidado (SID -501, independe do idioma)
    $guest = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }
    if ($guest -and $guest.Enabled) { Add-Resultado 'Contas' 'Convidado' 'Critico' 'Conta Convidado habilitada' 'Convidado' }
    else { Add-Resultado 'Contas' 'Convidado' 'OK' 'Desabilitada' }

    # Contas sem senha
    $semSenha = @(Get-LocalUser | Where-Object { $_.Enabled -and -not $_.PasswordRequired })
    if ($semSenha.Count -gt 0) { Add-Resultado 'Contas' 'Contas sem senha obrigatoria' 'Critico' (($semSenha.Name) -join ', ') }
    else { Add-Resultado 'Contas' 'Contas sem senha obrigatoria' 'OK' 'Nenhuma' }

    # Administradores locais
    try {
        $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | Select-Object -ExpandProperty Name)
    } catch {
        $nomeGrupo = (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount]).Value.Split('\')[1]
        $grp = [ADSI]"WinNT://$env:COMPUTERNAME/$nomeGrupo,group"
        $admins = @($grp.Invoke('Members') | ForEach-Object { $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null) })
    }
    $st = if ($admins.Count -gt $Config.MaxAdminsLocais) { 'Alerta' } else { 'OK' }
    Add-Resultado 'Contas' 'Administradores locais' $st "$($admins.Count): $($admins -join ', ')"

    # AutoRun
    if ((Get-RegValor 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun') -ne 255) {
        Add-Resultado 'Seguranca' 'AutoRun/AutoPlay' 'Alerta' 'Habilitado para midias removiveis' 'AutoRun'
    } else { Add-Resultado 'Seguranca' 'AutoRun/AutoPlay' 'OK' 'Desabilitado' }

    # RDP
    $rdpOff = Get-RegValor 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    if ($rdpOff -eq 0) {
        $nla = Get-RegValor 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
        if ($nla -ne 1) { Add-Resultado 'Seguranca' 'Area de Trabalho Remota' 'Critico' 'RDP habilitado SEM NLA' 'RDPNLA' }
        else { Add-Resultado 'Seguranca' 'Area de Trabalho Remota' 'Info' 'RDP habilitado com NLA. Desative se nao usar.' }
    } else { Add-Resultado 'Seguranca' 'Area de Trabalho Remota' 'OK' 'Desabilitada' }

    # WDigest (senhas em texto puro na memoria)
    if ((Get-RegValor 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential') -eq 1) {
        Add-Resultado 'Seguranca' 'WDigest' 'Critico' 'Senhas armazenadas em texto puro na memoria' 'WDigest'
    } else { Add-Resultado 'Seguranca' 'WDigest' 'OK' 'Desativado' }

    # Protecao LSA
    $ppl = Get-RegValor 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL'
    if ($ppl -in 1, 2) { Add-Resultado 'Seguranca' 'Protecao LSA' 'OK' 'Ativa' }
    else { Add-Resultado 'Seguranca' 'Protecao LSA' 'Info' 'Inativa. Avalie ativar (testar drivers antes).' }

    # Secure Boot / TPM / BitLocker
    try {
        if (Confirm-SecureBootUEFI -ErrorAction Stop) { Add-Resultado 'Hardware' 'Secure Boot' 'OK' 'Ativo' }
        else { Add-Resultado 'Hardware' 'Secure Boot' 'Alerta' 'Desativado na UEFI (ativar no setup da placa-mae)' }
    } catch { Add-Resultado 'Hardware' 'Secure Boot' 'Info' 'Nao suportado (BIOS legado)' }

    try {
        $tpm = Get-Tpm -ErrorAction Stop
        if ($tpm.TpmPresent -and $tpm.TpmReady) { Add-Resultado 'Hardware' 'TPM' 'OK' 'Presente e pronto' }
        else { Add-Resultado 'Hardware' 'TPM' 'Alerta' 'Ausente ou nao inicializado' }
    } catch {}

    try {
        $bl = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        if ("$($bl.ProtectionStatus)" -eq 'On') { Add-Resultado 'Hardware' 'BitLocker' 'OK' "Ativo em $env:SystemDrive" }
        else { Add-Resultado 'Hardware' 'BitLocker' 'Alerta' "Disco $env:SystemDrive sem criptografia (ative manualmente e guarde a chave)" }
    } catch { Add-Resultado 'Hardware' 'BitLocker' 'Info' 'Nao disponivel nesta edicao' }
}

function Test-SaudeSistema {
    Write-Etapa 'Saude do sistema'

    foreach ($d in Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3') {
        if (-not $d.Size) { continue }
        $pct = [math]::Round(($d.FreeSpace / $d.Size) * 100, 1)
        $livreGB = [math]::Round($d.FreeSpace / 1GB, 1)
        if ($pct -lt $Config.PercentualMinDisco) {
            Add-Resultado 'Saude' "Disco $($d.DeviceID)" 'Alerta' "$livreGB GB livres ($pct%)" 'LimpezaTemp'
        } else { Add-Resultado 'Saude' "Disco $($d.DeviceID)" 'OK' "$livreGB GB livres ($pct%)" }
    }

    try {
        $falhas = Get-PhysicalDisk -ErrorAction Stop | Where-Object { $_.HealthStatus -ne 'Healthy' }
        foreach ($f in $falhas) { Add-Resultado 'Saude' "Disco fisico $($f.FriendlyName)" 'Critico' "Estado: $($f.HealthStatus). Faca backup!" }
    } catch {}

    foreach ($nome in $ServicosCriticos) {
        $s = Get-Service -Name $nome -ErrorAction SilentlyContinue
        if (-not $s) { continue }
        if ($s.Status -ne 'Running') { Add-Resultado 'Servicos' $s.DisplayName 'Critico' "Status: $($s.Status)" "Servico:$nome" }
        else { Add-Resultado 'Servicos' $s.DisplayName 'OK' 'Em execucao' }
    }

    $quedas = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 41; ProviderName = 'Microsoft-Windows-Kernel-Power'; StartTime = (Get-Date).AddDays(-7) } -ErrorAction SilentlyContinue)
    if ($quedas.Count -gt 0) { Add-Resultado 'Saude' 'Desligamentos inesperados (7 dias)' 'Alerta' "$($quedas.Count) ocorrencia(s): verifique energia, drivers e temperatura" }
    else { Add-Resultado 'Saude' 'Desligamentos inesperados (7 dias)' 'OK' 'Nenhum' }

    $inicio = @(Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue)
    $st = if ($inicio.Count -gt 15) { 'Alerta' } else { 'Info' }
    Add-Resultado 'Saude' 'Programas na inicializacao' $st "$($inicio.Count): $((($inicio.Name) | Select-Object -Unique) -join ', ')"
}

function Get-BloatwareInstalado {
    Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object {
        $pkg = $_
        $alvo = $BloatwareAppx | Where-Object { $pkg.Name -like $_ }
        $prot = $AppxProtegidos | Where-Object { $pkg.Name -like $_ }
        $alvo -and -not $prot -and -not $pkg.NonRemovable
    } | Sort-Object Name -Unique
}

function Get-Win32Suspeitos {
    $chaves = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
              'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
              'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    Get-ItemProperty $chaves -ErrorAction SilentlyContinue | Where-Object {
        $p = $_
        $p.DisplayName -and ($Win32Suspeitos | Where-Object { $p.DisplayName -like $_ })
    } | Sort-Object DisplayName -Unique
}

function Test-Software {
    Write-Etapa 'Aplicativos indesejados'
    $bloat = @(Get-BloatwareInstalado)
    if ($bloat.Count -gt 0) {
        Add-Resultado 'Software' 'Bloatware (Store)' 'Alerta' "$($bloat.Count): $(($bloat.Name) -join ', '). Use a opcao 3 do menu ou -RemoverBloatware."
    } else { Add-Resultado 'Software' 'Bloatware (Store)' 'OK' 'Nenhum encontrado' }

    $w32 = @(Get-Win32Suspeitos)
    if ($w32.Count -gt 0) {
        Add-Resultado 'Software' 'Programas suspeitos/indesejados' 'Alerta' ("Revisar e desinstalar manualmente: " + (($w32.DisplayName) -join ', '))
    } else { Add-Resultado 'Software' 'Programas suspeitos/indesejados' 'OK' 'Nenhum encontrado' }
}

function Invoke-Auditoria {
    $script:Resultados.Clear()
    Test-SistemaOperacional
    Test-Antivirus
    Test-Firewall
    Test-Atualizacoes
    Test-ConfiguracoesSeguranca
    Test-SaudeSistema
    Test-Software
    $c = @($script:Resultados | Where-Object Status -eq 'Critico').Count
    $a = @($script:Resultados | Where-Object Status -eq 'Alerta').Count
    Write-Host ("`nResumo: {0} critico(s), {1} alerta(s). Nota: {2}/100" -f $c, $a, (Get-Nota)) -ForegroundColor White
}

function Get-Nota {
    $c = @($script:Resultados | Where-Object Status -eq 'Critico').Count
    $a = @($script:Resultados | Where-Object Status -eq 'Alerta').Count
    return [math]::Max(0, 100 - ($c * 10) - ($a * 4))
}

# =====================================================================
#  CORRECOES
# =====================================================================
function New-PontoRestauracao {
    if ($SemPontoRestauracao) { return }
    Write-Etapa 'Ponto de restauracao'
    try {
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
        $chave = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore'
        $orig = Get-RegValor $chave 'SystemRestorePointCreationFrequency'
        Set-RegValor $chave 'SystemRestorePointCreationFrequency' 0
        Checkpoint-Computer -Description "WinSecCheck $Carimbo" -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        if ($null -eq $orig) { Remove-ItemProperty $chave 'SystemRestorePointCreationFrequency' -ErrorAction SilentlyContinue }
        else { Set-RegValor $chave 'SystemRestorePointCreationFrequency' $orig }
        Write-Host '  Ponto de restauracao criado.' -ForegroundColor Green
        Add-Acao 'Ponto de restauracao' 'Criado'
    } catch {
        Write-Warning "Nao foi possivel criar ponto de restauracao: $($_.Exception.Message)"
        if (-not (Confirmar 'Continuar mesmo assim?')) { throw 'Cancelado pelo usuario.' }
    }
}

function Install-AtualizacoesWindows {
    Write-Etapa 'Instalando atualizacoes do Windows'
    $sessao = New-Object -ComObject Microsoft.Update.Session
    $res = $sessao.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
    if ($res.Updates.Count -eq 0) { Write-Host '  Nenhuma atualizacao pendente.'; return }
    $col = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($u in $res.Updates) {
        if (-not $u.EulaAccepted) { $u.AcceptEula() }
        [void]$col.Add($u); Write-Host "  - $($u.Title)"
    }
    Write-Host '  Baixando...'
    $dl = $sessao.CreateUpdateDownloader(); $dl.Updates = $col; [void]$dl.Download()
    Write-Host '  Instalando...'
    $inst = $sessao.CreateUpdateInstaller(); $inst.Updates = $col
    $r = $inst.Install()
    $txt = @{ 2 = 'Sucesso'; 3 = 'Sucesso com erros'; 4 = 'Falhou'; 5 = 'Abortado' }[[int]$r.ResultCode]
    Write-Host "  Resultado: $txt. Reinicio necessario: $($r.RebootRequired)" -ForegroundColor Green
    Add-Acao 'Windows Update' "$txt ($($col.Count) atualizacoes). Reinicio: $($r.RebootRequired)"
}

function Clear-ArquivosTemporarios {
    Write-Etapa 'Limpeza de temporarios'
    $pastas = @("$env:windir\Temp")
    $pastas += Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue |
               ForEach-Object { Join-Path $_.FullName 'AppData\Local\Temp' }
    $limite = (Get-Date).AddDays(-$Config.DiasArquivosTemp)
    $total = 0
    foreach ($p in ($pastas | Where-Object { Test-Path $_ })) {
        $arquivos = Get-ChildItem $p -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $limite }
        foreach ($f in $arquivos) {
            try { $t = $f.Length; Remove-Item $f.FullName -Force -ErrorAction Stop; $total += $t } catch {}
        }
    }
    $mb = [math]::Round($total / 1MB, 1)
    Write-Host "  Liberado: $mb MB" -ForegroundColor Green
    Add-Acao 'Limpeza de temporarios' "$mb MB liberados"
}

function Invoke-Correcao([string]$Id) {
    $ErrorActionPreference = 'Stop'
    switch -Regex ($Id) {
        '^DefenderTempoReal$'   { Set-MpPreference -DisableRealtimeMonitoring $false; break }
        '^DefenderAssinaturas$' { Update-MpSignature; break }
        '^DefenderVarredura$'   { Write-Host '  Varredura rapida em andamento...'; Start-MpScan -ScanType QuickScan; break }
        '^DefenderPUA$'         { Set-MpPreference -PUAProtection Enabled; break }
        '^Firewall$'            { Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True; break }
        '^WindowsUpdate$'       { Install-AtualizacoesWindows; break }
        '^UAC$' {
            $pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            Set-RegValor $pol 'EnableLUA' 1
            Set-RegValor $pol 'ConsentPromptBehaviorAdmin' 5
            break
        }
        '^SMB1$' {
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null
            break
        }
        '^PSv2$'      { Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart | Out-Null; break }
        '^Convidado$' { Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Disable-LocalUser; break }
        '^AutoRun$'   { Set-RegValor 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255; break }
        '^RDPNLA$'    { Set-RegValor 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 1; break }
        '^WDigest$'   { Set-RegValor 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0; break }
        '^LimpezaTemp$' { Clear-ArquivosTemporarios; break }
        '^Servico:(.+)$' {
            $n = $Matches[1]
            Set-Service -Name $n -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name $n
            break
        }
        default { throw "Correcao desconhecida: $Id" }
    }
}

function Invoke-Correcoes {
    Write-Etapa 'Aplicando correcoes'
    $pendentes = $script:Resultados | Where-Object { $_.Correcao -and $_.Status -in 'Alerta', 'Critico' } |
                 Sort-Object @{ e = { if ($_.Status -eq 'Critico') { 0 } else { 1 } } } |
                 Group-Object Correcao | ForEach-Object { $_.Group[0] }
    if (-not $pendentes) { Write-Host '  Nada a corrigir automaticamente.' -ForegroundColor Green; return }

    foreach ($r in $pendentes) {
        if (-not (Confirmar "Corrigir '$($r.Item)' ($($r.Detalhe))?")) { Add-Acao $r.Item 'Ignorado pelo usuario'; continue }
        try {
            Invoke-Correcao $r.Correcao
            Write-Host "  [CORRIGIDO] $($r.Item)" -ForegroundColor Green
            Add-Acao $r.Item 'Corrigido'
        } catch {
            Write-Host "  [FALHA] $($r.Item): $($_.Exception.Message)" -ForegroundColor Red
            Add-Acao $r.Item "Falha: $($_.Exception.Message)"
        }
    }
}

function Remove-Bloatware {
    Write-Etapa 'Remocao de bloatware'
    $pacotes = @(Get-BloatwareInstalado)
    if ($pacotes.Count -eq 0) { Write-Host '  Nenhum aplicativo indesejado encontrado.' -ForegroundColor Green }
    else {
        $pacotes | ForEach-Object { Write-Host "  - $($_.Name)" }
        if (Confirmar "Remover estes $($pacotes.Count) aplicativos de TODOS os usuarios?") {
            foreach ($p in $pacotes) {
                try {
                    Get-AppxPackage -AllUsers -Name $p.Name | Remove-AppxPackage -AllUsers -ErrorAction Stop
                    Write-Host "  [REMOVIDO] $($p.Name)" -ForegroundColor Green
                    Add-Acao "Remover $($p.Name)" 'Removido'
                } catch {
                    try {
                        Remove-AppxPackage -Package $p.PackageFullName -ErrorAction Stop
                        Add-Acao "Remover $($p.Name)" 'Removido (usuario atual)'
                    } catch {
                        Write-Host "  [FALHA] $($p.Name): $($_.Exception.Message)" -ForegroundColor Red
                        Add-Acao "Remover $($p.Name)" "Falha: $($_.Exception.Message)"
                    }
                }
            }
        }
    }

    # Pacotes provisionados = reinstalados automaticamente para novos usuarios
    $prov = @(Get-AppxProvisionedPackage -Online | Where-Object {
        $d = $_.DisplayName
        ($BloatwareAppx | Where-Object { $d -like $_ }) -and -not ($AppxProtegidos | Where-Object { $d -like $_ })
    })
    if ($prov.Count -gt 0 -and ($IncluirProvisionados -or (Confirmar "Remover tambem $($prov.Count) pacote(s) provisionado(s) (impede reinstalacao em novos usuarios)?"))) {
        foreach ($p in $prov) {
            try {
                Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName -ErrorAction Stop | Out-Null
                Add-Acao "Desprovisionar $($p.DisplayName)" 'Removido'
            } catch { Add-Acao "Desprovisionar $($p.DisplayName)" "Falha: $($_.Exception.Message)" }
        }
        Write-Host '  Provisionados removidos.' -ForegroundColor Green
    }

    # Impede que o Windows reinstale apps patrocinados
    Set-RegValor 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsConsumerFeatures' 1
    Add-Acao 'Bloquear apps patrocinados' 'Politica aplicada'

    $w32 = @(Get-Win32Suspeitos)
    if ($w32.Count -gt 0) {
        Write-Host "`n  Programas tradicionais para revisar (Configuracoes > Aplicativos):" -ForegroundColor Yellow
        $w32 | ForEach-Object { Write-Host "  - $($_.DisplayName)" -ForegroundColor Yellow }
    }
}

function Repair-Sistema {
    Write-Etapa 'Reparo do sistema (DISM + SFC) - pode levar 15-30 min'
    if (-not (Confirmar 'Executar DISM e SFC agora?')) { return }
    DISM.exe /Online /Cleanup-Image /RestoreHealth
    Add-Acao 'DISM RestoreHealth' "Codigo de saida $LASTEXITCODE"
    sfc.exe /scannow
    Add-Acao 'SFC scannow' "Codigo de saida $LASTEXITCODE"
}

# =====================================================================
#  RELATORIO
# =====================================================================
function Export-Relatorio {
    $os = Get-CimInstance Win32_OperatingSystem
    $nota = Get-Nota
    $corNota = if ($nota -ge 80) { '#2e7d32' } elseif ($nota -ge 50) { '#ef6c00' } else { '#c62828' }
    $enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }

    $linhas = foreach ($r in $script:Resultados) {
        "<tr class='$($r.Status)'><td>$(& $enc $r.Categoria)</td><td>$(& $enc $r.Item)</td><td><b>$($r.Status)</b></td><td>$(& $enc $r.Detalhe)</td></tr>"
    }
    $acoes = foreach ($a in $script:Acoes) {
        "<tr><td>$($a.Hora)</td><td>$(& $enc $a.Acao)</td><td>$(& $enc $a.Resultado)</td></tr>"
    }
    $tabAcoes = if ($acoes) { "<h2>Acoes executadas</h2><table><tr><th>Hora</th><th>Acao</th><th>Resultado</th></tr>$($acoes -join '')</table>" } else { '' }

    $html = @"
<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8"><title>WinSecCheck - $env:COMPUTERNAME</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#f5f6f8;color:#222}
h1{margin-bottom:4px}.sub{color:#666;margin-bottom:20px}
.nota{display:inline-block;font-size:42px;font-weight:700;color:$corNota}
table{border-collapse:collapse;width:100%;background:#fff;margin-bottom:24px}
th,td{padding:8px 10px;border-bottom:1px solid #e3e3e3;text-align:left;vertical-align:top;font-size:14px}
th{background:#263238;color:#fff}
tr.Critico td{background:#ffebee}tr.Alerta td{background:#fff8e1}tr.OK td{background:#f1f8e9}
</style></head><body>
<h1>Relatorio de Seguranca - $env:COMPUTERNAME</h1>
<div class="sub">$($os.Caption) build $($os.BuildNumber) | Usuario: $env:USERNAME | $(Get-Date -Format 'dd/MM/yyyy HH:mm')</div>
<div>Nota de seguranca: <span class="nota">$nota/100</span></div>
<h2>Verificacoes</h2>
<table><tr><th>Categoria</th><th>Item</th><th>Status</th><th>Detalhe</th></tr>$($linhas -join '')</table>
$tabAcoes
</body></html>
"@
    $arqHtml = Join-Path $PastaSaida "relatorio_${env:COMPUTERNAME}_$Carimbo.html"
    $arqCsv  = Join-Path $PastaSaida "relatorio_${env:COMPUTERNAME}_$Carimbo.csv"
    $html | Out-File -FilePath $arqHtml -Encoding utf8
    $script:Resultados | Export-Csv -Path $arqCsv -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    Write-Host "`nRelatorio: $arqHtml" -ForegroundColor Cyan
    Write-Host "CSV:       $arqCsv" -ForegroundColor Cyan
    Write-Host "Log:       $ArquivoLog" -ForegroundColor Cyan
    return $arqHtml
}

# =====================================================================
#  MENU E EXECUCAO
# =====================================================================
function Show-Menu {
    do {
        Write-Host @"

 ============================================
   WinSecCheck - Seguranca e Limpeza Windows
 ============================================
  1. Auditoria completa (somente leitura)
  2. Auditoria + corrigir problemas
  3. Remover aplicativos indesejados
  4. Varredura rapida do Defender
  5. Reparar sistema (DISM + SFC)
  6. Limpar arquivos temporarios
  7. Instalar atualizacoes do Windows
  8. Executar TUDO (2 + 3 + 6)
  0. Sair
"@ -ForegroundColor White
        $op = Read-Host 'Escolha'
        try {
            switch ($op) {
                '1' { Invoke-Auditoria; Invoke-Item (Export-Relatorio) }
                '2' { Invoke-Auditoria; New-PontoRestauracao; Invoke-Correcoes; Write-Host "`nReauditando..."; Invoke-Auditoria; Invoke-Item (Export-Relatorio) }
                '3' { New-PontoRestauracao; Remove-Bloatware }
                '4' { Write-Host 'Executando varredura...'; Update-MpSignature -ErrorAction SilentlyContinue; Start-MpScan -ScanType QuickScan; Write-Host 'Concluida.' -ForegroundColor Green }
                '5' { Repair-Sistema }
                '6' { Clear-ArquivosTemporarios }
                '7' { Install-AtualizacoesWindows }
                '8' { Invoke-Auditoria; New-PontoRestauracao; Invoke-Correcoes; Remove-Bloatware; Clear-ArquivosTemporarios; Write-Host "`nReauditando..."; Invoke-Auditoria; Invoke-Item (Export-Relatorio) }
                '0' { }
                default { Write-Host 'Opcao invalida.' -ForegroundColor Red }
            }
        } catch { Write-Host "Erro: $($_.Exception.Message)" -ForegroundColor Red }
    } while ($op -ne '0')
}

Start-Transcript -Path $ArquivoLog -Append | Out-Null
try {
    switch ($Modo) {
        'Menu'      { Show-Menu }
        'Auditoria' { Invoke-Auditoria; [void](Export-Relatorio) }
        'Corrigir'  {
            Invoke-Auditoria; New-PontoRestauracao; Invoke-Correcoes
            if ($RemoverBloatware) { Remove-Bloatware }
            Invoke-Auditoria; [void](Export-Relatorio)
        }
        'Completo'  {
            Invoke-Auditoria; New-PontoRestauracao; Invoke-Correcoes
            Remove-Bloatware; Clear-ArquivosTemporarios
            Invoke-Auditoria; [void](Export-Relatorio)
        }
    }
} finally {
    Stop-Transcript | Out-Null
}
