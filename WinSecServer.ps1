<#
.SYNOPSIS
    WinSecServer - Varredura de seguranca para computadores que atuam como SERVIDOR.

.DESCRIPTION
    SOMENTE LEITURA: este script NAO altera nada no computador.

    1. Mapeia as portas abertas e quais programas/servicos as usam.
    2. Observa por N minutos quais estacoes se conectam e em quais portas.
    3. Compara com o Firewall do Windows e mostra o que esta liberado ou bloqueado.
    4. Verifica banco de dados, compartilhamentos, contas, servicos, tarefas,
       acesso remoto, tentativas de invasao, energia, rede e backup.
    5. Gera um SCRIPT DE REGRAS DE FIREWALL que libera somente a rede local,
       para voce revisar e aplicar sem prejudicar as estacoes.
    6. Gera relatorio HTML + CSV.

.EXAMPLE
    .\WinSecServer.ps1 -MinutosObservacao 30
        Observa as estacoes por 30 minutos (recomendado em horario de expediente).
.EXAMPLE
    .\WinSecServer.ps1 -MinutosObservacao 0
        Varredura rapida, sem periodo de observacao.
#>
#Requires -RunAsAdministrator
#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateRange(0, 480)][int]$MinutosObservacao = 10,
    [ValidateRange(5, 300)][int]$IntervaloSegundos = 20,
    [string]$PastaSaida = "$env:ProgramData\WinSecCheck"
)

# =====================================================================
#  CONFIGURACAO
# =====================================================================
$PortasConhecidas = @{
    21 = 'FTP'; 22 = 'SSH'; 23 = 'Telnet'; 80 = 'HTTP'; 135 = 'RPC'; 139 = 'NetBIOS'
    443 = 'HTTPS'; 445 = 'Compartilhamento de arquivos (SMB)'; 1433 = 'SQL Server'
    1434 = 'SQL Browser'; 1521 = 'Oracle'; 3050 = 'Firebird'; 3306 = 'MySQL/MariaDB'
    3389 = 'Area de Trabalho Remota'; 5432 = 'PostgreSQL'; 5900 = 'VNC'; 5985 = 'WinRM'
    5986 = 'WinRM HTTPS'; 6379 = 'Redis'; 8080 = 'HTTP alternativo'; 11211 = 'Memcached'
    27017 = 'MongoDB'
}
# Portas que nunca devem ficar abertas para fora da rede local
$PortasRisco = @(21, 23, 135, 139, 445, 1433, 1434, 1521, 3050, 3306, 3389, 5432, 5900, 5985, 6379, 11211, 27017)
$ProcessosSistema = @('svchost', 'lsass', 'wininit', 'services', 'spoolsv', 'System', 'Idle')
$PadroesBanco = @('MSSQL*', 'SQLBrowser', 'SQLAgent*', 'Firebird*', 'MySQL*', 'MariaDB*', 'postgresql*', 'OracleService*', 'MongoDB*', 'Redis*')
$FerramentasRemotas = @('AnyDesk', 'RustDesk', 'TeamViewer', 'UltraViewer', 'Splashtop', 'ScreenConnect', 'MeshAgent', 'Supremo', 'RemotePC', 'AeroAdmin', 'tvnserver', 'winvnc')

# =====================================================================
#  INFRAESTRUTURA
# =====================================================================
$script:Resultados = New-Object System.Collections.Generic.List[object]
$script:TemCompartilhamentos = $false
$script:RedePublica = @()
$Carimbo = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not (Test-Path $PastaSaida)) { New-Item -ItemType Directory -Path $PastaSaida -Force | Out-Null }

function Write-Etapa([string]$Texto) { Write-Host "`n=== $Texto ===" -ForegroundColor Cyan }

function Add-Resultado {
    param([string]$Categoria, [string]$Item,
          [ValidateSet('OK', 'Info', 'Alerta', 'Critico')][string]$Status, [string]$Detalhe)
    $script:Resultados.Add([pscustomobject]@{ Categoria = $Categoria; Item = $Item; Status = $Status; Detalhe = $Detalhe })
    $cor = @{ OK = 'Green'; Info = 'Gray'; Alerta = 'Yellow'; Critico = 'Red' }[$Status]
    Write-Host ("  [{0,-7}] {1}: {2}" -f $Status, $Item, $Detalhe) -ForegroundColor $cor
}

function Get-RegValor([string]$Caminho, [string]$Nome) {
    $chave = Get-ItemProperty -Path $Caminho -ErrorAction SilentlyContinue
    if ($chave -and ($chave.PSObject.Properties.Name -contains $Nome)) { return $chave.$Nome }
    return $null
}

function ConvertTo-IPv4([string]$IP) {
    if ($IP -like '::ffff:*') { return $IP.Substring(7) }
    return $IP
}

function Get-RedesLocais {
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } |
        ForEach-Object { [pscustomobject]@{ IP = $_.IPAddress; Prefixo = [int]$_.PrefixLength; Interface = $_.InterfaceAlias } }
}

function Test-IPNaRede([string]$IP, [string]$Rede, [int]$Prefixo) {
    try {
        $a = [System.Net.IPAddress]::Parse($IP).GetAddressBytes()
        $b = [System.Net.IPAddress]::Parse($Rede).GetAddressBytes()
        if ($a.Length -ne 4 -or $b.Length -ne 4) { return $false }
        $ia = [BitConverter]::ToUInt32([byte[]]@($a[3], $a[2], $a[1], $a[0]), 0)
        $ib = [BitConverter]::ToUInt32([byte[]]@($b[3], $b[2], $b[1], $b[0]), 0)
        $mascara = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $Prefixo))
        return (($ia -band $mascara) -eq ($ib -band $mascara))
    } catch { return $false }
}

# =====================================================================
#  COLETA: PORTAS E CONEXOES
# =====================================================================
function Get-PortasEscuta {
    $svcPorPid = @{}
    foreach ($s in Get-CimInstance Win32_Service) {
        if ($s.ProcessId) {
            $k = [string]$s.ProcessId
            if (-not $svcPorPid.ContainsKey($k)) { $svcPorPid[$k] = New-Object System.Collections.Generic.List[string] }
            $svcPorPid[$k].Add($s.Name)
        }
    }
    $procs = @{}
    foreach ($p in Get-Process -ErrorAction SilentlyContinue) { $procs[[string]$p.Id] = $p }

    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -notin '127.0.0.1', '::1' } |
        Group-Object LocalPort | ForEach-Object {
            $c = $_.Group[0]
            $porta = [int]$_.Name
            $procId = [string]$c.OwningProcess
            $p = $procs[$procId]
            $nome = if ($p) { $p.ProcessName } else { '?' }
            $caminho = if ($procId -eq '4') { 'System' } elseif ($p) { $p.Path } else { $null }
            $servicos = if ($svcPorPid.ContainsKey($procId)) { ($svcPorPid[$procId] | Select-Object -First 4) -join ', ' } else { '' }
            $sistema = ($nome -in $ProcessosSistema) -and ($porta -ge 49152 -or $porta -in 135, 5040, 5357, 7680)
            [pscustomobject]@{
                Porta = $porta
                Descricao = if ($PortasConhecidas.ContainsKey($porta)) { $PortasConhecidas[$porta] } else { '' }
                Processo = $nome
                Servicos = $servicos
                Caminho = $caminho
                Sistema = $sistema
                Estacoes = ''
                Firewall = ''
                Classe = 'Info'
            }
        } | Sort-Object Porta
}

function Watch-Conexoes([int[]]$Portas) {
    $mapa = @{}
    $total = if ($MinutosObservacao -eq 0) { 1 } else { [math]::Max(1, [int](($MinutosObservacao * 60) / $IntervaloSegundos)) }
    for ($i = 1; $i -le $total; $i++) {
        Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            Where-Object { $Portas -contains [int]$_.LocalPort } | ForEach-Object {
                $ip = ConvertTo-IPv4 $_.RemoteAddress
                if ($ip -in '127.0.0.1', '::1' -or $ip -eq (ConvertTo-IPv4 $_.LocalAddress)) { return }
                $k = "$ip|$($_.LocalPort)"
                if (-not $mapa.ContainsKey($k)) {
                    $mapa[$k] = [pscustomobject]@{ Estacao = $ip; Nome = ''; Porta = [int]$_.LocalPort; PrimeiraVez = (Get-Date -Format 'HH:mm:ss'); Amostras = 0 }
                }
                $mapa[$k].Amostras++
            }
        if ($i -lt $total) {
            $pct = [int](($i / $total) * 100)
            Write-Progress -Activity 'Observando conexoes das estacoes' -Status ("{0} estacao/porta detectada(s) - amostra {1} de {2}" -f $mapa.Count, $i, $total) -PercentComplete $pct
            Start-Sleep -Seconds $IntervaloSegundos
        }
    }
    Write-Progress -Activity 'Observando conexoes das estacoes' -Completed

    $nomes = @{}
    foreach ($c in $mapa.Values) {
        if (-not $nomes.ContainsKey($c.Estacao)) {
            try { $nomes[$c.Estacao] = [System.Net.Dns]::GetHostEntry($c.Estacao).HostName } catch { $nomes[$c.Estacao] = '' }
        }
        $c.Nome = $nomes[$c.Estacao]
    }
    $mapa.Values | Sort-Object Porta, Estacao
}

# =====================================================================
#  FIREWALL
# =====================================================================
function Get-RegrasFirewall {
    $regras = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue)
    if ($regras.Count -eq 0) { return }
    $fPorta = @{}; $fApp = @{}; $fEnd = @{}
    $regras | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue | ForEach-Object { $fPorta[$_.InstanceID] = $_ }
    $regras | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue | ForEach-Object { $fApp[$_.InstanceID] = $_ }
    $regras | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue | ForEach-Object { $fEnd[$_.InstanceID] = $_ }
    foreach ($r in $regras) {
        $pf = $fPorta[$r.InstanceID]; $af = $fApp[$r.InstanceID]; $ef = $fEnd[$r.InstanceID]
        [pscustomobject]@{
            Nome = $r.DisplayName
            Perfil = "$($r.Profile)"
            Protocolo = if ($pf) { "$($pf.Protocol)" } else { 'Any' }
            Portas = if ($pf) { @($pf.LocalPort) } else { @('Any') }
            Programa = if ($af) { "$($af.Program)" } else { 'Any' }
            Origem = if ($ef) { @($ef.RemoteAddress) } else { @('Any') }
        }
    }
}

function Find-RegraQueLibera([int]$Porta, [string]$Caminho, [string[]]$Perfis, $Regras) {
    foreach ($r in $Regras) {
        if ($r.Perfil -ne 'Any' -and -not ($Perfis | Where-Object { $r.Perfil -match $_ })) { continue }
        if ($r.Protocolo -notin 'TCP', 'Any') { continue }
        $ok = $false
        foreach ($lp in $r.Portas) {
            $lp = "$lp"
            if ($lp -eq 'Any') { $ok = $true; break }
            if ($lp -match '^(\d+)-(\d+)$') { if ($Porta -ge [int]$Matches[1] -and $Porta -le [int]$Matches[2]) { $ok = $true; break } }
            elseif ($lp -match '^\d+$' -and [int]$lp -eq $Porta) { $ok = $true; break }
        }
        if (-not $ok) { continue }
        if ($r.Programa -ne 'Any') {
            if (-not $Caminho) { continue }
            if ([Environment]::ExpandEnvironmentVariables($r.Programa) -ne $Caminho) { continue }
        }
        return $r
    }
    return $null
}

function Invoke-AnaliseFirewall($Escuta, $Observadas) {
    Write-Etapa 'Firewall x servicos usados pelas estacoes'
    $perfisAtivos = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {
        switch ("$($_.NetworkCategory)") { 'DomainAuthenticated' { 'Domain' } 'Private' { 'Private' } default { 'Public' } }
    } | Select-Object -Unique)
    if ($perfisAtivos.Count -eq 0) { $perfisAtivos = @('Public') }

    $fwPerfis = @{}
    foreach ($p in Get-NetFirewallProfile) { $fwPerfis[$p.Name] = ("$($p.Enabled)" -eq 'True') }
    $fwLigado = [bool]($perfisAtivos | Where-Object { $fwPerfis[$_] })
    $regras = @(Get-RegrasFirewall)
    $redes = @(Get-RedesLocais)
    $linhas = New-Object System.Collections.Generic.List[string]

    if (-not $fwLigado) {
        Add-Resultado 'Firewall' 'Situacao' 'Critico' "Firewall DESLIGADO no perfil ativo ($($perfisAtivos -join ', ')). Aplique o script de regras ANTES de ligar."
    } else {
        Add-Resultado 'Firewall' 'Situacao' 'OK' "Ligado no perfil ativo ($($perfisAtivos -join ', '))"
    }

    foreach ($e in $Escuta) {
        $est = @($Observadas | Where-Object { $_.Porta -eq $e.Porta })
        $e.Estacoes = ($est | ForEach-Object { if ($_.Nome) { "$($_.Estacao) ($($_.Nome))" } else { $_.Estacao } }) -join ', '
        if ($e.Sistema) { $e.Firewall = 'Sistema (ignorada)'; $e.Classe = 'OK'; continue }

        $desc = if ($e.Descricao) { $e.Descricao } else { $e.Processo }
        $usada = ($est.Count -gt 0) -or ($e.Porta -eq 445 -and $script:TemCompartilhamentos)
        $regra = Find-RegraQueLibera -Porta $e.Porta -Caminho $e.Caminho -Perfis $perfisAtivos -Regras $regras
        $abertaGeral = $regra -and (($regra.Origem -join ',') -match 'Any')

        if (-not $fwLigado) {
            $e.Firewall = 'Firewall desligado (aberta)'; $e.Classe = 'Alerta'
        } elseif ($regra) {
            $e.Firewall = "Liberada: $($regra.Nome)"; $e.Classe = 'OK'
            if ($abertaGeral -and $e.Porta -in $PortasRisco) {
                $e.Classe = 'Alerta'
                Add-Resultado 'Firewall' "Porta $($e.Porta) ($desc)" 'Alerta' "Liberada para QUALQUER origem pela regra '$($regra.Nome)'. O script gerado restringe a rede local."
            }
        } else {
            $e.Firewall = 'BLOQUEADA'
            if ($usada) {
                $e.Classe = 'Critico'
                Add-Resultado 'Firewall' "Porta $($e.Porta) ($desc)" 'Critico' "Usada por estacoes, mas nenhuma regra de liberacao foi identificada. Aplique a regra do script gerado."
            } else {
                $e.Classe = 'Alerta'
                Add-Resultado 'Firewall' "Porta $($e.Porta) ($desc)" 'Alerta' "Bloqueada para a rede. Se as estacoes usam '$($e.Processo)', ative a regra correspondente no script gerado."
            }
        }

        # Linha do script de regras
        $ipsEst = @($est | ForEach-Object { $_.Estacao } | Select-Object -Unique)
        $externos = @($ipsEst | Where-Object {
            $ip = $_
            ($ip -match '^\d+\.\d+\.\d+\.\d+$') -and -not ($redes | Where-Object { Test-IPNaRede $ip $_.IP $_.Prefixo })
        })
        $origTxt = (@('LocalSubnet') + $externos | ForEach-Object { "'$_'" }) -join ','
        $prog = if ($e.Caminho -and $e.Caminho -ne 'System') { " -Program '$($e.Caminho -replace "'", "''")'" } else { '' }
        $nomeRegra = ("WinSecServer - {0} - TCP {1}" -f $desc, $e.Porta) -replace "'", ''
        $cmd = "New-NetFirewallRule -DisplayName '$nomeRegra' -Group 'WinSecServer' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $($e.Porta) -RemoteAddress $origTxt -Profile Any$prog | Out-Null"

        if ($usada) {
            $quem = if ($e.Estacoes) { $e.Estacoes } else { 'compartilhamentos de rede' }
            $linhas.Add("# $desc ($($e.Processo)) - usada por: $quem")
            $linhas.Add($cmd)
        } else {
            $linhas.Add("# $desc ($($e.Processo)) - NAO observada em uso. Remova o '#' da linha abaixo se as estacoes precisarem:")
            $linhas.Add("# $cmd")
        }
        if ($abertaGeral -and $e.Porta -in $PortasRisco) {
            $linhas.Add("# Depois de validar que tudo funciona, desative a regra ampla antiga:")
            $linhas.Add("# Disable-NetFirewallRule -DisplayName '$($regra.Nome -replace "'", "''")'")
        }
        $linhas.Add('')
    }
    return , $linhas
}

# =====================================================================
#  VERIFICACOES DO SERVIDOR
# =====================================================================
function Test-SistemaServidor {
    Write-Etapa 'Sistema'
    $os = Get-CimInstance Win32_OperatingSystem
    Add-Resultado 'Sistema' 'Versao' 'Info' "$($os.Caption) build $($os.BuildNumber)"
    if ($os.ProductType -eq 1) {
        Add-Resultado 'Sistema' 'Tipo de Windows' 'Alerta' 'Windows de estacao atuando como servidor: limite de 20 conexoes simultaneas a compartilhamentos e menos recursos de seguranca.'
    }
    if ($os.Caption -match 'Windows 10|Windows 7|Windows 8|Server 2008|Server 2012') {
        Add-Resultado 'Sistema' 'Suporte' 'Critico' 'Sistema sem suporte de seguranca da Microsoft. Planeje a migracao.'
    }
    $up = (Get-Date) - $os.LastBootUpTime
    Add-Resultado 'Sistema' 'Tempo ligado' 'Info' ("{0:N1} dias" -f $up.TotalDays)

    # Energia: servidor nao pode suspender
    foreach ($cfg in @(@{ Id = 'STANDBYIDLE'; Nome = 'Suspensao' }, @{ Id = 'HIBERNATEIDLE'; Nome = 'Hibernacao' })) {
        $saida = (powercfg /query SCHEME_CURRENT SUB_SLEEP $cfg.Id 2>$null) -join "`n"
        $hex = [regex]::Matches($saida, '0x[0-9a-fA-F]{8}')
        if ($hex.Count -ge 2) {
            $seg = [Convert]::ToUInt32($hex[$hex.Count - 2].Value, 16)
            if ($seg -gt 0) {
                Add-Resultado 'Energia' $cfg.Nome 'Critico' ("Ativada apos {0} min na tomada: o servidor pode desligar e derrubar as estacoes. Corrija com: powercfg /change standby-timeout-ac 0 ; powercfg /change hibernate-timeout-ac 0" -f [int]($seg / 60))
            } else { Add-Resultado 'Energia' $cfg.Nome 'OK' 'Desativada na tomada' }
        }
    }

    $ini = Get-RegValor 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' 'ActiveHoursStart'
    $fim = Get-RegValor 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' 'ActiveHoursEnd'
    if ($null -ne $ini) {
        Add-Resultado 'Sistema' 'Horario ativo do Windows Update' 'Info' "Das ${ini}h as ${fim}h. Reinicios automaticos ocorrem fora desse horario; ajuste ao expediente."
    }
}

function Test-RedeServidor {
    Write-Etapa 'Rede'
    foreach ($r in Get-RedesLocais) {
        $dhcp = (Get-NetIPInterface -InterfaceAlias $r.Interface -AddressFamily IPv4 -ErrorAction SilentlyContinue).Dhcp
        if ("$dhcp" -eq 'Enabled') {
            Add-Resultado 'Rede' "IP $($r.IP)" 'Alerta' "Obtido por DHCP em '$($r.Interface)'. Se o IP mudar, as estacoes perdem o acesso. Use IP fixo ou reserva no roteador."
        } else {
            Add-Resultado 'Rede' "IP $($r.IP)" 'OK' "Fixo (/$($r.Prefixo)) em '$($r.Interface)'"
        }
    }
    foreach ($cp in Get-NetConnectionProfile -ErrorAction SilentlyContinue) {
        if ("$($cp.NetworkCategory)" -eq 'Public') {
            $script:RedePublica += $cp.InterfaceAlias
            Add-Resultado 'Rede' "Perfil de rede ($($cp.InterfaceAlias))" 'Alerta' 'Rede marcada como PUBLICA: o Windows aplica as regras mais restritivas. Em rede interna, marque como Privada.'
        } else {
            Add-Resultado 'Rede' "Perfil de rede ($($cp.InterfaceAlias))" 'OK' "$($cp.NetworkCategory)"
        }
    }
}

function Test-Compartilhamentos {
    Write-Etapa 'Compartilhamentos de arquivos'
    $shares = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { -not $_.Special -and $_.Name -notmatch '\$$' })
    $script:TemCompartilhamentos = $shares.Count -gt 0
    if ($shares.Count -eq 0) { Add-Resultado 'Compartilhamentos' 'Pastas compartilhadas' 'Info' 'Nenhuma' }
    foreach ($s in $shares) {
        $acesso = @(Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue)
        $contas = ($acesso | ForEach-Object { "$($_.AccountName) ($($_.AccessRight))" }) -join '; '
        $todos = $acesso | Where-Object { $_.AccountName -match 'Everyone|Todos' -and "$($_.AccessRight)" -eq 'Full' -and "$($_.AccessControlType)" -eq 'Allow' }
        if ($todos) {
            Add-Resultado 'Compartilhamentos' $s.Name 'Alerta' "$($s.Path) - TODOS com controle total (alvo facil de ransomware). Restrinja aos usuarios necessarios. Acessos: $contas"
        } else {
            Add-Resultado 'Compartilhamentos' $s.Name 'Info' "$($s.Path) - Acessos: $contas"
        }
    }
    $sessoes = @(Get-SmbSession -ErrorAction SilentlyContinue)
    if ($sessoes.Count -gt 0) {
        $clientes = ($sessoes | ForEach-Object { "$($_.ClientComputerName) [$($_.ClientUserName)]" } | Select-Object -Unique) -join ', '
        Add-Resultado 'Compartilhamentos' 'Estacoes conectadas agora' 'Info' "$($sessoes.Count): $clientes"
    }
    $cfg = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
    if ($cfg) {
        if ($cfg.EnableSMB1Protocol) { Add-Resultado 'Compartilhamentos' 'SMBv1' 'Critico' 'Habilitado. Verifique se ha estacoes muito antigas antes de desativar.' }
        else { Add-Resultado 'Compartilhamentos' 'SMBv1' 'OK' 'Desabilitado' }
        if (-not $cfg.RequireSecuritySignature) {
            Add-Resultado 'Compartilhamentos' 'Assinatura SMB' 'Info' 'Nao exigida. Recomendado ativar, mas teste antes com as estacoes (impressoras e scanners antigos podem falhar).'
        }
    }
}

function Test-BancosDados {
    Write-Etapa 'Bancos de dados'
    $svcs = @(Get-CimInstance Win32_Service | Where-Object { $n = $_.Name; $PadroesBanco | Where-Object { $n -like $_ } })
    if ($svcs.Count -eq 0) {
        Add-Resultado 'Banco de dados' 'Servicos conhecidos' 'Info' 'Nenhum SQL Server/Firebird/MySQL/PostgreSQL detectado (o sistema pode usar banco proprio; veja a tabela de portas).'
        return
    }
    foreach ($s in $svcs) {
        $st = if ($s.State -eq 'Running' -and $s.StartMode -ne 'Auto') { 'Alerta' } else { 'Info' }
        $obs = if ($st -eq 'Alerta') { ' Inicio NAO automatico: apos reiniciar, as estacoes ficam sem banco.' } else { '' }
        Add-Resultado 'Banco de dados' $s.DisplayName $st "Estado: $($s.State), inicio: $($s.StartMode), conta: $($s.StartName).$obs"
    }
    $nomes = ($svcs.Name) -join ' '
    if ($nomes -match 'Firebird') { Add-Resultado 'Banco de dados' 'Firebird - senha padrao' 'Alerta' "Confirme com o fornecedor do sistema se a senha do SYSDBA ainda e a padrao 'masterkey' e troque em conjunto com ele." }
    if ($nomes -match 'MSSQL')    { Add-Resultado 'Banco de dados' 'SQL Server - conta sa' 'Alerta' "Confirme se a conta 'sa' tem senha forte ou esta desativada (alinhe com o fornecedor)." }
    if ($nomes -match 'MySQL|MariaDB') { Add-Resultado 'Banco de dados' 'MySQL - conta root' 'Alerta' "Confirme se o 'root' tem senha forte e so aceita conexao local." }
    if ($nomes -match 'postgresql') { Add-Resultado 'Banco de dados' 'PostgreSQL' 'Alerta' "Revise o pg_hba.conf: aceite conexoes apenas da rede local." }
}

function Test-ContasEServicos {
    Write-Etapa 'Contas, servicos e tarefas'
    $admins = try { @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { ($_.Name -split '\\')[-1] }) } catch { @() }
    foreach ($u in Get-LocalUser | Where-Object Enabled) {
        $adm = if ($admins -contains $u.Name) { ' (ADMINISTRADOR)' } else { '' }
        $logon = if ($u.LastLogon) { $u.LastLogon.ToString('dd/MM/yyyy HH:mm') } else { 'nunca' }
        if (-not $u.PasswordRequired) {
            Add-Resultado 'Contas' $u.Name 'Critico' "Conta$adm nao exige senha (pode estar sem senha). Ultimo logon: $logon"
        } else {
            Add-Resultado 'Contas' $u.Name 'Info' "Conta$adm. Ultimo logon: $logon"
        }
    }

    $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if ((Get-RegValor $wl 'AutoAdminLogon') -eq '1') {
        $usr = Get-RegValor $wl 'DefaultUserName'
        Add-Resultado 'Contas' 'Logon automatico' 'Alerta' "Ativo com o usuario '$usr'. Comum em servidores de sistema; antes de trocar a senha desse usuario, atualize o logon automatico."
        if ($null -ne (Get-RegValor $wl 'DefaultPassword')) {
            Add-Resultado 'Contas' 'Senha do logon automatico' 'Critico' 'Senha gravada em TEXTO PURO no registro. Reconfigure com a ferramenta Autologon da Microsoft (Sysinternals), que grava criptografado.'
        }
    }

    $comConta = @(Get-CimInstance Win32_Service | Where-Object {
        $_.StartName -and $_.StartName -notmatch '^(LocalSystem|NT AUTHORITY\\|NT SERVICE\\|AUTORIDADE NT\\)'
    })
    foreach ($s in $comConta) {
        Add-Resultado 'Servicos' $s.DisplayName 'Alerta' "Roda com a conta '$($s.StartName)'. Se mudar a senha dessa conta, atualize o servico ou ele nao inicia."
    }

    $semAspas = @(Get-CimInstance Win32_Service | Where-Object {
        $_.PathName -and $_.PathName -notmatch '^\s*"' -and $_.PathName -notmatch '^\s*[A-Za-z]:\\Windows\\' -and
        (($_.PathName -split '\.exe')[0] -match '\s')
    })
    foreach ($s in $semAspas) {
        Add-Resultado 'Servicos' "$($s.Name) (caminho sem aspas)" 'Alerta' "Falha classica de elevacao de privilegio: $($s.PathName). Corrija com o fornecedor do programa."
    }

    $tarefas = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and "$($_.State)" -ne 'Disabled' })
    if ($tarefas.Count -gt 0) {
        $lista = ($tarefas | ForEach-Object { "$($_.TaskName) [$($_.Principal.UserId)]" }) -join '; '
        Add-Resultado 'Tarefas agendadas' 'Tarefas de terceiros' 'Info' "$($tarefas.Count): $lista. Revise as desconhecidas (podem ser persistencia de malware)."
    }
}

function Test-AcessoRemoto {
    Write-Etapa 'Acesso remoto e tentativas de invasao'
    $rdpOff = Get-RegValor 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
    if ($rdpOff -eq 0) {
        $nla = Get-RegValor 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
        $st = if ($nla -eq 1) { 'Alerta' } else { 'Critico' }
        $txt = if ($nla -eq 1) { 'Habilitada com NLA.' } else { 'Habilitada SEM NLA.' }
        Add-Resultado 'Acesso remoto' 'Area de Trabalho Remota' $st "$txt Nunca redirecione a porta 3389 no roteador; para acesso externo use VPN."
    } else { Add-Resultado 'Acesso remoto' 'Area de Trabalho Remota' 'OK' 'Desabilitada' }

    $procs = @(Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $_.ProcessName })
    $ativos = @($FerramentasRemotas | Where-Object { $f = $_; $procs | Where-Object { $_ -like "*$f*" } })
    if ($ativos.Count -gt 1) {
        Add-Resultado 'Acesso remoto' 'Ferramentas em execucao' 'Alerta' "$($ativos -join ', '). Cada uma e uma porta de entrada: mantenha apenas a oficial da empresa."
    } elseif ($ativos.Count -eq 1) {
        Add-Resultado 'Acesso remoto' 'Ferramentas em execucao' 'Info' ($ativos -join ', ')
    }

    try {
        $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = (Get-Date).AddDays(-1) } -MaxEvents 5000 -ErrorAction Stop)
        $porOrigem = $ev | ForEach-Object { $_.Properties[19].Value } | Where-Object { $_ -and $_ -ne '-' } |
                     Group-Object | Sort-Object Count -Descending | Select-Object -First 5
        $resumo = ($porOrigem | ForEach-Object { "$($_.Name) ($($_.Count)x)" }) -join ', '
        $st = if ($ev.Count -gt 30) { 'Alerta' } else { 'Info' }
        Add-Resultado 'Acesso remoto' 'Logons com falha (24h)' $st "$($ev.Count) tentativa(s). Origens: $resumo"
    } catch {
        Add-Resultado 'Acesso remoto' 'Logons com falha (24h)' 'OK' 'Nenhum registrado'
    }
}

function Test-Backup {
    Write-Etapa 'Backup'
    $bk = @(Get-CimInstance Win32_Service | Where-Object { "$($_.Name) $($_.DisplayName)" -match 'Acronis|Veeam|Cobian|Macrium|Iperius|Duplicati|Backup' } |
            Where-Object { $_.Name -notin 'SDRSVC', 'wbengine' })
    if ($bk.Count -gt 0) {
        Add-Resultado 'Backup' 'Software de backup' 'OK' (($bk | ForEach-Object { "$($_.DisplayName) ($($_.State))" } | Select-Object -Unique) -join ', ')
    } else {
        Add-Resultado 'Backup' 'Software de backup' 'Critico' 'Nenhum software de backup detectado em um servidor com banco de dados.'
    }
    Add-Resultado 'Backup' 'Recomendacao' 'Info' 'Garanta uma copia fora do servidor (nuvem ou disco desconectado) e teste a restauracao do banco periodicamente: ransomware criptografa tambem os backups acessiveis pela rede.'
}

# =====================================================================
#  RELATORIO
# =====================================================================
function ConvertTo-TabelaHtml($Objetos, [string[]]$Colunas, [string]$CampoClasse) {
    $lista = @($Objetos)
    if ($lista.Count -eq 0) { return '<p><i>Nenhum item.</i></p>' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<div class="rolagem"><table><tr>')
    foreach ($c in $Colunas) { [void]$sb.Append("<th>$c</th>") }
    [void]$sb.Append('</tr>')
    foreach ($o in $lista) {
        $cls = if ($CampoClasse) { " class='$($o.$CampoClasse)'" } else { '' }
        [void]$sb.Append("<tr$cls>")
        foreach ($c in $Colunas) { [void]$sb.Append('<td>' + [System.Net.WebUtility]::HtmlEncode([string]$o.$c) + '</td>') }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</table></div>')
    return $sb.ToString()
}

function Export-Relatorio($Escuta, $Observadas, [string]$ArquivoRegras) {
    $os = Get-CimInstance Win32_OperatingSystem
    $c = @($script:Resultados | Where-Object Status -eq 'Critico').Count
    $a = @($script:Resultados | Where-Object Status -eq 'Alerta').Count
    $obsTxt = if ($MinutosObservacao -gt 0) { "$MinutosObservacao minuto(s)" } else { 'instantanea' }

    $html = @"
<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8"><title>WinSecServer - $env:COMPUTERNAME</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#f5f6f8;color:#222}
h1{margin-bottom:4px}h2{margin-top:32px;border-bottom:2px solid #263238;padding-bottom:4px}
.sub{color:#666}.cards{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
.card{background:#fff;padding:12px 18px;border-radius:6px;box-shadow:0 1px 3px #0002}
.card b{font-size:28px;display:block}.rolagem{overflow-x:auto}
table{border-collapse:collapse;width:100%;background:#fff}
th,td{padding:7px 9px;border-bottom:1px solid #e3e3e3;text-align:left;vertical-align:top;font-size:13px}
th{background:#263238;color:#fff}tr.Critico td{background:#ffebee}tr.Alerta td{background:#fff8e1}tr.OK td{background:#f1f8e9}
li{margin-bottom:8px}code{background:#eceff1;padding:2px 5px;border-radius:3px}
</style></head><body>
<h1>Varredura de Servidor - $env:COMPUTERNAME</h1>
<div class="sub">$($os.Caption) build $($os.BuildNumber) | $(Get-Date -Format 'dd/MM/yyyy HH:mm') | Observacao: $obsTxt</div>
<div class="cards">
<div class="card"><b style="color:#c62828">$c</b>Criticos</div>
<div class="card"><b style="color:#ef6c00">$a</b>Alertas</div>
<div class="card"><b>$(@($Observadas | ForEach-Object { $_.Estacao } | Select-Object -Unique).Count)</b>Estacoes observadas</div>
<div class="card"><b>$(@($Escuta | Where-Object { -not $_.Sistema }).Count)</b>Portas de aplicativos</div>
</div>
<h2>1. Estacoes que acessaram o servidor</h2>
$(ConvertTo-TabelaHtml $Observadas @('Estacao','Nome','Porta','PrimeiraVez','Amostras'))
<h2>2. Portas abertas e situacao no firewall</h2>
$(ConvertTo-TabelaHtml ($Escuta | Where-Object { -not $_.Sistema }) @('Porta','Descricao','Processo','Servicos','Estacoes','Firewall','Caminho') 'Classe')
<h2>3. Verificacoes</h2>
$(ConvertTo-TabelaHtml $script:Resultados @('Categoria','Item','Status','Detalhe') 'Status')
<h2>4. Plano seguro (sem prejudicar as estacoes)</h2>
<ol>
<li><b>Revise o script de regras gerado</b>: <code>$ArquivoRegras</code>. Ele libera as portas usadas apenas para a rede local. Aplique-o, teste as estacoes e so entao mantenha o firewall ligado. Para desfazer: <code>Remove-NetFirewallRule -Group 'WinSecServer'</code>.</li>
<li>Se a rede estiver como Publica, marque-a como Privada (o comando esta comentado no script de regras).</li>
<li>Garanta IP fixo e desative suspensao/hibernacao: o servidor precisa ficar sempre disponivel.</li>
<li>Antes de trocar senhas ou permissoes de qualquer conta, confira na secao 3 os servicos, tarefas e logon automatico que dependem dela.</li>
<li>Troque senhas padrao do banco de dados <b>junto com o fornecedor do sistema</b>, para atualizar tambem a configuracao das estacoes.</li>
<li>Nunca redirecione portas de banco de dados, compartilhamento ou RDP no roteador. Para acesso externo, use VPN ou a ferramenta de acesso remoto oficial.</li>
<li>Mantenha apenas uma ferramenta de acesso remoto e remova as demais.</li>
<li>Backup 3-2-1: tres copias, dois meios diferentes, uma fora do local. Teste a restauracao.</li>
<li>Faca qualquer mudanca fora do horario de atendimento e tenha o ponto de restauracao/backup em maos.</li>
</ol>
</body></html>
"@
    $arqHtml = Join-Path $PastaSaida "servidor_${env:COMPUTERNAME}_$Carimbo.html"
    $html | Out-File -FilePath $arqHtml -Encoding utf8
    $script:Resultados | Export-Csv -Path (Join-Path $PastaSaida "servidor_${env:COMPUTERNAME}_$Carimbo.csv") -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    return $arqHtml
}

# =====================================================================
#  EXECUCAO
# =====================================================================
Write-Host @"

 ==================================================
   WinSecServer - Varredura de Servidor (somente leitura)
   Nenhuma configuracao sera alterada.
 ==================================================
"@ -ForegroundColor White

Write-Etapa 'Mapeando portas abertas'
$escuta = @(Get-PortasEscuta)
$portasApp = @($escuta | Where-Object { -not $_.Sistema } | ForEach-Object { $_.Porta })
Write-Host "  $($portasApp.Count) porta(s) de aplicativos em escuta: $($portasApp -join ', ')"

$observadas = @()
if ($portasApp.Count -gt 0) {
    Write-Etapa "Observando estacoes por $MinutosObservacao minuto(s)"
    Write-Host '  Deixe as estacoes trabalhando normalmente durante a observacao.' -ForegroundColor DarkGray
    $observadas = @(Watch-Conexoes -Portas $portasApp)
    Write-Host "  $(@($observadas | ForEach-Object { $_.Estacao } | Select-Object -Unique).Count) estacao(oes) detectada(s)."
}

Test-SistemaServidor
Test-RedeServidor
Test-Compartilhamentos
Test-BancosDados
Test-ContasEServicos
Test-AcessoRemoto
Test-Backup
$linhasRegras = Invoke-AnaliseFirewall -Escuta $escuta -Observadas $observadas

# Script de regras de firewall
$arqRegras = Join-Path $PastaSaida "regras_firewall_${env:COMPUTERNAME}_$Carimbo.ps1"
$cab = New-Object System.Collections.Generic.List[string]
$cab.Add('<#')
$cab.Add("  Regras de firewall geradas pelo WinSecServer em $(Get-Date -Format 'dd/MM/yyyy HH:mm') para $env:COMPUTERNAME")
$cab.Add('  REVISE ANTES DE APLICAR e execute como Administrador.')
$cab.Add('  As regras liberam as portas SOMENTE para a rede local (LocalSubnet) e para as estacoes observadas.')
$cab.Add("  Para desfazer tudo:  Remove-NetFirewallRule -Group 'WinSecServer'")
$cab.Add('#>')
$cab.Add('#Requires -RunAsAdministrator')
$cab.Add("Remove-NetFirewallRule -Group 'WinSecServer' -ErrorAction SilentlyContinue")
$cab.Add('')
foreach ($ifc in ($script:RedePublica | Select-Object -Unique)) {
    $cab.Add("# Rede marcada como Publica. Remova o '#' para marcar como Privada (rede interna):")
    $cab.Add("# Set-NetConnectionProfile -InterfaceAlias '$($ifc -replace "'", "''")' -NetworkCategory Private")
    $cab.Add('')
}
$rod = @(
    '',
    "Write-Host 'Regras aplicadas:' -ForegroundColor Green",
    "Get-NetFirewallRule -Group 'WinSecServer' | Format-Table DisplayName, Enabled -AutoSize",
    "Write-Host 'Teste o acesso das estacoes. Para manter o firewall ligado: Set-NetFirewallProfile -All -Enabled True'"
)
(@($cab) + @($linhasRegras) + $rod) | Out-File -FilePath $arqRegras -Encoding utf8

$relatorio = Export-Relatorio -Escuta $escuta -Observadas $observadas -ArquivoRegras $arqRegras
$c = @($script:Resultados | Where-Object Status -eq 'Critico').Count
$a = @($script:Resultados | Where-Object Status -eq 'Alerta').Count
Write-Host ("`nResumo: {0} critico(s), {1} alerta(s)." -f $c, $a) -ForegroundColor White
Write-Host "Relatorio:        $relatorio" -ForegroundColor Cyan
Write-Host "Regras firewall:  $arqRegras" -ForegroundColor Cyan
if ([Environment]::UserInteractive) { Invoke-Item $relatorio }
