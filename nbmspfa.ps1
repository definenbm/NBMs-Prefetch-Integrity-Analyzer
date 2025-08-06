$dir = "C:\Windows\Prefetch"
Clear-Host

Write-Host @"
 ________   ________  _____ ______   ________           ________  ________ ________     
|\   ___  \|\   __  \|\   _ \  _   \|\   ____\         |\   __  \|\  _____\\   __  \    
\ \  \\ \  \ \  \|\ /\ \  \\\__\ \  \ \  \___|_        \ \  \|\  \ \  \__/\ \  \|\  \   
 \ \  \\ \  \ \   __  \ \  \\|__| \  \ \_____  \        \ \   ____\ \   __\\ \   __  \  
  \ \  \\ \  \ \  \|\  \ \  \    \ \  \|____|\  \        \ \  \___|\ \  \_| \ \  \ \  \ 
   \ \__\\ \__\ \_______\ \__\    \ \__\____\_\  \        \ \__\    \ \__\   \ \__\ \__\
    \|__| \|__|\|_______|\|__|     \|__|\_________\        \|__|     \|__|    \|__|\|__|
                                       \|_________|                                                                                                                          
"@ -ForegroundColor Cyan

Write-Host ""
Write-Host "  prefetch integ analyzer made by nbm  " -ForegroundColor White -NoNewline

function Test-Admin {
    $u = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($u)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (!(Test-Admin)) {
    Write-Warning "run as admin"
    Start-Sleep 10
    exit
}

Start-Sleep 3

$files = Get-ChildItem -Path $dir -Filter *.pf
$hashes = @{}
$sus = @{}

foreach ($f in $files) {
    try {
        if ($f.IsReadOnly) {
            if (-not $sus.ContainsKey($f.Name)) {
                $sus[$f.Name] = "$($f.Name) is read only"
            }
        }

        $r = [System.IO.StreamReader]::new($f.FullName)
        $buf = New-Object char[] 3
        $null = $r.ReadBlock($buf, 0, 3)
        $r.Close()

        if (-join $buf -ne "MAM") {
            if (-not $sus.ContainsKey($f.Name)) {
                $sus[$f.Name] = "$($f.Name) isnt a valid prefetch file"
            }
        }

        $h = Get-FileHash -Path $f.FullName -Algorithm SHA256

        if ($hashes.ContainsKey($h.Hash)) {
            $hashes[$h.Hash].Add($f.Name)
        } else {
            $list = [System.Collections.Generic.List[string]]::new()
            $list.Add($f.Name)
            $hashes[$h.Hash] = $list
        }

    } catch {
        Write-Host "error: $($f.FullName) - $($_.Exception.Message)"
    }
}

foreach ($h in $hashes.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }) {
    foreach ($f in $h.Value) {
        if (-not $sus.ContainsKey($f)) {
            $sus[$f] = "$f has duplicate hash"
        }
    }
}

if ($sus.Count) {
    Write-Host "suspicious files:" -ForegroundColor Yellow
    foreach ($k in $sus.Keys) {
        Write-Host "$k : $($sus[$k])"
    }
} else {
    Write-Host "nothing suspicious"
}
