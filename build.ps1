[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $TargetOS,
    [Parameter(Mandatory)]
    [string] $Configuration,
    [Parameter(Mandatory)]
    [string] $Platform,
    [string] $Solution = 'DMF.sln',
    [ValidateSet('Build', 'Pack')]
    [string] $Action = 'Build'
)

# Global configuration
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

$script:TARGETOS_URL = @{
    '19H1' = 'https://devicesoss.z5.web.core.windows.net/ewdk/EWDK_vb_release_19041_191206-1406.iso'
}
$script:CACHE_DIR = Join-Path $PSScriptRoot -ChildPath '.cache'


#################################################################
# Helper functions
#
#################################################################
<#
    Execute a command, and update environment modification into
    current powershell process.
#>
function Set-EnvironmentFromScript {
    param(
        [Parameter(Mandatory)]
        [string] $Command
    )
    $envFile = Join-Path $([System.IO.Path]::GetTempPath()) -ChildPath ("{0}.env.json" -f [guid]::NewGuid())
    try {
        # Constructing the command line to grab the environment after the execution of the script file
        $pwshCommand = "[System.Environment]::GetEnvironmentVariables() | ConvertTo-Json | Out-File '${envFile}' -Force"
        $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($pwshCommand))
        $cmdLine = "`"$Command`" $args & powershell -NoLogo -NoProfile -NonInteractive -encodedCommand ${encodedCommand}"
        $cmdDotExe = (Get-Command 'cmd.exe').Source
        Write-Verbose "Executing: ${cmdline}"
        &$cmdDotExe /c $cmdLine | Write-Host

        # Updating the environment back in current session
        if (Test-Path $envFile -PathType Leaf) {
            Write-Verbose "Loading ${envFile}"
            $object = Get-Content $envFile -Raw | ConvertFrom-Json
            foreach ($name in $object.PSObject.Properties.name) {
                $value = $object."${name}"
                Write-Verbose "Setting environment variable ${name}=${value}"
                [System.Environment]::SetEnvironmentVariable($name, $value)
            }
        }
    }
    finally {
        if (Test-Path $envFile -PathType Leaf) {
            Remove-Item $envFile -Force
        }
    }
}

function Get-Nuget {
    [CmdletBinding()]
    param()
    $url = 'https://dist.nuget.org/win-x86-commandline/latest/nuget.exe'
    $nugetExe = Join-Path $script:CACHE_DIR -ChildPath 'gitversion.exe'
    if (-not (Test-Path $nugetExe -PathType Leaf)) {
        Write-Host "> Downloading latest nuget.exe"
        $null = New-Item $script:CACHE_DIR -Force -ItemType Directory
        Invoke-WebRequest -Uri $url -UseBasicParsing -OutFile $nugetExe
    }
    $nugetExe
}

function Request-GitVersion {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromRemainingArguments)]
        [string[]] $Arguments = @()
    )
    # Download GitVersion if needed
    $gitVersionExe = Join-Path $script:CACHE_DIR -ChildPath 'GitVersion.CommandLine/tools/gitversion.exe'
    if (-not (Test-Path $gitVersionExe -PathType Leaf)) {
        Write-Host "> Downloading latest gitversion.exe"
        $null = New-Item $script:CACHE_DIR -Force -ItemType Directory
        $nugetExe = Get-Nuget
        &$nugetExe install GitVersion.CommandLine -ExcludeVersion -OutputDirectory $script:CACHE_DIR
    }
    
    Write-Verbose "Executing: ${gitVersionExe} $($Arguments -join ' ')"
    $result = &$gitVersionExe @Arguments *>&1
    "GitVersion output: ${result}" | Write-Debug
    if ($LASTEXITCODE -ne 0) {
        $result | Write-Host
        throw "Unable to request the version! (ExitCode=${LASTEXITCODE})"
    }
    $result | ConvertFrom-Json
}

<#
    Download EWDK Iso from azure endpoint
#>
function Save-Ewdk {
    [CmdletBinding()]
    param(
        [string] $TargetOS
    )
    $backupProgressPreference = $ProgressPreference
    $isoFile = Join-Path $script:CACHE_DIR -ChildPath "${TargetOS}.iso"
    if (-not (Test-Path $isoFile -PathType Leaf)) {
        try {
            $ProgressPreference = 'SilentlyContinue'
            $url = $TARGETOS_URL[$TargetOS]
            Write-Host "Downloading ${TargetOS} from ${url} as ${isoFile}"
            Invoke-WebRequest -Uri $url -OutFile $isoFile -UseBasicParsing -ErrorAction Stop
            $isoFile
        }
        catch {
            if (Test-Path $isoFile -PathType Leaf) {
                Remove-Item $isoFile -Force
            }
        }
        finally {
            $ProgressPreference = $backupProgressPreference
        }
    }
    else {
        $isoFile
    }
}


#################################################################
# Actions
#
#################################################################
function Invoke-Build {
    [CmdletBinding()]
    param()
    $version = Request-GitVersion /nofetch
    $version | Out-String | Write-Host
    Write-Host "##vso[build.updatebuildnumber]$($version.NuGetVersion)"
    $isoFile = Save-Ewdk -TargetOS $TargetOS

    $mountedISO = $null
    try {
        Write-Host "Mounting ISO: ${isoFile}"
        $mountedISO = Mount-DiskImage -PassThru -ImagePath $isoFile
        Start-Sleep -Seconds 5 # TODO: Need to fix
        $diskVolume = ($mountedISO | Get-Volume).DriveLetter

        # Enable EWDK
        Write-Host "Enabling EWK from ${diskVolume}"
        Set-EnvironmentFromScript -Command "${diskVolume}:\BuildEnv\SetupBuildEnv.cmd"

        # Build the solution
        $splat = @(
            $Solution,
            "/p:Configuration=${Configuration}"
            "/p:Platform=${Platform}"
        )
        msbuild @splat
        $exitCode = $LASTEXITCODE
        $global:LASTEXITCODE = 0
        if ($exitCode -ne 0) {
            throw "Build failed (exitCode=${exitCode})"
        }
    } finally {
        Pop-Location
        if ($null -ne $mountedISO) {
            Write-Host "Unmounting $($mountedISO.ImagePath)"
            Dismount-DiskImage -ImagePath $mountedISO.ImagePath
        }
    }
}


function Invoke-Pack {
    [CmdletBinding()]
    param()
}


# Calling main action
&"Invoke-${Action}"