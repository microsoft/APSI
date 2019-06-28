# Command to create the APSI SDK archive
$ScriptDirectory = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$APSIDirectory = Split-Path -Parent -Path $ScriptDirectory

function remove-dir-if-present {
    if (Test-Path $args) {
        Remove-Item -Recurse -Path $args
    }
}

remove-dir-if-present $ScriptDirectory\SDK
mkdir $ScriptDirectory\SDK

Copy-Item -Recurse -Path $APSIDirectory\APSIClient    $ScriptDirectory\SDK
Copy-Item -Recurse -Path $APSIDirectory\APSICommon    $ScriptDirectory\SDK
Copy-Item -Recurse -Path $APSIDirectory\APSINative    $ScriptDirectory\SDK
Copy-Item -Recurse -Path $APSIDirectory\APSIReceiver  $ScriptDirectory\SDK
Copy-Item -Recurse -Path $APSIDirectory\Cuckoo        $ScriptDirectory\SDK
Copy-Item          -Path $ScriptDirectory\APSISDK.sln $ScriptDirectory\SDK

remove-dir-if-present $ScriptDirectory\SDK\APSIClient\bin
remove-dir-if-present $ScriptDirectory\SDK\APSIClient\obj
remove-dir-if-present $ScriptDirectory\SDK\APSICommon\x64
remove-dir-if-present $ScriptDirectory\SDK\APSINative\x64
remove-dir-if-present $ScriptDirectory\SDK\APSIReceiver\x64
remove-dir-if-present $ScriptDirectory\SDK\Cuckoo\x64

Compress-Archive -CompressionLevel Optimal -Path $ScriptDirectory\SDK -DestinationPath $ScriptDirectory\apsisdk.zip
