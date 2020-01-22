# Copy APSI libraries to the local machine
# This is used for our Automated Build to be able to find all necessary libraries.

$ScriptDirectory = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$APSIDirectory = Split-Path -Parent -Path $ScriptDirectory
$LibsDirectory = Join-Path -Path $ScriptDirectory -ChildPath Libs
$LibsZipFile = Join-Path -Path $LibsDirectory -ChildPath Libs.zip

mkdir -Path $LibsDirectory

Invoke-WebRequest -Uri "https://seal.file.core.windows.net/apsilibs/Libs.zip?sp=rl&st=2020-01-22T23:31:10Z&se=2022-01-23T23:31:00Z&sv=2019-02-02&sig=h3gcPt9Aoy7%2BwaWrTcgX6HqPGCFr3RL0t3wWrsoLCYQ%3D&sr=f" -OutFile $LibsZipFile
Expand-Archive -Path $LibsZipFile -DestinationPath $LibsDirectory

