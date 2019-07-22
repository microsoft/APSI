# Copy APSI libraries to the local machine
# This is used for our Automated Build to be able to find all necessary libraries.

$ScriptDirectory = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$APSIDirectory = Split-Path -Parent -Path $ScriptDirectory
$LibsDirectory = Join-Path -Path $ScriptDirectory -ChildPath Libs
$LibsZipFile = Join-Path -Path $LibsDirectory -ChildPath Libs.zip

mkdir -Path $LibsDirectory

Invoke-WebRequest -Uri "https://seal.file.core.windows.net/apsilibs/Libs.zip?sp=rl&st=2019-07-22T19:08:08Z&se=2021-07-23T19:08:00Z&sv=2018-03-28&sig=%2FOpDjExw7tll1hN12d8%2FOdjO8N7II8yCgLa%2FCUJ4Cm4%3D&sr=f" -OutFile $LibsZipFile
Expand-Archive -Path $LibsZipFile -DestinationPath $LibsDirectory

