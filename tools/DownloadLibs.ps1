# Copy APSI libraries to the local machine
# This is used for our Automated Build to be able to find all necessary libraries.

$ScriptDirectory = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$APSIDirectory = Split-Path -Parent -Path $ScriptDirectory
$LibsDirectory = Join-Path -Path $ScriptDirectory -ChildPath Libs
$LibsZipFile = Join-Path -Path $LibsDirectory -ChildPath Libs.zip

mkdir -Path $LibsDirectory

Invoke-WebRequest -Uri "https://vmcreator.file.core.windows.net/apsilibs/Libs.zip?sp=rl&st=2019-07-19T21:12:33Z&se=2021-07-20T21:12:00Z&sv=2018-03-28&sig=aMOA0ff%2F%2BL6fm3ZytXZl1q%2FKbKoedsYD6A9v6xeognk%3D&sr=f" -OutFile $LibsZipFile
Expand-Archive -Path $LibsZipFile -DestinationPath $LibsDirectory

