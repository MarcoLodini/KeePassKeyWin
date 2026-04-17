#!/bin/bash
# Build and test script for Linux/WSL.
# Windows dotnet writes to WSL UNC paths; a brief sync is needed between builds
# to ensure output files are visible to subsequent build steps.
set -e
DOTNET="/mnt/c/Program Files/dotnet/dotnet.exe"

"$DOTNET" build tests/TestSupport/KeePassStub/KeePassStub.csproj
sync; sleep 1
"$DOTNET" build src/PassKee.Core/PassKee.Core.csproj
sync; sleep 1
"$DOTNET" build src/PassKee.Plugin/PassKee.Plugin.csproj
sync; sleep 1
"$DOTNET" build tests/PassKee.Core.Tests/PassKee.Core.Tests.csproj
sync; sleep 1
"$DOTNET" test  tests/PassKee.Core.Tests/PassKee.Core.Tests.csproj --no-build
