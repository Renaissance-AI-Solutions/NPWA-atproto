# PowerShell script to generate all lexicon types for PDS
Write-Host "Generating lexicon types for PDS..."

# Get all lexicon JSON files
$lexiconFiles = Get-ChildItem -Path "../../lexicons" -Recurse -Filter "*.json" | ForEach-Object { 
    # Convert to relative path from PDS directory
    $relativePath = $_.FullName -replace [regex]::Escape((Get-Location).Path), "."
    $relativePath = $relativePath -replace "\\", "/"
    return "`"$relativePath`""
}

# Join all files into a single command
$allFiles = $lexiconFiles -join " "

# Run the lexicon generation command
$command = "pnpm lex gen-server --yes ./src/lexicon $allFiles"
Write-Host "Running: $command"

# Execute the command
Invoke-Expression $command

Write-Host "Lexicon generation completed!"
