# Generate Lexicons for PDS Package
# This script runs the lexicon code generation for the PDS (Personal Data Server) package

Write-Host "Generating lexicons for PDS package..." -ForegroundColor Green

try {
    # Run the codegen script defined in package.json
    pnpm run codegen
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ PDS lexicon generation completed successfully!" -ForegroundColor Green
    } else {
        Write-Host "❌ PDS lexicon generation failed with exit code: $LASTEXITCODE" -ForegroundColor Red
        exit $LASTEXITCODE
    }
} catch {
    Write-Host "❌ Error running PDS lexicon generation: $_" -ForegroundColor Red
    exit 1
}
