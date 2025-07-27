# PowerShell script to generate critical API lexicon TypeScript files
# This script generates only the most important lexicon files needed for the API

Write-Host "Generating critical API lexicon TypeScript files..."

# Define critical files for the API package
$criticalFiles = @(
    # App.bsky actor files (including our badges changes)
    "../../lexicons/app/bsky/actor/defs.json",
    "../../lexicons/app/bsky/actor/profile.json",
    "../../lexicons/app/bsky/actor/getProfile.json",
    "../../lexicons/app/bsky/actor/getProfiles.json",
    
    # App.bsky feed files
    "../../lexicons/app/bsky/feed/defs.json",
    "../../lexicons/app/bsky/feed/post.json",

    # App.bsky embed files (missing ones)
    "../../lexicons/app/bsky/embed/recordWithMedia.json",
    "../../lexicons/app/bsky/embed/video.json",
    "../../lexicons/app/bsky/feed/like.json",
    "../../lexicons/app/bsky/feed/repost.json",
    
    # App.bsky embed files
    "../../lexicons/app/bsky/embed/defs.json",
    "../../lexicons/app/bsky/embed/record.json",
    "../../lexicons/app/bsky/embed/images.json",
    "../../lexicons/app/bsky/embed/external.json",
    
    # App.bsky richtext files
    "../../lexicons/app/bsky/richtext/facet.json",
    
    # App.bsky graph files
    "../../lexicons/app/bsky/graph/defs.json",
    "../../lexicons/app/bsky/graph/follow.json",
    "../../lexicons/app/bsky/graph/block.json",
    
    # Com.atproto files (critical ones)
    "../../lexicons/com/atproto/label/defs.json",
    "../../lexicons/com/atproto/repo/strongRef.json",
    "../../lexicons/com/atproto/moderation/defs.json",
    "../../lexicons/com/atproto/server/defs.json",
    "../../lexicons/com/atproto/server/createAccount.json",
    "../../lexicons/com/atproto/server/createSession.json",
    "../../lexicons/com/atproto/server/getSession.json",
    "../../lexicons/com/atproto/server/refreshSession.json",
    "../../lexicons/com/atproto/server/deleteSession.json",

    # Com.atproto identity files
    "../../lexicons/com/atproto/identity/resolveHandle.json",

    # Chat.bsky files
    "../../lexicons/chat/bsky/actor/defs.json",
    "../../lexicons/chat/bsky/actor/declaration.json",
    "../../lexicons/chat/bsky/actor/deleteAccount.json",
    "../../lexicons/chat/bsky/actor/exportAccountData.json",
    "../../lexicons/chat/bsky/convo/defs.json",
    "../../lexicons/chat/bsky/convo/getConvo.json",
    "../../lexicons/chat/bsky/convo/listConvos.json",
    "../../lexicons/chat/bsky/convo/sendMessage.json",

    # Tools.ozone files (essential ones)
    "../../lexicons/tools/ozone/moderation/defs.json",
    "../../lexicons/tools/ozone/server/getConfig.json"
)

Write-Host "Total critical files to generate: $($criticalFiles.Count)"

# Generate all critical files in one command
$cmd = "pnpm lex gen-api --yes ./src/client " + ($criticalFiles -join " ")
Write-Host "Running command..."

# Execute command
try {
    Invoke-Expression $cmd
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Critical API lexicon files generated successfully"
    } else {
        Write-Host "Failed to generate critical API lexicon files with exit code $LASTEXITCODE"
        exit 1
    }
} catch {
    Write-Host "Error generating critical API lexicon files: $($_.Exception.Message)"
    exit 1
}

Write-Host "Critical API lexicon generation complete!"
