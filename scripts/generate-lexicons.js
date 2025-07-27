const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const lexiconPath = path.join(__dirname, '..', 'lexicons');
const outputPath = path.join(__dirname, '..', 'packages', 'pds', 'src', 'lexicon');

console.log('Starting lexicon generation...');
console.log('Lexicon path:', lexiconPath);
console.log('Output path:', outputPath);

// Ensure output directory exists
if (!fs.existsSync(outputPath)) {
  fs.mkdirSync(outputPath, { recursive: true });
  console.log('Created output directory:', outputPath);
}

// Recursively find all JSON files in lexicons/com/atproto
function findJsonFiles(dir) {
  const files = [];
  const items = fs.readdirSync(dir);
  
  for (const item of items) {
    const fullPath = path.join(dir, item);
    const stat = fs.statSync(fullPath);
    
    if (stat.isDirectory()) {
      files.push(...findJsonFiles(fullPath));
    } else if (item.endsWith('.json')) {
      files.push(fullPath);
    }
  }
  
  return files;
}

// Find all JSON files across all namespaces (com, app, chat, tools)
const lexiconFiles = findJsonFiles(lexiconPath);

console.log(`Found ${lexiconFiles.length} lexicon files`);

if (lexiconFiles.length === 0) {
  console.error('❌ No lexicon files found');
  process.exit(1);
}

// Normalize paths for Windows - convert backslashes to forward slashes
const normalizedOutputPath = outputPath.replace(/\\/g, '/');
const normalizedLexiconFiles = lexiconFiles.map(f => f.replace(/\\/g, '/'));

// Build the lexicon generation command using gen-server for PDS
const command = `node ./packages/lex-cli/dist/index.js gen-server --yes "${normalizedOutputPath}" ${normalizedLexiconFiles.join(' ')}`;

console.log('Running command:', command);

try {
  execSync(command, { 
    stdio: 'inherit',
    cwd: path.join(__dirname, '..')
  });
  console.log('✅ Lexicon generation completed successfully!');
} catch (error) {
  console.error('❌ Error generating lexicons:', error.message);
  
  // Additional debugging info
  console.error('Current working directory:', process.cwd());
  console.error('Lexicon directory exists:', fs.existsSync(lexiconPath));
  console.error('Output directory exists:', fs.existsSync(outputPath));
  
  // Check if @atproto/lex-cli is available
  try {
    execSync('npx @atproto/lex-cli --version', { stdio: 'pipe' });
    console.log('✅ @atproto/lex-cli is available');
  } catch (lexiconError) {
    console.error('❌ @atproto/lex-cli is not installed or not accessible');
    console.error('Try running: pnpm build to build the lex-cli package');
  }
  
  process.exit(1);
}