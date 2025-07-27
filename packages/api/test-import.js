// Simple test to check if ComAtprotoServerNS can be imported
try {
  const { ComAtprotoServerNS } = require('./dist/client/index.js');
  console.log('SUCCESS: ComAtprotoServerNS imported successfully');
  console.log('ComAtprotoServerNS:', typeof ComAtprotoServerNS);
} catch (error) {
  console.log('ERROR: Failed to import ComAtprotoServerNS');
  console.log('Error:', error.message);
}
