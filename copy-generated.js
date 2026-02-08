const fs = require('fs');
const path = require('path');

const src = path.join(__dirname, 'src', 'generated');
const dest = path.join(__dirname, 'dist', 'generated');

fs.cpSync(src, dest, { recursive: true });
console.log('✓ Generated files copied to dist/');