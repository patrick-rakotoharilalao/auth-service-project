import { cpSync } from 'fs';
import { join } from 'path';

const src = join(__dirname, 'src', 'generated');
const dest = join(__dirname, 'dist', 'generated');

cpSync(src, dest, { recursive: true });
console.log('✓ Generated files copied to dist/');