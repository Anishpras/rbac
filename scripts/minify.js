const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const packageJson = require('../package.json');

// Create a banner with copyright and version information
const banner = `/**
 * @license
 * ${packageJson.name} v${packageJson.version}
 * Copyright (c) ${new Date().getFullYear()} ${packageJson.author}
 * Licensed under the ${packageJson.license} License
 */`;

const distDir = path.resolve(__dirname, '../dist');

// Function to recursively find all JS files
function findJsFiles(dir, fileList = []) {
  const files = fs.readdirSync(dir);

  files.forEach(file => {
    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);

    if (stat.isDirectory()) {
      findJsFiles(filePath, fileList);
    } else if (file.endsWith('.js')) {
      fileList.push(filePath);
    }
  });

  return fileList;
}

// Make sure dist directory exists
if (!fs.existsSync(distDir)) {
  console.error('Error: dist directory does not exist. Run build first.');
  process.exit(1);
}

// Find all JS files in the dist directory
const jsFiles = findJsFiles(distDir);

if (jsFiles.length === 0) {
  console.error('No JS files found in the dist directory.');
  process.exit(1);
}

// Record file sizes before minification
const sizeBefore = {};
jsFiles.forEach(file => {
  sizeBefore[file] = fs.statSync(file).size;
});

// Process each JS file
let totalSavings = 0;
let totalSizeBefore = 0;
let totalSizeAfter = 0;

jsFiles.forEach(filePath => {
  console.log(`Minifying ${path.relative(process.cwd(), filePath)}...`);
  
  try {
    // Read the original content
    const originalContent = fs.readFileSync(filePath, 'utf8');
    totalSizeBefore += originalContent.length;
    
    // Run terser on each file individually to preserve directory structure
    // Check if source map exists
    const sourceMapPath = `${filePath}.map`;
    const hasSourceMap = fs.existsSync(sourceMapPath);
    
    // Add source map options if available
    const sourceMapOptions = hasSourceMap && process.env.NODE_ENV !== 'production' ? 
      `--source-map "content='${sourceMapPath}',url='${path.basename(filePath)}.map'"` : '';
    
    // More aggressive compression for production
    const compressionOptions = process.env.NODE_ENV === 'production' ?
      '--compress passes=3,pure_getters=true,toplevel=true,drop_console=true,ecma=2020 --mangle toplevel=true,reserved=["RBACManager"]' :
      '--compress --mangle';
    
    const minifyCmd = `npx terser "${filePath}" ${compressionOptions} ${sourceMapOptions} --output "${filePath}"`;
    execSync(minifyCmd);
    
    // Add the banner to the minified file
    const minifiedContent = fs.readFileSync(filePath, 'utf8');
    fs.writeFileSync(filePath, `${banner}\n${minifiedContent}`);
    
    // Remove source maps after minification if in production mode
    if (process.env.NODE_ENV === 'production' && hasSourceMap) {
      fs.unlinkSync(sourceMapPath);
      
      // Also remove source map reference in the file
      let finalContent = fs.readFileSync(filePath, 'utf8');
      finalContent = finalContent.replace(/\/\/# sourceMappingURL=.*\.map/g, '');
      fs.writeFileSync(filePath, finalContent);
    }
    
    const sizeAfter = fs.statSync(filePath).size;
    totalSizeAfter += sizeAfter;
    
    const savings = sizeBefore[filePath] - sizeAfter;
    totalSavings += savings;
    
    console.log(`  Original size: ${(sizeBefore[filePath] / 1024).toFixed(2)} KB`);
    console.log(`  Minified size: ${(sizeAfter / 1024).toFixed(2)} KB`);
    console.log(`  Saved: ${(savings / 1024).toFixed(2)} KB (${((savings / sizeBefore[filePath]) * 100).toFixed(2)}%)`);
  } catch (error) {
    console.error(`Error minifying ${filePath}:`, error);
    process.exit(1);
  }
});

console.log('\nMinification complete!');
console.log(`Total original size: ${(totalSizeBefore / 1024).toFixed(2)} KB`);
console.log(`Total minified size: ${(totalSizeAfter / 1024).toFixed(2)} KB`);
console.log(`Total savings: ${(totalSavings / 1024).toFixed(2)} KB (${((totalSavings / totalSizeBefore) * 100).toFixed(2)}%)`);
