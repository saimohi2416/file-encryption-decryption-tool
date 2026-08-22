const { execSync } = require('child_process');
const domain = 'securevault-enterprise.surge.sh';

console.log('===========================================================');
console.log('   SecureVault Enterprise - Surge.sh Deployment Engine');
console.log('===========================================================');
console.log(`Publishing build to: https://${domain} ...`);

try {
  const result = execSync(`node node_modules/surge/bin/surge ./ ${domain}`, {
    stdio: 'inherit',
    encoding: 'utf-8'
  });
  console.log('\n===========================================================');
  console.log(' [SUCCESS] DEPLOYMENT COMPLETED SUCCESSFULLY!');
  console.log(` Public HTTPS URL: https://${domain}`);
  console.log('===========================================================\n');
} catch (err) {
  console.error('\n[ERROR] Deployment failed:', err.message);
  process.exit(1);
}
