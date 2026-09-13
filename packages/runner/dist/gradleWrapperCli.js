import { gradleDistributionCacheKey } from './gradleWrapper.js';
const [distributionUrl, extra] = process.argv.slice(2);
if (distributionUrl === undefined || extra !== undefined) {
    throw new Error('usage: automated-api-gradle-wrapper-cache-key <distribution-url>');
}
process.stdout.write(gradleDistributionCacheKey(distributionUrl));
//# sourceMappingURL=gradleWrapperCli.js.map