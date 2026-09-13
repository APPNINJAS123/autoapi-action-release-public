import { createHash } from 'node:crypto';
export function gradleDistributionCacheKey(distributionUrl) {
    const url = new URL(distributionUrl);
    if (url.protocol !== 'https:' || url.hostname !== 'services.gradle.org') {
        throw new Error('Gradle distribution URL must use the official HTTPS host');
    }
    return BigInt(`0x${createHash('md5').update(distributionUrl).digest('hex')}`).toString(36);
}
//# sourceMappingURL=gradleWrapper.js.map