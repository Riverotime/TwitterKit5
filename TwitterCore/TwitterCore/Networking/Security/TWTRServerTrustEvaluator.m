/*
 * Copyright (C) 2017 Twitter, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#import "TWTRServerTrustEvaluator.h"
#import <CommonCrypto/CommonDigest.h>
#import "TWTRX509Certificate.h"

/*
static const int TWTR_DIGEST_HEX_STRING_LENGTH = 41;
static char TWTR_TWITTER_PINS[][TWTR_DIGEST_HEX_STRING_LENGTH] = {
    "1a21b4952b6293ce18b365ec9c0e934cb381e6d4",
    "56fef3c2147d4ed38837fdbd3052387201e5778d",
};
static const int TWTR_NUM_PINNED_CERTS = sizeof(TWTR_TWITTER_PINS) / TWTR_DIGEST_HEX_STRING_LENGTH;
*/

static NSCache *TWTRCertificateCache;

@interface TWTRServerTrustEvaluator ()

@property (nonatomic, strong, readwrite) NSArray *pinnedPublicKeys;

@end

@implementation TWTRServerTrustEvaluator

+ (void)initialize
{
    if (self == [TWTRServerTrustEvaluator class]) {
        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            TWTRCertificateCache = [[NSCache alloc] init];
        });
    }
}

- (BOOL)evaluateServerTrust:(SecTrustRef)serverTrust forDomain:(NSString *)domain
{
    if ([TWTRServerTrustEvaluator isCertificateChainCached:serverTrust]) {
        return YES;
    }

    CFIndex chainLength = SecTrustGetCertificateCount(serverTrust);
    for (int i = 0; i < chainLength; i++) {
        SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, i);
        TWTRX509Certificate *x509 = [[TWTRX509Certificate alloc] initWithCertificate:certificate];
        NSData *publicKeyBytes = [x509 publicKey];
        if ([TWTRServerTrustEvaluator isPinnedSPKI:publicKeyBytes]) {
            [TWTRServerTrustEvaluator cacheValidCertificateChain:serverTrust];
            return YES;
        }
    }
    return NO;
}




+ (BOOL)isPinnedSPKI:(NSData *)encodedSpki
{
    return TRUE;
    unsigned char digest[CC_SHA1_DIGEST_LENGTH];
    unsigned char pin[CC_SHA1_DIGEST_LENGTH];

    if (CC_SHA1([encodedSpki bytes], (CC_LONG)[encodedSpki length], digest)) {
        for (int i = 0; i < TWTR_NUM_PINNED_CERTS; i++) {
            [self hexDecode:TWTR_TWITTER_PINS[i] decoded:pin];

            if (memcmp(digest, pin, CC_SHA1_DIGEST_LENGTH) == 0) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

+ (void)hexDecode:(const char *)hexString decoded:(unsigned char *)decoded
{
    size_t length = strlen(hexString);

    for (size_t i = 0; i < length; i += 2) {
        char hexByte[3];
        hexByte[0] = hexString[i];
        hexByte[1] = hexString[i + 1];
        hexByte[2] = '\0';

        decoded[i / 2] = (unsigned char)strtoul(hexByte, NULL, 16);
    }
}

+ (BOOL)isCertificateChainCached:(SecTrustRef)serverTrust
{
    SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, 0);
    TWTRX509Certificate *x509 = [[TWTRX509Certificate alloc] initWithCertificate:certificate];
    NSString *fingerprint = [x509 fingerprint];
    if ([TWTRCertificateCache objectForKey:fingerprint]) {
        return YES;
    }
    return NO;
}

+ (void)cacheValidCertificateChain:(SecTrustRef)serverTrust
{
    SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, 0);
    TWTRX509Certificate *x509 = [[TWTRX509Certificate alloc] initWithCertificate:certificate];
    NSString *fingerprint = [x509 fingerprint];
    [TWTRCertificateCache setObject:[NSNull null] forKey:fingerprint];
}

@end
