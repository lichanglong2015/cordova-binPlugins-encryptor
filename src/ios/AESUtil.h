//
//  AESUtil.h
//  hrzz
//
//  Created by Checker on 16/11/15.
//
//

#import <Foundation/Foundation.h>

@interface AESUtil : NSObject

+(NSString *)AES128Encrypt:(NSString *)plainText key:(NSString *)key;

+(NSString *)AES128Decrypt:(NSString *)encryptText key:(NSString *)key;

@end
