//
//  Encryptor.h
//  hrzz
//
//  Created by Checker on 16/11/12.
//
//

#import <Cordova/CDVPlugin.h>

@interface Encryptor : CDVPlugin

- (void)encrypt:(CDVInvokedUrlCommand*)command;
- (void)decrypt:(CDVInvokedUrlCommand*)command;

@end
