#import "LCUtils/GCSharedUtils.h"
#import "LCUtils/Shared.h"
#import "Utils.h"
#import "WebServer.h"
#include "src/Theming.h"
#import "src/components/LogUtils.h"

#import "GCDWebServer/GCDWebServer/Requests/GCDWebServerMultiPartFormRequest.h"
#import "GCDWebServer/GCDWebServer/Responses/GCDWebServerDataResponse.h"

extern NSBundle* gcMainBundle;

@implementation WebServer
- (void)initServer {
	if ([[Utils getPrefsGC] boolForKey:@"WEB_SERVER"]) {
		__weak WebServer* weakSelf = self;
		self.webServer = [[GCDWebServer alloc] init];

		NSString* websitePath = [gcMainBundle pathForResource:@"web" ofType:nil];

		[self.webServer addGETHandlerForBasePath:@"/" directoryPath:websitePath indexFilename:nil cacheAge:0 allowRangeRequests:YES];

		NSString* infoPlistPath;
		if (![Utils isSandboxed]) {
			infoPlistPath = [[Utils getGDBundlePath] stringByAppendingPathComponent:@"DindeGDPS.app/Info.plist"];
		} else {
			if ([Utils isContainerized]) {
				infoPlistPath = [[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent:@"Info.plist"];
			} else {
				infoPlistPath = [[[LCPath bundlePath] URLByAppendingPathComponent:[Utils gdBundleName]] URLByAppendingPathComponent:@"Info.plist"].path;
			}
		}
		//[NSClassFromString(@"WebSharedClass") forceRestart];
		NSDictionary* infoDictionary = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];

		NSString* model = [[UIDevice currentDevice] localizedModel];
		NSString* systemName = [[UIDevice currentDevice] systemName];
		NSString* systemVersion = [[UIDevice currentDevice] systemVersion];
		NSString* deviceStr = [NSString stringWithFormat:@"%@ %@ (%@,%@)", systemName, systemVersion, model, [Utils archName]];
		NSFileManager* fm = [NSFileManager defaultManager];
		[self.webServer addHandlerForMethod:@"GET" pathRegex:@"/.*\\.html" requestClass:[GCDWebServerRequest class]
							   processBlock:^GCDWebServerResponse*(GCDWebServerRequest* request) {
								   NSError* error = nil;
								   NSArray* files;
								   if ([Utils isContainerized]) {
									   files = [fm contentsOfDirectoryAtPath:[[LCPath docPath].path stringByAppendingString:@"/game/geode/mods/"] error:&error];
								   } else {
									   files = [fm contentsOfDirectoryAtPath:[[Utils docPath] stringByAppendingString:@"game/geode/mods/"] error:&error];
								   }
								   int modsInstalled = 0;
								   if (!error) {
									   modsInstalled = (unsigned long)[files count];
								   }
								   NSDictionary* variables = @{
									   @"container" : [Utils isContainerized] ? @"container" : @"not container",
									   @"launch" : [Utils isContainerized] ? @"Restart" : @"Launch",
									   @"host" : [NSString stringWithFormat:@"%@", weakSelf.webServer.serverURL],
									   @"version" : [NSString stringWithFormat:@"v%@", [[gcMainBundle infoDictionary] objectForKey:@"CFBundleVersion"] ?: @"N/A"],
									   @"geode" : [Utils getGeodeVersion],
									   @"gd" : [NSString stringWithFormat:@"v%@", [infoDictionary objectForKey:@"CFBundleShortVersionString"] ?: @"N/A"],
									   @"device" : deviceStr,
									   @"mods" : [NSString stringWithFormat:@"%i", modsInstalled],
								   };
								   return [GCDWebServerDataResponse responseWithHTMLTemplate:[websitePath stringByAppendingPathComponent:request.path] variables:variables];
							   }];

		[self.webServer addHandlerForMethod:@"GET" path:@"/styles.css" requestClass:[GCDWebServerRequest class] processBlock:^GCDWebServerResponse*(GCDWebServerRequest* request) {
			NSString* path = [gcMainBundle pathForResource:@"styles" ofType:@"css" inDirectory:@"web"];
			NSError* error = nil;
			NSString* content = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:&error];
			if (error) {
				AppLog(@"Couldn't read styles.css: %@", error);
				return [GCDWebServerDataResponse responseWithStatusCode:500];
			}
			return [GCDWebServerDataResponse responseWithData:[[content stringByReplacingOccurrencesOfString:@"%accent%" withString:[Utils colorToHex:[Theming getAccentColor]]]
																  dataUsingEncoding:NSUTF8StringEncoding]
												  contentType:@"text/css"];
		}];

		[self.webServer addHandlerForMethod:@"GET" path:@"/" requestClass:[GCDWebServerRequest class] processBlock:^GCDWebServerResponse*(GCDWebServerRequest* request) {
			return [GCDWebServerResponse responseWithRedirect:[NSURL URLWithString:@"index.html" relativeToURL:request.URL] permanent:NO];
		}];
		[self.webServer addHandlerForMethod:@"POST" path:@"/launch" requestClass:[GCDWebServerRequest class] processBlock:^GCDWebServerResponse*(GCDWebServerRequest* request) {
			GCDWebServerDataResponse* response = [GCDWebServerDataResponse responseWithStatusCode:200];
			if ([Utils isContainerized]) {
				[NSClassFromString(@"GCSharedUtils") relaunchApp];
				return response;
			}
			if (([[Utils getPrefsGC] boolForKey:@"MANUAL_REOPEN"] && ![Utils isSandboxed]) || NSClassFromString(@"LCSharedUtils")) {
				[[Utils getPrefsGC] setValue:[Utils gdBundleName] forKey:@"selected"];
				[[Utils getPrefsGC] setValue:@"GeometryDash" forKey:@"selectedContainer"];
				[[Utils getPrefsGC] setBool:NO forKey:@"safemode"];
				NSFileManager* fm = [NSFileManager defaultManager];
				[fm createFileAtPath:[[LCPath docPath] URLByAppendingPathComponent:@"jitflag"].path contents:[[NSData alloc] init] attributes:@{}];
				// get around NSUserDefaults because sometimes it works and doesnt work when relaunching...
				[Utils showNoticeGlobal:@"launcher.relaunch-notice".loc];
				return response;
			}
			if (![Utils isSandboxed]) {
				[Utils tweakLaunch_withSafeMode:false];
				return response;
			}
			NSString* openURL = [NSString stringWithFormat:@"geode://launch"];
			NSURL* url = [NSURL URLWithString:openURL];
			if ([[NSClassFromString(@"UIApplication") sharedApplication] canOpenURL:url]) {
				[[NSClassFromString(@"UIApplication") sharedApplication] openURL:url options:@{} completionHandler:nil];
				return response;
			};
			return response;
		}];
		[self.webServer addHandlerForMethod:@"POST" path:@"/stop" requestClass:[GCDWebServerRequest class] processBlock:^GCDWebServerResponse*(GCDWebServerRequest* request) {
			GCDWebServerDataResponse* response = [GCDWebServerDataResponse responseWithStatusCode:200];
			[weakSelf.webServer stop];
			return response;
		}];

		[self.webServer addHandlerForMethod:@"GET" path:@"/logs" requestClass:[GCDWebServerRequest class] processBlock:^GCDWebServerResponse*(GCDWebServerRequest* request) {
			if (![Utils isContainerized]) {
				GCDWebServerDataResponse* response = [GCDWebServerDataResponse responseWithStatusCode:400];
				return response;
			} else {
				NSURL* file = [Utils pathToMostRecentLogInDirectory:[[LCPath docPath].path stringByAppendingString:@"/game/geode/logs/"]];
				NSError* error = nil;
				NSString* content = [NSString stringWithContentsOfFile:file.path encoding:NSUTF8StringEncoding error:&error];
				if (error) {
					AppLog(@"Couldn't read the latest log: %@", error);
					return [GCDWebServerDataResponse responseWithStatusCode:500];
				}
				GCDWebServerDataResponse* response = [GCDWebServerDataResponse responseWithData:(NSData*)[content dataUsingEncoding:NSUTF8StringEncoding]
																					contentType:@"text/plain"];
				return response;
			}
		}];
		[self.webServer
			addHandlerForMethod:@"POST"
						   path:@"/upload"
				   requestClass:[GCDWebServerMultiPartFormRequest class] processBlock:^GCDWebServerResponse*(GCDWebServerMultiPartFormRequest* request) {
					   int uploads = 0;
					   int fails = 0;
					   AppLog(@"[Server] Received request to upload files");
					   for (GCDWebServerMultiPartFile* file in request.files) {
						   if (![file.controlName isEqualToString:@"files"])
							   continue;
						   AppLog(@"[Server] Received request to upload %@", file.fileName);
						   NSURL* path;
						   if ([Utils isContainerized]) {
							   path = [NSURL fileURLWithPath:[[LCPath docPath].path stringByAppendingString:@"/game/geode/mods/"]];
						   } else {
							   path = [NSURL fileURLWithPath:[[Utils docPath] stringByAppendingString:@"game/geode/mods/"]];
						   }
						   NSURL* destinationURL = [path URLByAppendingPathComponent:file.fileName];
						   if ([file.fileName isEqualToString:@"Geode.ios.dylib"]) {
							   if ([Utils isContainerized]) {
								   AppLog(@"[Server] Geode dylib cannot be replaced ingame");
								   fails++;
								   continue;
							   }
							   AppLog(@"[Server] Getting Geode dylib path...");
							   NSString* docPath = [fm URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask].lastObject.path;
							   NSString* tweakPath = [NSString stringWithFormat:@"%@/Tweaks/Geode.ios.dylib", docPath];
							   if (![Utils isSandboxed]) {
								   NSString* applicationSupportDirectory = [[Utils getGDDocPath] stringByAppendingString:@"Library/Application Support"];
								   if (applicationSupportDirectory != nil) {
									   // https://github.com/geode-catgirls/geode-inject-ios/blob/meow/src/geode.m
									   NSString* geode_dir = [applicationSupportDirectory stringByAppendingString:@"/GeometryDash/game/geode"];
									   NSString* geode_lib = [geode_dir stringByAppendingString:@"/Geode.ios.dylib"];
									   bool is_dir;
									   NSFileManager* fm = [NSFileManager defaultManager];
									   if (![fm fileExistsAtPath:geode_dir isDirectory:&is_dir]) {
										   AppLog(@"mrow creating geode dir !!");
										   if (![fm createDirectoryAtPath:geode_dir withIntermediateDirectories:YES attributes:nil error:NULL]) {
											   AppLog(@"mrow failed to create folder!!");
										   }
									   }
									   tweakPath = geode_lib;
								   }
							   }
							   destinationURL = [NSURL fileURLWithPath:tweakPath];
						   } else if (![[file.fileName pathExtension] isEqualToString:@"geode"]) {
							   AppLog(@"[Server] File %@ is not a geode file", file.fileName);
							   fails++;
							   continue;
						   }
						   NSError* error = nil;
						   if ([fm fileExistsAtPath:destinationURL.path]) {
							   [fm removeItemAtURL:destinationURL error:&error];
							   if (error) {
								   AppLog(@"[Server] Couldn't replace file %@: %@", file.fileName, error);
								   fails++;
								   continue;
							   }
						   }
						   if ([fm moveItemAtPath:file.temporaryPath toPath:destinationURL.path error:&error]) {
							   AppLog(@"[Server] Uploaded file %@!", file.fileName);
							   uploads++;
						   } else {
							   AppLog(@"[Server] Error saving file %@: %@", file.fileName, error);
							   fails++;
						   }
					   }

					   NSString* response = nil;
					   if (uploads > 0 && fails > 0) {
						   response = [NSString stringWithFormat:@"Successfully uploaded %@ files, failed to upload %@ files. View app logs for more info.", @(uploads), @(fails)];
					   } else if (uploads > 0) {
						   response = [NSString stringWithFormat:@"Successfully uploaded %@ files.", @(uploads)];
					   } else if (fails > 0) {
						   response = [NSString stringWithFormat:@"Failed to upload %@ files. View app logs for more info.", @(fails)];
					   } else {
						   response = @"No files uploaded.";
					   }
					   return [GCDWebServerDataResponse responseWithText:response];
				   }];
		[self.webServer startWithPort:8080 bonjourName:nil];
		AppLog(@"Started server: %@", self.webServer.serverURL);
	}
}
@end
