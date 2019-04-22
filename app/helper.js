/**
 * Copyright 2017 IBM All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an 'AS IS' BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
'use strict';

var log4js = require('log4js');
var logger = log4js.getLogger('Helper');
logger.setLevel('DEBUG');

var path = require('path');

var path = require('path');
var util = require('util');

var hfc = require('fabric-client');
hfc.setLogger(logger);
var fabricCAClient=require('fabric-ca-client')





async function getClientForOrg(userorg, username) {
	logger.debug('getClientForOrg - ****** START %s %s', userorg, username)
    let config = '-connection-profile-path';
	let client = hfc.loadFromConfig(hfc.getConfigSetting('network' + config));
	client.loadFromConfig(hfc.getConfigSetting(userorg + config));
	await client.initCredentialStores();
	if (username) {
		let user = await client.getUserContext(username, true);
		if (!user) {
			throw new Error(util.format('User was not found :', username));
		} else {
			logger.debug('User %s was found to be registered and enrolled', username);
		}
	}
	logger.debug('getClientForOrg - ****** END %s %s \n\n', userorg, username)
    return client;
}

var getRegisteredUser = async function (username, userOrg, isJson) {
	try {
		let secret;
		var client = await getClientForOrg(userOrg);
		var fabric_ca_client = client.getCertificateAuthority();
        logger.debug('Successfully initialized the credential stores');
        var user = await client.getUserContext(username, true);
		if (user && user.isEnrolled()) {
			//if user is already registered
			logger.info('Successfully loaded member from persistence');
            var admins = hfc.getConfigSetting('admins');
			let adminUserObj = await client.setUserContext({
				username: admins[0].username,
				password: admins[0].secret
			});
			//getting identityService
			const identityService = fabric_ca_client.newIdentityService('admin');
			var request = {enrollmentID:username,affiliation:userOrg.toLowerCase() + '.department1',maxEnrollments:-1,attrs:[{name:'jerry',value:'developer',ecert: true}]}
			//updating the certificate
            let response = await identityService.update(username,request,adminUserObj);
			console.log('===response is=====',JSON.stringify(response));
			
		} else {
	         // user was not enrolled, so we will need an admin user object to register
			logger.info('User %s was not enrolled, so we will need an admin user object to register', username);
			var admins = hfc.getConfigSetting('admins');
			let adminUserObj = await client.setUserContext({
				username: admins[0].username,
				password: admins[0].secret
			});
			let caClient = client.getCertificateAuthority();
			 secret = await caClient.register({
				enrollmentID: username,
				affiliation: userOrg.toLowerCase() + '.department1',
				maxEnrollments :-1,
				attrs: [{
						name: 'jerry',
						value: 'student',
						ecert: true
					}],
					
			}, adminUserObj);
			console.log('===================================secret on registration========================',secret);
			logger.debug('Successfully got the secret for user %s', username);
		  
			logger.debug('Successfully enrolled username %s  and setUserContext on the client object', username);
		}
	
   //enrolling the user,if user is already enrolled then  reenrolling the user
	var enrollresponse= await fabric_ca_client.enroll({enrollmentID:username,enrollmentSecret:'auXYNvqjggtv'});
	console.log(enrollresponse)

 user = await client.createUser({username:username,mspid:'Org1MSP',cryptoContent:{privateKeyPEM:enrollresponse.key.toBytes(),signedCertPEM:enrollresponse.certificate}
	 })
	 
	console.log(user);
	// user = await client.setUserContext({
	// 	username:username,
	// 	password: 'KowZehBNmvID'

		
	// });

	user=await client.setUserContext(user);
	
	console.log('enroll response',enrollresponse);

		if (user && user.isEnrolled) {
			if (isJson && isJson === true) {
				var response = {
					success: true,
					secret: user._enrollmentSecret,
					message: username + ' enrolled Successfully',
				};
				
				return response;
			}
		} else {
			throw new Error('User was not enrolled ');
		}
	} catch (error) {
		logger.error('Failed to get registered user: %s with error: %s', username, error.toString());
		return 'failed ' + error.toString();
	}

};

var setupChaincodeDeploy = function () {
	process.env.GOPATH = path.join(__dirname, hfc.getConfigSetting('CC_SRC_PATH'));
};

var getLogger = function (moduleName) {
	var logger = log4js.getLogger(moduleName);
	logger.setLevel('DEBUG');
	return logger;
};

exports.getClientForOrg = getClientForOrg;
exports.getLogger = getLogger;
exports.setupChaincodeDeploy = setupChaincodeDeploy;
exports.getRegisteredUser = getRegisteredUser;