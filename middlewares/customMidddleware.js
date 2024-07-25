const { log } = require('util');
const { readJsonFiles, checkValidKeyInDictionary, validateAccessToken,logError,logInfo,logWarning } = require('../commonServices/commonOperation');
const MongoDBManager = require('../commonServices/mongoServices');
const otherConfig = readJsonFiles('./applicationConfig/otherFeaturesConfigs.json');
const apiRequirementsConfig = readJsonFiles('./applicationConfig/apiRequirements.json');

const mongoConfig = readJsonFiles('./applicationConfig/mongoConfig.json'); // Instantiate the MongoDBManager


const APIMiddleware = async (req, res, next) => {
    try {
        // Check if the request is to an API endpoint
        const requestBody = req.body;
        console.log('requestBody', requestBody);
        let apiKeyProjectName = req.header('apiKey')?req.header('apiKey').split('//'):['',''];
        const apiKey = requestBody.apiKey || apiKeyProjectName[1];
        const projectName = requestBody.projectName || apiKeyProjectName[0];
        req.body.projectName = projectName;
        console.log('apikey--', apiKey, 'projectName--', projectName)
        if (!apiKey || !projectName) {
            message_error = { error: 'Please provide apiKey & projectName', 'success': false, message: 'input error' };
            logError({ ...message_error });
            return res.status(400).json(message_error);
        }
        if (!apiRequirementsConfig[projectName]) {
            message_error = { error: 'project does not exist', 'success': false, message: 'input error' };
            logError({ ...message_error });
            return res.status(400).json(message_error);
        }
        if (apiKey !== otherConfig[projectName].apiKey) {
            message_error = { error: 'Invalid apiKey', 'success': false, message: 'input error' };
            logError({ ...message_error });
            return res.status(400).json(message_error);
        }
        let requestPath =req.path.toLowerCase(req.path)
        console.log('request.path', req.path,requestPath.includes('/roleaccess/'));
        if (requestPath.includes('/auth/')) {
            if (!apiRequirementsConfig[projectName]) {
                message_error = { error: 'projectName does not exist', 'success': false, message: 'input error' };
                logError({ ...message_error });
                return res.status(400).json(message_error);
            }
            const accessToken = req.headers.authorization.split('Bearer ').pop();
            const tokenInfo = validateAccessToken(accessToken, otherConfig[projectName].tokenConfig.secretKey);
            console.log('tokenInfo--', tokenInfo);
            if (tokenInfo) {
                if (requestPath.includes('/auth/roleaccess/')) {
                    if (!await isAllowed(req, tokenInfo)) {
                        message_error = { error: 'Access Forbidden', 'success': false, message: 'permission error' };
                        logError({ ...message_error });
                        return res.status(403).json(message_error);
                    }
                }
                if (requestPath.includes('/vfuser/')) {
                    if (!await isVerified(req, tokenInfo)) {
                        message_error = { error: 'Access Forbidden', 'success': false, message: 'User not verified' };
                        logError({ ...message_error });
                        return res.status(403).json(message_error);
                    }
                }
                req.tokenInfo = tokenInfo;
                return next();
            } else {
                message_error = { error: 'Invalid or expired access token', 'success': false, message: 'permission error' };
                logError({ ...message_error });
                return res.status(403).json(message_error);
            }
        }
        // Pass the request to the next middleware or route handler
        return next();
    } catch (err) {
        console.error('Exception in middleware', err);
        message_error = { error: err.message, 'success': false, message: 'middleware error' };
        logError({ ...message_error });
        return res.status(500).json(message_error);
    }
};

const isAllowed = async(req, tokenInfo) => {
    try {
        const projectName = req.body.projectName;
        console.log(`API view being called: ${req.path}`);
        const tempArr = req.path.split('/');
        const viewClass = tempArr[tempArr.length-1];
        console.log(`API view being called: ${viewClass}`);
        const queryConditions = {
            '$or': [
                { 'settingName': "ApisAllowedRoles" },
                { 'settingName': "userIdWithRoles" }
            ]
        };
        let mongoDBManagerObj = new MongoDBManager(mongoConfig[projectName]['databaseName']);
        const rolesInfoArr = await mongoDBManagerObj.findDocuments(mongoConfig[projectName].apiSettings, queryConditions, {});
        let apisAllowedRoles = {};
        let userIdWithRoles = {};
        for (const record of rolesInfoArr) {
            if (record.settingName === 'ApisAllowedRoles') {
                apisAllowedRoles = record[projectName][viewClass] || {};
            } else if (record.settingName === 'userIdWithRoles') {
                userIdWithRoles = record[projectName][tokenInfo.userName] || {};
            }
        }
        return Object.keys(apisAllowedRoles).some(role => userIdWithRoles[role]);
    } catch (err) {
        console.error('Exception in middleware', err);
        message_error = { error: err.message, 'success': false, message: 'middleware error' };
        logError({ ...message_error });
        return false;
    }
};
const isVerified = async(req, tokenInfo) => {
    try {
        const projectName = req.body.projectName;
        console.log(`API view being called: ${req.path}`);
        const queryConditions = {
           'userName': tokenInfo.userName,
        };
        let mongoDBManagerObj = new MongoDBManager(mongoConfig[projectName]['databaseName']);
        const userEmailVefData = await mongoDBManagerObj.findDocuments(mongoConfig[projectName].userCol, queryConditions, {emailVefData:1,'_id':0});
        return userEmailVefData[0].emailVefData.verified == true;
    } catch (err) {
        console.error('Exception in middleware', err);
        message_error = { error: err.message, 'success': false, message: 'middleware error' };
        logError({ ...message_error });
        return false;
    }
};



module.exports = APIMiddleware;
