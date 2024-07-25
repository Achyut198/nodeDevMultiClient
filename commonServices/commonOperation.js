const fs = require("fs");
const jwt = require("jsonwebtoken");
const { promisify } = require("util");
const { response } = require("express");
const { DateTime } = require("luxon");

const Joi = require("joi");
// Generate a secret key
const key = "QHlPYy2x4kPbWThoF63YXs9x345EmfgjQK7nsvfC2H0=";
const winston = require("winston");
const crypto = require("crypto");
const { Console } = require("winston/lib/winston/transports");
const nodemailer = require("nodemailer");
const { STATUS_CODES } = require("http");
const readFromEncryptedFile = false;
const encryptJsonFile = (filename, key) => {
    try {
        const data = fs.readFileSync(filename, "utf8");
        const cipher = crypto.createCipher("aes-256-cbc", key);
        let encryptedData = cipher.update(data, "utf8", "hex");
        encryptedData += cipher.final("hex");
        fs.writeFileSync(filename + ".enc", encryptedData);
    } catch (err) {
        console.error("Error in reading/writing encryptJsonFile file", err);
    }
};

const decryptJsonFile = (filename, key) => {
    try {
        const encryptedData = fs.readFileSync(filename, "utf8");
        const decipher = crypto.createDecipher("aes-256-cbc", key);
        let decryptedData = decipher.update(encryptedData, "hex", "utf8");
        decryptedData += decipher.final("utf8");
        return JSON.parse(decryptedData);
    } catch (err) {
        console.error("Error in reading decryptJsonFile file", err);
        return {};
    }
};

filename = "public/applicationConfig/mongoConfig.json";
filesNameArray = ["mongoConfig", "otherFeaturesConfigs", "apiRequirements"];
// Encrypt the JSON file
filesNameArray.forEach((element) => {
    encryptJsonFile("public/applicationConfig/" + element + ".json", key);
});

// Decrypt the encrypted JSON file
// decryptJsonFile(filename + '.enc', key)
//     .then(data => console.log("Decrypted data:", data))
//     .catch(error => console.error("Decryption error:", error));

const readJsonFiles = (filePath, readEncryptFile = readFromEncryptedFile) => {
    try {
        if (readEncryptFile) {
            return decryptJsonFile(filePath + ".enc", key);
        } else {
            const data = fs.readFileSync(filePath, "utf8");
            return JSON.parse(data);
        }
    } catch (err) {
        console.error("error in reading json readJsonFiles file-->", err);
        return {};
    }
};

// Read JSON files
const otherConfig = readJsonFiles(
    "./public/applicationConfig/otherFeaturesConfigs.json"
);
const mongoConfig = readJsonFiles("./public/applicationConfig/mongoConfig.json");

// Validate length
const validateLength = (data, minLen, maxLen) => {
    try {
        const minLength = data.length;
        minLen = parseInt(minLen);
        maxLen = parseInt(maxLen);
        return minLength >= minLen && minLength <= maxLen;
    } catch (error) {
        return false;
    }
};

// Validate pattern
const validatePattern = (data, pattern) => {
    try {
        if (pattern === "") return true;
        const regex = new RegExp(pattern);
        return regex.test(data);
    } catch (error) {
        return false;
    }
};

// Intersection of arrays
const intersection = (arr1, arr2) => {
    const set1 = new Set(arr1);
    const set2 = new Set(arr2);
    const intersectionSet = new Set([...set1].filter((x) => set2.has(x)));
    return [...intersectionSet];
};

// Send email
let emailAuth = (
    smtpServer = otherConfig["emailConfig"].smtp_server,
    smtpPort = otherConfig["emailConfig"].smtp_port,
    senderEmail = otherConfig["emailConfig"].sender_email,
    senderPassword = otherConfig["emailConfig"].sender_password
) => {
    try {
        let transporter = nodemailer.createTransport({
            host: smtpServer,
            port: smtpPort,
            secure: false, // true for 465, false for other ports
            auth: {
                user: senderEmail,
                pass: senderPassword,
            },
        });
        return transporter;
    } catch (error) {
        console.error("Error in creating transporter object:", error);
        return null;
    }
};
let transporterObj = emailAuth();
async function sendEmail(
    subject,
    body,
    toEmail,
    projectName,
    retryId = 0,
    transporter = transporterObj,
    senderEmail = otherConfig["emailConfig"].sender_email
) {
    try {
        // Create a SMTP transporter object

        // Send mail with defined transport object
        let info = await transporter.sendMail({
            from: senderEmail,
            to: toEmail,
            subject: subject,
            html: body,
        });
        let mongoDBManagerObj;
        // setTimeout(() => {
        const MongoDBManager = require("./mongoServices");
        mongoDBManagerObj = new MongoDBManager(
            mongoConfig[projectName]["databaseName"]
        );
        // }, 500);
        if (retryId != 0) {
            mongoDBManagerObj.deleteDocument(
                otherConfig["emailConfig"]["retryMailCol"],
                { toEmail: toEmail, subject: subject, body: body }
            );
        }

        console.log("Message sent: %s", info.messageId);
        return true;
    } catch (error) {
        console.error("\nretryId :", retryId, "\n\nError in sending email:", error);
        if (retryId == 0) {
            // existing_data = mongoDBManagerObj.findDocuments(otherConfig["emailConfig"]['retryMailCol'], { '_id': retryId })
            // if (existing_data.length > 0) {
            //     console.log('Data already present. Skipping insertion.')
            // }
            // else {

            let mongoDBManagerObj;
            const MongoDBManager = require("./mongoServices");
            mongoDBManagerObj = new MongoDBManager(
                mongoConfig[projectName]["databaseName"]
            );
            retryObj = {
                subject: subject,
                body: body,
                toEmail: toEmail,
                timestamp: DateTime.now(),
            };
            mongoDBManagerObj.insertDocument(
                otherConfig["emailConfig"]["retryMailCol"],
                retryObj
            );
            // }
        } else {
            console.log("-----will retry to send mail in next attempt ----");
        }
        return false;
    }
}

// Generate tokens
const generateTokens = (
    payload,
    secretKey,
    accessExpirationDelta,
    refreshExpirationDelta
) => {
    const access_token_exp =
        Math.floor(Date.now() / 1000) + accessExpirationDelta;
    const refresh_token_exp =
        Math.floor(Date.now() / 1000) + refreshExpirationDelta;

    const access_token_payload = {
        ...payload,
        exp: access_token_exp,
        iat: Math.floor(Date.now() / 1000),
    };
    const access_token = jwt.sign(access_token_payload, secretKey);

    const refresh_token_payload = {
        ...payload,
        exp: refresh_token_exp,
        iat: Math.floor(Date.now() / 1000),
    };
    const refresh_token = jwt.sign(refresh_token_payload, secretKey);
    console.log("refresh_token--->", refresh_token);
    const refresh_token_data = jwt.verify(refresh_token, secretKey);
    console.log("refresh_token_data--", refresh_token_data);

    return { access_token, refresh_token };
};

// Get new access token
const getNewAccessToken = (refresh_token, secretKey, accessExpirationDelta) => {
    try {
        const refresh_token_data = jwt.verify(refresh_token, secretKey);
        console.log("refresh_token_data", refresh_token_data);
        // Check if the refresh token has payload and expiration time
        if (refresh_token_data && refresh_token_data.exp && refresh_token_data) {
            const payload = refresh_token_data;
            // Create a new access token with an updated expiration time
            const new_access_token = jwt.sign(
                {
                    ...payload,
                    exp: Math.floor(Date.now() / 1000) + accessExpirationDelta,
                    iat: Math.floor(Date.now() / 1000),
                },
                secretKey
            );

            return new_access_token;
        } else {
            // Handle invalid or missing payload in the refresh token
            console.error("Invalid or missing payload in the refresh token");
            return null;
        }
    } catch (error) {
        // Handle JWT verification errors
        console.error(`Error: ${error.message}`);
        return null;
    }
};

// Validate access token
const validateAccessToken = (access_token, secretKey) => {
    try {
        console.log("Validating access token...", access_token, secretKey);
        const decoded_token = jwt.verify(access_token, secretKey);
        const exp_datetime = new Date(decoded_token.exp * 1000);
        if (exp_datetime < Date.now()) {
            throw new Error("Token has expired");
        }
        return decoded_token;
    } catch (error) {
        console.error(`Error: ${error.message}`);
        return null;
    }
};

// Logging functions
const current_date = new Date().toISOString().slice(0, 10);

const setupLogger = (log_level, log_filename) => {
    const logger = winston.createLogger({
        level: log_level,
        transports: [new winston.transports.File({ filename: log_filename })],
    });
    return logger;
};

const logWarning = (message_info) => {
    try {
        const project_name = message_info.projectName || "other";
        const log_filename = `logs/${project_name}/${current_date}_warning.log`;
        const logger = setupLogger("warning", log_filename);
        logger.warning(message_info);
    } catch (err) {
        console.error(`error in logging warning--> ${err.message}`);
    }
};

const logError = (message_info) => {
    try {
        const project_name = message_info.projectName || "other";
        const log_filename = `logs/${project_name}/${current_date}_error.log`;
        const logger = setupLogger("error", log_filename);
        logger.error(message_info);
    } catch (err) {
        console.error(`error in logging error--> ${err.message}`);
    }
};

const logInfo = (message_info) => {
    try {
        const project_name = message_info.projectName || "other";
        const log_filename = `logs/${project_name}/${current_date}_info.log`;
        const logger = setupLogger("info", log_filename);
        logger.info(message_info);
    } catch (err) {
        console.error(`error in logging info --> ${err.message}`);
    }
};

const requestDataInjectionCheck = (fields, fieldsConfig, requestBody) => {
    // try {
    const userData = {};
    let ErrorArr = [];
    for (const field of fields) {
        // console.log('fieldsConfig[field]',field, fieldsConfig[field]);
        let { minLength, maxLength, pattern, dataType, required } =
            fieldsConfig[field];
        console.log(minLength, maxLength, pattern, dataType);
        minLength = minLength ? Number(minLength) : 0;
        maxLength = maxLength ? Number(maxLength) : 1000;
        console.log("minLength", minLength, maxLength);
        let fieldSchema;
        dataType = dataType || "";
        switch (dataType) {
            case "number":
                fieldSchema = Joi.number()
                    .min(minLength || -Infinity)
                    .max(maxLength || Infinity);
                break;
            case "boolean":
                fieldSchema = Joi.boolean();
                break;
            case "date":
                fieldSchema = Joi.date();
                break;
            case "array":
                fieldSchema = Joi.array().items(Joi.any()); // You may want to specify the types of items within the array
                break;
            case "object":
                fieldSchema = Joi.object();
                break;
            case "string":
            case "":
                fieldSchema = Joi.string()
                    .min(minLength)
                    .max(maxLength)
                    .pattern(new RegExp(pattern || ".*"));
                break;
            case "object":
                fieldSchema = Joi.object();
                break;
            default:
                throw new Error(
                    `Unsupported data type for field ${field}: ${dataType}`
                );
        }
        if (required) {
            fieldSchema = fieldSchema.required();
        }

        const { error, value } = fieldSchema.validate(requestBody[field], {
            abortEarly: false,
        });
        // console.log('joi error----->', error,'joi value----->',value);
        if (error) {
            ErrorArr.push({
                field: field,
                message: error.details[0].message,
            });
            // console.log('joi error----->', error.details[0].message);
            // return response(message_error,STATUS_CODES.BAD_REQUEST);
        }

        userData[field] = value;
    }
    if (ErrorArr.length > 0) {
        return { error: ErrorArr };
    }
    return userData;
    // } catch (err) {
    //     console.error(`Error: ${err.message}`);
    //     return {};
    // }
};

module.exports = {
    encryptJsonFile,
    decryptJsonFile,
    readJsonFiles,
    validateLength,
    validatePattern,
    intersection,
    sendEmail,
    generateTokens,
    getNewAccessToken,
    validateAccessToken,
    logWarning,
    logError,
    logInfo,
    requestDataInjectionCheck,
};
