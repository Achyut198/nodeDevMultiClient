const express = require('express');
const router = express.Router();
const customMiddleware = require('../middlewares/customMidddleware');
// const auth=require('../middleware/auth');

const userController = require('../controller/auth/userApi');
router.post('/registerUser', customMiddleware, userController.registerUser);
router.get('/forGotPasswordOnUserId', customMiddleware, userController.forgotPasswordOnUserId);
router.post('/loginUser', customMiddleware, userController.loginUser);
router.get('/getNewAcessToken', customMiddleware, userController.getNewAcessToken);
router.post('/passWordResetVerification', customMiddleware, userController.passWordResetVerification);
router.post('/Auth/emailVerifyUser', customMiddleware, userController.emailVerifyUser);
router.post('/Auth/vfUser/updateUserEmail', customMiddleware, userController.updateUserEmail);
router.post('/Auth/vfUser/updateUserBasicData', customMiddleware, userController.updateUserBasicData);
router.post('/Auth/roleAccess/AssignRoleToUser', customMiddleware, userController.AssignRoleToUser);
// router.post('/login',userController.login);
// router.post('/updateUser/:id',auth,userController.updateUser)

module.exports = router;