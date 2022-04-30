const express = require('express');
const authController = require('../controllers/auth');
const {check, body} = require('express-validator')
const User = require("../models/user");

const router = express.Router();
router.get('/login', authController.getLogin);
router.get('/signup', authController.getSignup);
router.get('/reset', authController.getReset);
router.get('/reset/:token', authController.getNewPassword);

router.post('/login', authController.postLogin);
router.post('/signup',
    [
        check('email')
            .isEmail()
            .withMessage('Please Enter a Valid Email!')
            .custom((value, {req}) => {
                //! As this Custom Validator must return a Value
                //? then before logic here we have to write return
                return User.findOne({email: value})
                    .then((userData) => {
                        if (userData) {
                            return Promise.reject('E-mail already in use');
                        }
                    })
            })
            .normalizeEmail(),
        body('password','Minimum Length for Password is 3 Characters')
            .isLength({min: 3})
            .trim()
        ,
        body('confirmPassword')
            .trim()
            .custom((value, {req}) => {
                if (value !== req.body.password) {
                    throw new Error('Password Must Match!');
                }
                //! Indicates the success of this synchronous custom validator
                //! As this Custom Validator must return a Value
                return true;
            })
    ],
    authController.postSignup
)
router.post('/logout', authController.postLogout);
router.post('/reset', authController.postReset);
router.post('/new-password', authController.postNewPassword);


module.exports = router;