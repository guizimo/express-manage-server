const AdminModel = require("../models/AdminModel");
const { body, validationResult } = require("express-validator");
const { sanitizeBody } = require("express-validator");
const jwt = require("jsonwebtoken")


//helper file to prepare responses.
const apiResponse = require("../helpers/apiResponse");
const bcryptjs = require("bcryptjs");


/**
 * User registration.
 * 注册接口
 *
 * @param {string}      username
 * @param {string}      phone
 * @param {string}      password
 *
 * @returns {Object}
 */
exports.register = [
    // Validate fields.
    body("username").isLength({min: 1}).trim().withMessage("username must be specified.").isAlphanumeric().withMessage("username has non-alphanumeric characters."),
    body("phone").isLength({min: 1}).trim().withMessage("phone must be specified.").isMobilePhone().withMessage("phone must be a valid phone.").custom((value) => {
        return AdminModel.findOne({
            phone: value
        }).then((user) => {
            if (user) {
                return Promise.reject("phone already in use");
            }
        });
    }),
    body("password").isLength({min: 6}).trim().withMessage("Password must be 6 characters or greater."),
    // Sanitize fields.
    sanitizeBody("username").escape(),
    sanitizeBody("phone").escape(),
    sanitizeBody("password").escape(),

    // Process request after validation and sanitization.
    (req, res) => {
        try {
            // Extract the validation errors from a request.
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return apiResponse.validationErrorWithData(res, "Validation Error.", errors.array());
            } else {
                //hash input password
                bcryptjs.hash(req.body.password, 10, function (err, hash) {
                    // Create User object with escaped and trimmed data
                    var user = new AdminModel({
                        username: req.body.username,
                        phone: req.body.phone,
                        password: hash,
                    });
                    // Save user.
                    user.save(function (err) {
                        if (err) {
                            return apiResponse.ErrorResponse(res, err);
                        }
                        let userData = {
                            _id: user._id,
                            username: user.username,
                            phone: user.phone
                        };
                        return apiResponse.successResponseWithData(res, "Registration Success.", userData);
                    });
                });
            }
        } catch (err) {
            //throw error in json response with status 500.
            return apiResponse.ErrorResponse(res, err);
        }
    }
];

/**
 * User login.
 * 登录接口
 * 
 * @param {string}      phone
 * @param {string}      password
 *
 * @returns {Object}
 */
 exports.login = [
	body("phone").isLength({ min: 1 }).trim().withMessage("phone must be specified.")
		.isMobilePhone().withMessage("phone must be a valid phone."),
	body("password").isLength({ min: 1 }).trim().withMessage("Password must be specified."),
	sanitizeBody("phone").escape(),
	sanitizeBody("password").escape(),
	(req, res) => {
		try {
			const errors = validationResult(req);
			if (!errors.isEmpty()) {
				return apiResponse.validationErrorWithData(res, "Validation Error.", errors.array());
			}else {
				AdminModel.findOne({phone : req.body.phone}).then(user => {
					if (user) {
						//Compare given password with db's hash.
						bcryptjs.compare(req.body.password,user.password,function (err,same) {
							if(same){
								//Check account confirmation.
								// Check User's account active or not.
                                if(user.status) {
                                    let userData = {
                                        _id: user._id,
                                        username: user.username,
                                        phone: user.phone,
                                    };
                                    //Prepare JWT token for authentication
                                    const jwtPayload = userData;
                                    const jwtData = {
                                        expiresIn: process.env.JWT_TIMEOUT_DURATION,
                                    };
                                    const secret = process.env.JWT_SECRET;
                                    //Generated JWT token with Payload and secret.
                                    userData.token = jwt.sign(jwtPayload, secret, jwtData);
                                    return apiResponse.successResponseWithData(res,"Login Success.", userData);
                                }else {
                                    return apiResponse.unauthorizedResponse(res, "Account is not active. Please contact admin.");
                                }
							}else{
								return apiResponse.unauthorizedResponse(res, "phone or Password wrong.");
							}
						});
					}else{
						return apiResponse.unauthorizedResponse(res, "phone or Password wrong.");
					}
				});
			}
		} catch (err) {
			return apiResponse.ErrorResponse(res, err);
		}
	}];
