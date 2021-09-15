const AdminModel = require("../models/AdminModel");
const { body, validationResult } = require("express-validator");
const { sanitizeBody } = require("express-validator");


//helper file to prepare responses.
const apiResponse = require("../helpers/apiResponse");
const bcryptjs = require("bcryptjs");


/**
 * User registration.
 * 注册接口
 *
 * @param {string}      firstName
 * @param {string}      lastName
 * @param {string}      email
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
            console.log(req.body)
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
