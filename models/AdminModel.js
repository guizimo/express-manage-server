var mongoose = require("mongoose");
var AdminSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    phone: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    roleId: {
        type: String,
        required: false
    },
    status: {
        type: Boolean,
        required: true,
        default: 1
    }
}, {
    timestamps: true
});

module.exports = mongoose.model("Admin", AdminSchema);