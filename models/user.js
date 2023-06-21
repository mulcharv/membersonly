const mongoose = require("mongoose");

const Schema = mongoose.Schema;

const UserSchema = new Schema({
    first_name: { type: String, required: true, maxLength: 50},
    last_name: { type: String, required: true, maxLength: 50},
    username: { type: String, required: true, maxLength: 50},
    password: { type: String, required: true, maxLength: 100},
    profile_image: { type: Buffer, required: true, contentType: String},
    membership_status: { type: Boolean},
    admin_status: { type: Boolean}
});

UserSchema.virtual("full_name").get(function () {
    fullname = `${this.first_name} ${this.last_name}`;
    return fullname;
});

module.exports = mongoose.model("User", UserSchema);


