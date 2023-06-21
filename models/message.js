const mongoose = require("mongoose");

const { DateTime } = require("luxon");

const Schema = mongoose.Schema;

const MessageSchema = new Schema({ 
    message_text: { type: String, required: true, maxLength: 240},
    author: { type: Schema.Types.ObjectId, ref: "User", required: true},
}, { timestamps: true });

MessageSchema.virtual("timestamp_formatted").get(function () {
    return DateTime.fromJSDate(this.createdAt).toLocaleString(DateTime.DATE_MED);
});

module.exports = mongoose.model("Message", MessageSchema);

