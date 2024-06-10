const mongoose = require("mongoose");

const CommentSchema = new mongoose.Schema({
  comment: String,
  data: {
    type: Date,
    default: Date.now(),
  },
  authorID: { type: mongoose.Schema.Types.ObjectId, ref: "user" },
  blogID: { type: mongoose.Schema.Types.ObjectId, ref: "blog" },
});

module.exports = mongoose.model("Comment", CommentSchema);
