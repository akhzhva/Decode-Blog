const mongoose = require("mongoose");

const BlogSchema = new mongoose.Schema({
  title: String,
  category: { type: mongoose.Schema.Types.ObjectId, ref: "category" },
  description: String,
  date: String,
  Image: String,
  user: { type: mongoose.Schema.Types.ObjectId, ref: "user" },
});

module.exports = mongoose.model("blog", BlogSchema);
