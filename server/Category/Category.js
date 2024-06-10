const { name } = require("ejs");
const mongoose = require("mongoose");

const CategorySchema = new mongoose.Schema({
  name: String,
  key: Number,
});

module.exports = mongoose.model("category", CategorySchema);
