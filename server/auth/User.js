const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  email: String,
  full_name: String,
  password: String,
  googleId: String,
  githubId: String,
  isAdmin: {
    type: Boolean,
    default: false,
  },
  description: String,
});

module.exports = mongoose.model("user", UserSchema);
