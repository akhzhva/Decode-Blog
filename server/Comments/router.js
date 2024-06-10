const express = require("express");
const router = express.Router();
const { saveComment, deleteComment } = require("./controller");
const { isAuth } = require("../auth/middlewares");

router.post("/api/comment", isAuth, saveComment);
router.delete("/api/comment/:id", isAuth, deleteComment);

module.exports = router;
