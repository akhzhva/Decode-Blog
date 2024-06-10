const Comment = require("./Comment");

const saveComment = async (req, res) => {
  if (req.body.authorId && req.body.blogId)
    await new Comment({
      comment: req.body.text,
      blogID: req.body.blogId,
      authorID: req.body.authorId,
      date: Date.now(),
    }).save();
  res.status(200).send(true);
};

const deleteComment = async (req, res) => {
  const comment = await Comment.findById(req.params.id);
  if (comment) {
    await Comment.deleteOne({ _id: req.params.id });
    res.status(200).send("ok");
  } else {
    res.status(404).send("Not Found");
  }
};

module.exports = {
  saveComment,
  deleteComment,
};
