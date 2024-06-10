function checkInput() {
  const text = document.getElementById("comment_text").value;
  const button = document.getElementById("submit-comment");
  button.disabled = !text.trim();
}

function deleteComment(commentId, blogId) {
  axios
    .delete(`/api/comment/${commentId}`)
    .then((data) => {
      if (data.status == 200) {
        location.replace(`/post/${blogId}`);
      }
    })
    .catch((error) => {
      console.error("Ошибка при лении комментария:", error);
    });
}

function sendComment(e) {
  e.preventDefault();
  const comment_text = document.querySelector("#comment_text").value;
  const author = document.querySelector("#comment_author").value;
  const blog = document.querySelector("#comment_blog").value;

  if (comment_text.length > 0) {
    axios
      .post("/api/comment", {
        text: comment_text,
        authorId: author,
        blogId: blog,
      })
      .then((data) => {
        if (data.data) {
          location.reload();
        }
      });
  }
}
