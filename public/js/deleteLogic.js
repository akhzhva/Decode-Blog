function deleteBlog(id, authorID) {
  axios.delete(`/api/post/${id}`).then((data) => {
    if (data.status == 200) {
      location.replace(`/myblogs/${authorID}`);
    } else if (data.status == 404) {
      location.replace("/not_found");
    }
  });
}

function deleteUser(id) {
  axios.delete(`/api/user_delete/${id}`).then((data) => {
    if (data.status == 200) {
      location.replace(`/auth`);
    } else if (data.status == 404) {
      location.replace(`/edit_profile/${id}`);
    }
  });
}
