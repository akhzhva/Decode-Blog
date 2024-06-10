function redirectToPage(url) {
  window.location.href = url;
}

document.addEventListener("DOMContentLoaded", () => {
  const editButton = document.querySelector(".edit_button_out");
  const editChoice = document.querySelector(".edit-choice");

  editButton.addEventListener("click", (event) => {
    event.stopPropagation();
    editChoice.style.display =
      editChoice.style.display === "flex" ? "none" : "flex";
  });

  document.addEventListener("click", () => {
    if (editChoice.style.display === "flex") {
      editChoice.style.display = "none";
    }
  });

  editChoice.addEventListener("click", (event) => {
    event.stopPropagation();
  });
});


function toggleHeaderModule(event) {
  event.stopPropagation();
  const headerModule = document.querySelector(".header-module");
  if (headerModule.style.display === "flex") {
    headerModule.style.display = "none";
  } else {
    headerModule.style.display = "flex";
  }
}

document.addEventListener("click", function (event) {
  const headerModule = document.querySelector(".header-module");
  const avatar = document.querySelector(".auth-button img");
  if (headerModule.style.display === "flex" && event.target !== avatar) {
    headerModule.style.display = "none";
  }
});

document
  .querySelector(".header-module")
  .addEventListener("click", function (event) {
    event.stopPropagation();
  });

function getCurrentDate() {
  const currentDate = new Date();
  const day = currentDate.getDate().toString().padStart(2, "0");
  const month = (currentDate.getMonth() + 1).toString().padStart(2, "0");
  const year = currentDate.getFullYear();
  return `${day}.${month}.${year}`;
}

