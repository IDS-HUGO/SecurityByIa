function guardarSesion(token) {
  localStorage.setItem("auth_token", token);
}

function guardarPreferencia() {
  localStorage.setItem("theme", "dark");
}
