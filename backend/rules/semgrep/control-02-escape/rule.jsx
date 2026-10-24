// Control 2 (inventario v1.0): escape de caracteres especiales por intérprete

// Caso que debe detectar: HTML crudo sin sanitizar
function Bio({ html }) {
  // ruleid: js-react-raw-html-ctl2
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

// Caso seguro: sanitización con DOMPurify
function BioSafe({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}

// Caso que debe detectar: consulta SQL con template literal
// ruleid: js-sql-template-ctl2
db.query(`SELECT * FROM users WHERE email = '${email}'`);

// Caso seguro: consultas parametrizadas
db.query("SELECT * FROM users WHERE email = ?", [email]);

// Caso que debe detectar: bypass de sanitización de Angular
// ruleid: js-angular-bypass-trust-ctl2
this.sanitizer.bypassSecurityTrustHtml(userInput);

// Caso seguro (Vue escapa texto por defecto): {{ comentarioUsuario }}

