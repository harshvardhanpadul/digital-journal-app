import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;


const db = new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT
});

db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

function checkAuth(req, res, next) {
  if (req.session.userId) {
    next();
  } else {
    res.redirect("/login");
  }
}

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
);

app.set("view engine", "ejs");

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  const hash = await bcrypt.hash(password, saltRounds);

  try {
    await db.query(
      "INSERT INTO users(email,password) VALUES($1,$2)",
      [email, hash]
    );

    res.redirect("/login");
  } catch {
    res.redirect("/register");
  }
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const result = await db.query(
    "SELECT * FROM users WHERE email=$1",
    [email]
  );

  if (result.rows.length > 0) {
    const user = result.rows[0];

    const valid = await bcrypt.compare(password, user.password);

    if (valid) {
      req.session.userId = user.id;
      res.redirect("/dashboard");
    } else {
      res.redirect("/login");
    }
  } else {
    res.redirect("/login");
  }
});


app.get("/dashboard",checkAuth, async (req, res) => {
  if (!req.session.userId) {
    return res.redirect("/login");
  }

  const result = await db.query(
    "SELECT * FROM entries WHERE user_id=$1 ORDER BY created_at DESC",
    [req.session.userId]
  );

  res.render("dashboard", {
    entries: result.rows
  });
});

app.get("/edit/:id",checkAuth, async (req, res) => {

  const result = await db.query(
    "SELECT * FROM entries WHERE id=$1",
    [req.params.id]
  );

  res.render("edit", {
    entry: result.rows[0]
  });

});
app.get("/new", (req, res) => {
  res.render("new");
});

app.post("/new",checkAuth, async (req, res) => {
  await db.query(
    "INSERT INTO entries(title,content,user_id) VALUES($1,$2,$3)",
    [
      req.body.title,
      req.body.content,
      req.session.userId
    ]
  );

  res.redirect("/dashboard");
});

app.post("/edit/:id", async (req, res) => {

  await db.query(
    "UPDATE entries SET title=$1, content=$2 WHERE id=$3",
    [
      req.body.title,
      req.body.content,
      req.params.id
    ]
  );

  res.redirect("/dashboard");

});

app.get("/delete/:id",checkAuth, async (req, res) => {
  await db.query(
    "DELETE FROM entries WHERE id=$1",
    [req.params.id]
  );

  res.redirect("/dashboard");
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});