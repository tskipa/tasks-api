import fs from "fs";
import { json, urlencoded } from "body-parser";
import { create, defaults, router } from "json-server";
import jwt from "jsonwebtoken";

interface User {
  name: string;
  email: string;
  password?: string;
  role: string;
}

const server = create();
const mainRouter = router("db.json");
const userdb = JSON.parse(
  fs.readFileSync("./users.json", { encoding: "utf-8" })
);

server.use(defaults());
server.use(urlencoded({ extended: true }));
server.use(json());

const SECRET_KEY = "123456789";
const expiresIn = "1h";

function createToken(payload: Partial<User>) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn });
}

function verifyToken(token: string) {
  return jwt.verify(token, SECRET_KEY, (err, decode) =>
    decode !== undefined ? decode : err
  );
}

function isAuthenticated({ email, password }) {
  return (
    userdb.users.findIndex(
      (user: Partial<User>) =>
        user.email === email && user.password === password
    ) !== -1
  );
}

server.post("/api/auth/register", (req, res) => {
  console.log("register endpoint called; request body:");
  console.log(req.body);
  const { email, password } = req.body;

  if (isAuthenticated({ email, password }) === true) {
    const status = 401;
    const message = "Email and Password already exist";
    res.status(status).json({ status, message });
    return;
  }

  fs.readFile("./users.json", (err, payload) => {
    if (err) {
      const status = 401;
      const message = err;
      res.status(status).json({ status, message });
      return;
    }

    let data = JSON.parse(payload.toString());
    let lastItemId = data.users[data.users.length - 1].id;

    data.users.push({ id: lastItemId + 1, email: email, password: password });

    fs.writeFile("./users.json", JSON.stringify(data), (err) => {
      if (err) {
        const status = 401;
        const message = err;
        res.status(status).json({ status, message });
        return;
      }
    });
  });
  const access_token = createToken({ email, password });
  console.log("Access Token:" + access_token);
  res.status(200).json({ access_token });
});

server.post("/api/auth/login", (req, res) => {
  console.log("login endpoint called; request body:");
  console.log(req.body);
  const { email, password } = req.body;
  if (isAuthenticated({ email, password }) === false) {
    const status = 401;
    const message = "Incorrect email or password";
    res.status(status).json({ status, message });
    return;
  }
  const access_token = createToken({ email, password });
  console.log("Access Token:" + access_token);
  res.status(200).json({ access_token });
});

server.use(/^(?!\/auth).*$/, (req, res, next) => {
  if (
    req.headers.authorization === undefined ||
    req.headers.authorization.split(" ")[0] !== "Bearer"
  ) {
    const status = 401;
    const message = "Error in authorization format";
    res.status(status).json({ status, message });
    return;
  }
  try {
    let verifyTokenResult: any;
    verifyTokenResult = verifyToken(req.headers.authorization.split(" ")[1]);
    if (verifyTokenResult instanceof Error) {
      const status = 401;
      const message = "Access token not provided";
      res.status(status).json({ status, message });
      return;
    }
    next();
  } catch (err) {
    const status = 401;
    const message = "Error access_token is revoked";
    res.status(status).json({ status, message });
  }
});

server.get("/api/verifyUser", (_req, res) => {
  console.log("Cheking if token is valid");
  res.status(200).json(true);
});

server.use("/api", mainRouter);

server.listen(3000, () => {
  console.log("Runing Server on Port 3000");
});
