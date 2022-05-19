import fs from "fs";
import { json, urlencoded } from "body-parser";
import { create, defaults, router } from "json-server";
import jwt from "jsonwebtoken";

interface User {
  id: number;
  name: string;
  email: string;
  password?: string;
  role: string;
}

const server = create();
const mainRouter = router("db.json");
const db = JSON.parse(fs.readFileSync("db.json", { encoding: "utf-8" }));
console.log(db);

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

function getUser({ email, password }) {
  return db.users.find(
    (user: Partial<User>) => user.email === email && user.password === password
  );
}

server.post("/api/auth/register", (req, res) => {
  const { email, password } = req.body;
  let user = getUser({ email, password });
  if (user) {
    const status = 401;
    const message = "Email and Password already exist";
    res.status(status).json({ status, message });
    return;
  }

  fs.readFile("db.json", (err, payload) => {
    if (err) {
      const status = 401;
      const message = err;
      res.status(status).json({ status, message });
      return;
    }

    const data = JSON.parse(payload.toString());
    const lastItemId = data.users[data.users.length - 1].id;
    const newUser = { id: lastItemId + 1, email: email, password: password };

    data.users.push(newUser);

    fs.writeFile("db.json", JSON.stringify(data), (err) => {
      if (err) {
        const status = 401;
        const message = err;
        res.status(status).json({ status, message });
        return;
      }
    });
    user = newUser;
  });
  const access_token = createToken({ email, password });
  res.status(200).json({ access_token, userId: user.id });
});

server.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body;
  const user = getUser({ email, password });
  if (!user) {
    const status = 401;
    const message = "Incorrect email or password";
    res.status(status).json({ status, message });
    return;
  }
  const access_token = createToken({ email, password });
  res.status(200).json({ access_token, userId: user.id });
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

server.use("/api", mainRouter);

server.listen(3000, () => {
  console.log("Runing Server on Port 3000");
});
