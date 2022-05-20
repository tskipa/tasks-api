import { promises } from "fs";
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
const dbRouter = router("db.json");

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

async function getUser({ email, password }) {
  const db = await promises.readFile("users.json");
  const data = JSON.parse(db.toString());
  return data.users.find(
    (user: Partial<User>) => user.email === email && user.password === password
  );
}

async function getUserById({ id }) {
  const db = await promises.readFile("users.json");
  const data = JSON.parse(db.toString());
  return data.users.find((user: Partial<User>) => user.id === id);
}

async function verifyEmail({ email }) {
  const db = await promises.readFile("users.json");
  const data = JSON.parse(db.toString());
  return data.users.find((user: Partial<User>) => user.email === email);
}

function errorResponse(res: any, status: number, message: string) {
  res.status(status).json({ status, message });
}

server.post("/api/auth/register", async (req, res) => {
  const { email, password, ...rest } = req.body;
  delete rest.confirmPassword;
  const user = await verifyEmail({ email });
  if (user) {
    return errorResponse(res, 401, "Email already exists");
  }
  try {
    const db = await promises.readFile("users.json");
    const data = JSON.parse(db.toString());
    const lastItemId = data.users[data.users.length - 1].id;
    const newUser = { id: lastItemId + 1, email, password, ...rest };
    data.users.push(newUser);
    try {
      await promises.writeFile("users.json", JSON.stringify(data));
      const access_token = createToken({ email, password });
      res.status(200).json({ token: access_token, ...newUser, password: null });
    } catch (error) {
      return errorResponse(res, 401, error);
    }
  } catch (error) {
    return errorResponse(res, 401, error);
  }
});

server.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await getUser({ email, password });
  if (!user) {
    return errorResponse(res, 401, "Incorrect email or password");
  }
  const access_token = createToken({ email, password });
  res.status(200).json({ token: access_token, ...user, password: null });
});

server.use(/^(?!\/auth).*$/, (req, res, next) => {
  if (
    req.headers.authorization === undefined ||
    req.headers.authorization.split(" ")[0] !== "Bearer"
  ) {
    return errorResponse(res, 401, "Error in authorization format");
  }
  try {
    const verifyTokenResult = verifyToken(
      req.headers.authorization.split(" ")[1]
    );
    if ((verifyTokenResult as any) instanceof Error) {
      return errorResponse(res, 401, "Access token not provided");
    }
    next();
  } catch (_error) {
    return errorResponse(res, 401, "Access token is revoked");
  }
});

server.post("/api/user", async (req, res) => {
  try {
    const user = await getUserById(req.body);
    if (!user) {
      return errorResponse(res, 404, "User Can't be found");
    }
    res.status(200).json({ ...user, password: null });
  } catch (error) {
    return errorResponse(res, 404, error);
  }
});

server.get("/api/users", async (_req, res) => {
  try {
    const db = await promises.readFile("users.json");
    const data = JSON.parse(db.toString());
    res.status(200).json(data.users);
  } catch (error) {
    return errorResponse(res, 404, error);
  }
});

server.use("/api", dbRouter);

server.listen(3000, () => {
  console.log("Runing Server on Port 3000");
});
