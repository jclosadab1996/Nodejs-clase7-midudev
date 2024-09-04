import crypto from "node:crypto";

import DBLocal from "db-local";
import bcrypt from "bcrypt";
import { SALT_ROUNDS } from "./config.js";

const { Schema } = new DBLocal({ path: "./db" });

const User = Schema("User", {
  _id: { type: String, required: true },
  username: { type: String, required: true },
  password: { type: String, required: true },
});
export class UserRepository {
  static async create({ username, password }) {
    // 1. Validaciones de username (opcional: usar zod)
    Validations.username(username);
    Validations.password(password);

    // 2. ASEGURARSE QUE EL USUARIO NO EXISTE
    const user = User.findOne({ username });
    if (user) throw new Error("Username alredy exists");

    const id = crypto.randomUUID();
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    User.create({
      _id: id,
      username,
      password: hashedPassword,
    }).save();

    return id;
  }

  static async login({ username, password }) {
    // 1. Validaciones de username (opcional: usar zod)
    Validations.username(username);
    Validations.password(password);

    // 2. Buscar el usuario
    const user = User.findOne({ username });
    if (!user) throw new Error("Username does not exist");

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) throw new Error("Password is invalid");

    const { password: _, ...publicUser } = user;

    return publicUser;
  }
}

class Validations {
  static username(username) {
    if (typeof username !== "string")
      throw new Error("username must be a string");
    if (username.length < 3)
      throw new Error("Username must be at least 3 characters long");
  }

  static password(password) {
    if (typeof password !== "string")
      throw new Error("username must be a string");
    if (password.length < 6)
      throw new Error("Username must be at least 6 characters long");
  }
}
