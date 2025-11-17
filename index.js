import express from "express";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import mongodb, { MongoClient } from "mongodb";

dotenv.config();

const app = express();
app.use(express.json());
const port = process.env.PROT || 3000;
const client = new MongoClient(process.env.DATA_BASE_URL);

async function run() {
  // database connection

  try {
    await client.connect();
    // console.log("database connection");
    const db = client.db("crud-operation");
    const userCollection = db.collection("users");

    //!  register
    app.post("/register", async (req, res) => {
      try {
        const { name, email, password } = req.body;

        const existed = await userCollection.findOne({
          email: email,
        });

        if (existed) {
          return res.status(409).json({
            message: "user already exist",
          });
        }

        const passwordHashed = await bcrypt.hash(password, 10);

        const result = await userCollection.insertOne({
          name,
          email,
          password: passwordHashed,
        });
        res.status(201).json({
          message: "user create successfully",
          result,
        });
      } catch (error) {
        res.status(409).json({
          message: "field to create user",
        });
      }
    });

    //! login

    app.post("/login", async (req, res) => {
      try {
        const { email, password } = req.body;
        // console.log(email, password);

        //  find email to get match data
        const user = await userCollection.findOne({ email });

        const isMatchPassword = await bcrypt.compare(password, user.password);

        if (!isMatchPassword) {
          return res.status(400).json({ message: "password incorrect" });
        }

        //  generate  a toke using jwt

        const token = jwt.sign(
          {
            email: user.email,
            _id: user._id,
          },
          "fdfsdfjdklfjdjfdj",
          {
            expiresIn: "3h",
          }
        );

        res.status(200).json({
          message: "logged successfully!",
          token,
        });
      } catch (error) {
        res.status(400).json({
          message: "login field please check your email and password",
        });
      }
    });
  } catch (error) {
    console.log(error);
  }
}

run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
