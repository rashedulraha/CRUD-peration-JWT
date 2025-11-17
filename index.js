import express from "express";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import mongodb, { MongoClient, ObjectId } from "mongodb";

dotenv.config();

const app = express();
app.use(express.json());
const port = process.env.PROT || 3000;
const client = new MongoClient(process.env.DATA_BASE_URL);

//! MiddleWare
const verifyJwtToken = (req, res, next) => {
  const token = req.headers.authorization || undefined;

  if (token) {
    return res.status(403).json({
      message: "unauthorize",
    });
  }

  jwt.verify(token, "fdfsdfjdklfjdjfdj", (error, decodedData) => {
    if (error) {
      return res.status(409).json({
        message: "You are not authorize",
      });
    }
    req.user = decodedData;
    next();
  });
};

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

    //!  get profile data

    app.get("/me", verifyJwtToken, async (req, res) => {
      try {
        const user = req.user;

        const userData = await userCollection.findOne(
          {
            _id: new ObjectId(user._id),
          },
          {
            projection: { password: 0 },
          }
        );

        res.status(200).json(userData);
      } catch (error) {
        res.status(400).json({
          message: "Filed to fetch profile data",
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
