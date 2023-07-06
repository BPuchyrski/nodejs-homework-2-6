const express = require("express");
const router = express.Router();
const Joi = require("joi");
const bcrypt = require("bcryptjs");
const User = require("../../models/users");
const authenticateToken = require("../../token.auth");
const jwt = require("jsonwebtoken");
const gravatar = require("gravatar");
const jimp = require("jimp");
// const fs = require("fs").promises;
const path = require("path");
const multer = require("multer");
const { v4: uuidv4 } = require("uuid");
const nodemailer = require("nodemailer");

const userValidationSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
});

const tmpDir = path.join(process.cwd(), "tmp");
const avatarDir = path.join(process.cwd(), "public", "avatars");

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, tmpDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + "-" + Math.round(Math.random() * 1e9) + ext);
  },
});

const upload = multer({ storage });

router.post("/signup", async (req, res) => {
  try {
    const { error } = userValidationSchema.validate(req.body);
    if (error) {
      res.status(400).json({ message: error.message });
      return;
    }

    const existingUser = await User.findOne({ email: req.body.email });
    if (existingUser) {
      res.status(409).json({ message: "Email in use" });
      return;
    }
    const avatar = gravatar.url(req.body.email, {
      s: "200",
      r: "pg",
      d: "identicon",
    });
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(req.body.password, salt);
    const newUser = await User.create({
      email: req.body.email,
      password: hashedPassword,
      avatarURL: avatar,
      verify: false,
      verificationToken: uuidv4(),
    });
    const transporter = nodemailer.createTransport({
      service: "outlook",
      secure: false,
      auth: {
        user: "goithomework098123@outlook.com",
        pass: "fggrfgr34324@@#$%$^%&FFGHF",
      },
    });

    const html = `<a href="http://localhost:4000/users/verify/${newUser.verificationToken}">Confirm email</a>`;

    const emailOptions = {
      from: "goithomework098123@outlook.com",
      to: newUser.email,
      subject: "Verify email",
      html,
    };

    res.status(201).json({
      user: {
        email: newUser.email,
        subscription: newUser.subscription,
      },
    });

    await transporter.sendMail(emailOptions);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
router.post("/login", async (req, res) => {
  try {
    const { error } = userValidationSchema.validate(req.body);
    if (error) {
      res.status(400).json({ message: error.message });
      return;
    }

    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      res.status(401).json({ message: "Email or password is wrong" });
      return;
    }

    const isVerified = user.verify;
    if (!isVerified) {
      res.status(401).json({ message: "Email is not verified" });
      return;
    }

    const passwordMatch = await bcrypt.compare(
      req.body.password,
      user.password
    );
    if (!passwordMatch) {
      res.status(401).json({ message: "Email or password is wrong" });
      return;
    }

    const token = jwt.sign({ userId: user._id }, "secret", {
      expiresIn: "1h",
    });
    user.token = token;
    await user.save();

    res.status(200).json({
      token: user.token,
      user: {
        email: user.email,
        subscription: user.subscription,
      },
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.get("/logout", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      res.status(401).json({ message: "Not authorized" });
      return;
    }
    res.json({ message: "Log out" });
    res.status(204);
    user.token = null;
    await user.save();
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
router.get("/current", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user._id);

    if (!user) {
      res.status(401).json({ message: "Not authorized" });
      return;
    }

    res.status(200).json({
      email: user.email,
      subscription: user.subscription,
      avatarURL: user.avatarURL,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
router.patch(
  "/avatars",
  authenticateToken,
  upload.single("avatar"),
  async (req, res) => {
    console.log(req.file);
    try {
      if (!req.file) {
        return res.status(400).json({ message: "File not provided" });
      }

      const img = await jimp.read(req.file.path);
      await img
        .autocrop()
        .cover(
          250,
          250,
          jimp.HORIZONTAL_ALIGN_CENTER | jimp.VERTICAL_ALIGN_MIDDLE
        )
        .writeAsync(req.file.path);

      const user = await User.findById(req.user._id);

      if (!user) {
        return res.status(401).json({ message: "Not authorized" });
      }

      user.avatarURL = `/avatars/${req.file.filename}`;
      await user.save();

      res.status(200).json({ avatarURL: user.avatarURL });

      await img.writeAsync(path.join(avatarDir, req.file.filename));
    } catch (err) {
      res.status(500).json({ message: err.message });
    }
  }
);
router.get("/verify/:verificationToken", async (req, res) => {
  try {
    const user = await User.findOne({
      verificationToken: req.params.verificationToken,
    });

    if (user.verify) {
      return res
        .status(400)
        .json({ message: "Verification has already been passed" });
    }

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    if (user.verificationToken === req.params.verificationToken) {
      user.verify = true;
      await user.save();
      return res.status(200).json({ message: "Verification successful" });
    }
    return res.status(404).json({ message: "User not found" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
router.post("/verify", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ message: "Missing required field email" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.verify) {
      return res
        .status(400)
        .json({ message: "Verification has already been passed" });
    }

    const transporter = nodemailer.createTransport({
      service: "outlook",
      secure: false,
      auth: {
        user: "goithomework098123@outlook.com",
        pass: "fggrfgr34324@@#$%$^%&FFGHF",
      },
    });

    const html = `<p>Click on the link below to verify your account</p>
      <a href='http://localhost:4000/users/verify/${user.verificationToken}' target='_blank'>VERIFY</a>`;

    const emailOptions = {
      from: "goithomework098123@outlook.com",
      to: email,
      subject: "Verification ✔",
      text: "Mail with verification link",
      html,
    };

    await transporter.sendMail(emailOptions);
    res.status(200).json({ message: "Verification email sent" });
  } catch (error) {
    return res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
