const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const ChatUser = require("../models/User");
const dotenv = require("dotenv");
dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET;

router.post("/register", async (req, res)=>{
    const {username, password} = req.body;
    try {
        const existingUser = await ChatUser.findOne({username});
        if(existingUser){
            return res.status(400).json({message: "User is already exists. Please login"});
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new ChatUser({username, password: hashedPassword});
        await newUser.save();

        const token = jwt.sign({id: newUser._id}, JWT_SECRET, {expiresIn: "4h"});
        return res.status(201).json({message: "User Registerd", token, username});
    } catch (error) {
        return res.status(500).json({message: "Server Error", error});
    }
});
router.post("/login", async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await ChatUser.findOne({ username });
        if (!user) return res.status(404).json({ message: "User not found." });

        const isPasswordMatch = await user.comparePassword(password);
        if (!isPasswordMatch)
            return res.status(400).json({ message: "Invalid Credentials" });

        res.status(200)
           .json({ message: "Login successful", username: user.username });
    } catch (error) {
        return res.status(500).json({message: "Server Error", error});
    }
});
module.exports = router;