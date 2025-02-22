const express = require("express");
const router = express.Router();
const userController = require("../Controller/userController");

router.get("/user", userController.getUser);

router.post("/register", userController.saveUser);

router.post("/login", userController.AuthenticateUser);

router.get("/getuserdetails", userController.GetUserDetails);

router.delete("/deleteuser", userController.DeleteUser);

module.exports = router;
