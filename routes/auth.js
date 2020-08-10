const express = require("express");
const {
	register,
	login,
	getMe,
	forgotPassword,
	resetPassword,
	updateDetails,
	profilePhotoUpload,
	updatePassword,
	logout,
} = require("../controllers/auth");

const router = express.Router();

const { protect } = require("../middelware/auth");

router.post("/register", register);
router.post("/login", login);
router.get("/logout", logout);
router.get("/me", protect, getMe);
router.put("/updatedetails", protect, updateDetails);
router.put("/:id/photo", protect, profilePhotoUpload);
router.put("/updatepassword", protect, updatePassword);
router.post("/forgotpassword", forgotPassword);
router.put("/resetpassword/:resttoken", resetPassword);

module.exports = router;
