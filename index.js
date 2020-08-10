const path = require("path");
const express = require("express");
const dotenv = require("dotenv");
const morgan = require("morgan");
const colors = require("colors");
const fileupload = require("express-fileupload");
const cookieParser = require("cookie-parser");
const mongoSantize = require("express-mongo-sanitize");
const helemt = require("helmet");
const xss = require("xss-clean");
const rateLimit = require("express-rate-limit");
const hpp = require("hpp");
const cors = require("cors");
const errorHandler = require("./middelware/error");
const connectDB = require("./config/db");

//Load Env
dotenv.config();

//Connect to database
connectDB();

//Route files
const auth = require("./routes/auth");
const users = require("./routes/user");

const app = express();

//Body parser
app.use(express.json());

//Cookie parser
app.use(cookieParser());

//Dev logging middelware
if (process.env.NODE_ENV === "development") {
	app.use(morgan("dev"));
}

//File uploading
app.use(fileupload());

//Sanitize data
app.use(mongoSantize());

//Set security headers
app.use(helemt());

//Prevent XSS attacks
app.use(xss());

//Rate limiting
const limiter = rateLimit({
	windowMs: 60 * 1000, //1 min
	max: 100,
});

app.use(limiter);

//Prevent HTTP params pollution
app.use(hpp());

//Enablr cors
app.use(cors());

//Set static folder
app.use(express.static(path.join(__dirname, "public")));

//Mount routers
app.use("/api/v1/auth", auth);
app.use("/api/v1/users", users);

app.use(errorHandler);

const PORT = process.env.PORT || 1337;

const server = app.listen(
	PORT,
	console.log(
		`Server running in ${process.env.NODE_ENV} mode on port ${PORT}`.yellow
			.bold
	)
);

//Handle unhandled promise rejections
process.on("unhandledRejection", (err, promise) => {
	console.log(`Error: ${err.message}`.red);
	//Close server & exit
	server.close(() => process.exit(1));
});
