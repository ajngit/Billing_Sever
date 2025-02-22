// app.js
const express = require("express");
const cors = require("cors");
const userRoutes = require("./Routes/userRoutes");
const productRoutes = require("./Routes/productRoutes");
const RegistrationRoutes = require("./Routes/RegistrationRoutes");
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors({
    origin: ["http://localhost:4200","http://localhost:1433","https://harvest-hub-nine.vercel.app"],
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

app.use("/", userRoutes);
app.use("/", productRoutes);
app.use("/",RegistrationRoutes)


app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
