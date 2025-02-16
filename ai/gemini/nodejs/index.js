// In index.js

const express = require("express");
const cors = require("cors");
const app = express();

const generateContent = require("./routes/gemini.js");

// Enable CORS
app.use(cors());

// Middleware to parse JSON
app.use(express.json());

// Serve static files from the "public" folder
app.use(express.static("public"));

// Routes
app.post("/gemini", generateContent);

app.listen(3000, () => {
    console.log("App is running on port 3000");
});
