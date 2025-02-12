// In index.js

const express = require("express");
const app = express();

const generateContent = require("./routes/gemini.js");


// Middleware to parse JSON
app.use(express.json());

// Serve static files from the "public" folder
app.use(express.static("public"));

// Routes
app.get("/", (req, res) => {
    res.sendFile(__dirname + "/public/index.html");
});

app.post("/gemini", generateContent);

app.listen(3000, () => {
    console.log("App is running on port 3000");
});