const dotenv = require("dotenv").config();
const { GoogleGenerativeAI } = require("@google/generative-ai");
const marked = require("marked"); // Import the marked library

const genAI = new GoogleGenerativeAI(process.env.API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash" });
//const model = genAI.getGenerativeModel({ model: "gemini-1.5-pro" });

const generateContent = async (req, res) => {
    try {
        const { question } = req.body;

        if (!question) {
            return res.status(400).json({ error: "Question is required." });
        }

        //console.log("Sending question to Gemini:", question);

        const result = await model.generateContent(question);
        const response = await result.response;
        const text = response.text();

        // Convert Markdown to HTML

	const { JSDOM } = require("jsdom");
	const createDOMPurify = require("dompurify");
	const { window } = new JSDOM("");
	const DOMPurify = createDOMPurify(window);

	// Convert Markdown to HTML and sanitize it
	const htmlResponse = DOMPurify.sanitize(marked.parse(text));

        //const htmlResponse = marked.parse(text);

        //console.log("Gemini response (HTML):", htmlResponse);

        res.json({ response: htmlResponse });
    } catch (err) {
        console.error("Error in generateContent:", err);
        res.status(500).json({ error: "Unexpected Error!!!" });
    }
};

module.exports = generateContent;