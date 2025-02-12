# Web Prompt Using Gemini API with NoteJS

## Introduction

We will use [Google AI SDK for JavaScript](https://github.com/google-gemini/generative-ai-js) and Node.js to develop a backend which talks to Google Gemini. The front end provides a web page which includes a prompt for questions.

## Prerequisites

- Download and install the latest Node.js.
- Get [Google API key](https://aistudio.google.com/app/apikey)

## The project

### Initialize the project

- Create a directory call `gemini` and cd into it
- Run: `npm init`. This will create a `package.json` file in the directory.
- Install dependencies: `npm install express @google/generative-ai dotenv`. This will add the 3 dependencies into `package.json` file:
  
  ```json
  "dependencies": {
    "@google/generative-ai": "^0.21.0",
    "dotenv": "^16.4.7",
    "express": "^4.21.2"
  }
  ```

- Create a `.env` file in the project directory with
  
  ```env
  API_KEY=YOUR_API_KEY
  ```

### Directories and Files

The directory and files in the project:

```ascii
        │   .env
        │   index.js
        │   package.json
        │   README.md
        ├───public
        │       index.html
        │       script.js
        │       styles.css
        │
        └───routes
                gemini.js
```

### Run the code

Add a start script in `package.json` file

```json
"scripts": {
  "start": "node index.js"
}
```

Start the app in the project directory

```cmd
npm start
```

You can now access Gemini Chat via [http://localhost:3000/](http://localhost:3000/).
