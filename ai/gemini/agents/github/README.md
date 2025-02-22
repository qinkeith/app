# Github AI Agent in Python

## Setup the python environment

- Create a python virtual environment: `python -m venv github`
- Activate the virtual environment: `.\github\Scripts\activate`
- Install the requirements: `pip install python-dotenv requests langchain langchain-astradb langchain-google-genai langchain-google-vertexai langchainhub`

## Setup the environment variables

- Create a Google AI Studio API key at [https://aistudio.google.com/apikey}(https://aistudio.google.com/apikey)
- Create an Astra DB instance and a keyspace at [https://astra.datastax.com/](https://astra.datastax.com/). By default the keyspace is `default_keyspace`.
- Create a `.env` file in the root of the project
- Add the following variables to the `.env` file:
  - `GITHUB_TOKEN`: Your Github personal access token
  - `ASTRA_DB_API_ENDPOINT`: Your Astra DB API endpoint
  - `ASTRA_DB_APPLICATION_TOKEN`: Your Astra DB application token
  - `ASTRA_DB_KEYSPACE`: Your Astra DB keyspace
  - `GOOGLE_API_KEY`: Your Google API key

## Run the agent

- `python main.py`
