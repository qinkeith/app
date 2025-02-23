import pdb
from dotenv import load_dotenv
import os
from typing import List

from langchain_google_genai import GoogleGenerativeAIEmbeddings, ChatGoogleGenerativeAI
from langchain.agents import create_tool_calling_agent
from langchain_astradb import AstraDBVectorStore
from github import fetch_github_issues
from langchain import hub
from langchain.agents import AgentExecutor
from langchain.tools.retriever import create_retriever_tool
from note import note_tool
from langchain.prompts import ChatPromptTemplate

load_dotenv()


def connect_to_vstore():
    embeddings = GoogleGenerativeAIEmbeddings(model="models/embedding-001")
    
    # Use the vector API endpoint
    ASTRA_DB_API_ENDPOINT = os.getenv("ASTRA_DB_API_ENDPOINT")
    ASTRA_DB_APPLICATION_TOKEN = os.getenv("ASTRA_DB_APPLICATION_TOKEN")
    ASTRA_DB_KEYSPACE = os.getenv("ASTRA_DB_KEYSPACE")

    vstore = AstraDBVectorStore(
        embedding=embeddings,
        collection_name="github_agent",
        api_endpoint=ASTRA_DB_API_ENDPOINT,
        token=ASTRA_DB_APPLICATION_TOKEN,
        namespace=ASTRA_DB_KEYSPACE,
    )
    return vstore

vstore = connect_to_vstore()

add_to_vectorstore = input("Do you want to update the issues? (y/N): ").lower() in ["y", "yes"]

if add_to_vectorstore:
    owner = "qinkeith"
    repo = "app"
    issues = fetch_github_issues(owner, repo)
    
    try:
        vstore.delete_collection()
    except:
        pass

    vstore = connect_to_vstore()
    vstore.add_documents(issues)

retriever = vstore.as_retriever(search_kwargs={"k": 3})
retriever_tool = create_retriever_tool(
    retriever,
    "github_search",
    "Search for information about issues. For any questions about github, use this tool.",
)

# Define tools
tools = [retriever_tool, note_tool]

# Create a custom prompt that works with Gemini
prompt = ChatPromptTemplate.from_messages([
    ("system", """You are a helpful AI assistant that uses tools to accomplish tasks. 
    Available tools:
    {tools}
    
    When using tools:
    1. First decide which tool to use based on the task
    2. Then call the tool with appropriate input
    3. Use the note_tool to save important findings
    
    Remember to always provide the exact text when using note_tool."""),
    ("human", "{input}"),
    ("assistant", "I'll help you with that request."),
    ("human", "Assistant: {agent_scratchpad}")
])

# Create a google chat model for the agent
llm = ChatGoogleGenerativeAI(model="gemini-2.0-flash")

# Setup the proper tool descriptions
tool_descriptions = "\n".join([f"- {tool.name}: {tool.description}" for tool in tools])

# Bind the llm, tools, and prompts together to create an agent
agent = create_tool_calling_agent(
    llm=llm,
    tools=tools,
    prompt=prompt
)

# Set verbose mode to display agent output
agent_executor = AgentExecutor(
    agent=agent,
    tools=tools,
    verbose=True
)

# Modify the question loop to encourage note-taking
while (question := input("Ask a question about github issues (q to quit): ")) != "q":
    if question.lower().strip() == "test note":
        result = agent_executor.invoke({
            "input": "Use the note_tool to save this text: 'This is a test note'",
            "tools": tool_descriptions,
        })
    else:
        result = agent_executor.invoke({
            "input": question + " After finding relevant information, use the note_tool to save a summary.",
            "tools": tool_descriptions,
        })
    print(result["output"])
