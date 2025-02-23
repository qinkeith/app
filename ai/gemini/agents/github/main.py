import pdb
from dotenv import load_dotenv
import os

from langchain_google_genai import GoogleGenerativeAIEmbeddings, ChatGoogleGenerativeAI
from langchain.agents import create_tool_calling_agent
from langchain_astradb import AstraDBVectorStore
from github import fetch_github_issues
from langchain import hub
from langchain.agents import AgentExecutor
from langchain.tools.retriever import create_retriever_tool
from note import note_tool

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
print(f"* {retriever}")
retriever_tool = create_retriever_tool(
    retriever,
    "github_search",
    "Search for information about issues. For any questions about github, use this tool.",
)

prompt = hub.pull("hwchase17/openai-functions-agent")

# Create a chat model instead of embeddings model for the agent
llm = ChatGoogleGenerativeAI(model="gemini-2.0-flash")

tools = [retriever_tool, note_tool]
agent = create_tool_calling_agent(llm, tools, prompt)
agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)  # Fixed ArithmeticError to AgentExecutor

while (question := input("Ask a question about github issues (q to quit): ")) != "q":
    result = agent_executor.invoke({"input": question})
    print(result["output"])
