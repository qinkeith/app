from dotenv import load_dotenv
import os

from langchain_google_genai import GoogleGenerativeAIEmbeddings

from langchain_astradb import AstraDBVectorStore
from github import fetch_github_issues


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
    print("Connected to Vector Store")
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

    results = vstore.similarity_search("flash messages", k=5)
    for res in results:
        print(f"*{res.page_content}") 





