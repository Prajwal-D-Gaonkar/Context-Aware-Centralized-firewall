from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama import OllamaLLM
import PyPDF2

# Initialize model
model = OllamaLLM(model="llama3.2")

# Define the LLM prompt
template = """
You are an expert in advising the admin to ensure policies on blocking the network traffic.
Based on the following project development script, give your suggestions and recommendations.
Provide exactly 5 concise bullet points, each one line long.

Script:
{script}
"""

# Create the prompt and chain
prompt = ChatPromptTemplate.from_template(template)
chain = prompt | model

# Function to extract text from a PDF
def extract_text_from_pdf(file_path):
    text = ""
    with open(file_path, "rb") as f:
        reader = PyPDF2.PdfReader(f)
        for page in reader.pages:
            text += page.extract_text() or ""
    return text.strip()

# Advisor function
def advisingAgent(pdf_path):
    print(f"\n🔍 Reading PDF from: {pdf_path}")
    script_text = extract_text_from_pdf(pdf_path)
    
    print("\n🧠 Generating LLM advice...\n")
    result = chain.invoke({"script": script_text})
    
    print("\n✅ LLM Response:\n")
    print(result)
    return result

# FIX: correct main condition
if __name__ == "__main__":
    advisingAgent(r"C:\Users\prajw\OneDrive\Desktop\Context-Aware-Centralized-firewall\manager\agent\raw (1).pdf")
