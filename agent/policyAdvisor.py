from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama import OllamaLLM
import PyPDF2
model = OllamaLLM(model="llama3.2")
template = """
You are an expert in advising the admin to ensure policies on blocking the network traffic.
Based on the following project development script, give your suggestions and recommendations.

Script:
{script}
"""
prompt = ChatPromptTemplate.from_template(template)
chain = prompt | model
def extract_text_from_pdf(file_path):
    text = ""
    with open(file_path, "rb") as f:
        reader = PyPDF2.PdfReader(f)
        for page in reader.pages:
            text += page.extract_text() or ""
    return text.strip()
def advisingAgent(pdf_path):
    script_text = extract_text_from_pdf(pdf_path)
    result = chain.invoke({"script": script_text})
    print("\n LLM Response:\n")
    print(result)
if __name__ == "__main__":
    advisingAgent("agent/CACF_Project_Development_Report.pdf")