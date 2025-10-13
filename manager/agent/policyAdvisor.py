from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama import OllamaLLM
from langchain import LLMChain
import PyPDF2

# Initialize model
model = OllamaLLM(model="llama3.2")

# Define the LLM prompt
template = """
You are an expert in advising the admin to ensure policies on blocking network traffic.
Based on the following project development script, give your suggestions and recommendations.
Provide exactly 5 concise bullet points, each one line long.

Script:
{script}
"""

# Create the prompt
prompt = ChatPromptTemplate.from_template(template)

# Chain the prompt with the model
chain = LLMChain(llm=model, prompt=prompt)

# Function to extract text from a PDF
def extract_text_from_pdf(file_path):
    text = ""
    try:
        with open(file_path, "rb") as f:
            reader = PyPDF2.PdfReader(f)
            for page in reader.pages:
                text += page.extract_text() or ""
    except Exception as e:
        print(f"❌ Error reading PDF: {e}")
    return text.strip()

# Advisor function
def advisingAgent(pdf_path):
    print(f"\n🔍 Reading PDF from: {pdf_path}")
    script_text = extract_text_from_pdf(pdf_path)
    
    if not script_text:
        print("❌ No text extracted from PDF.")
        return None
    
    print("\n🧠 Generating LLM advice...\n")
    try:
        result = chain.run({"script": script_text})
    except Exception as e:
        print(f"❌ Error calling LLM: {e}")
        return None
    
    print("\n✅ LLM Response:\n")
    print(result)
    return result

# Correct main condition
if __name__ == "__main__":
    advisingAgent('manager/agent/raw (1).pdf')
