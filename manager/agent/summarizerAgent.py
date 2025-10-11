from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama import OllamaLLM

model=OllamaLLM(model="llama3.2")
template="""
you are an expert in summarizing why the network request traffic is blocked
based on the output of the Machine learning model {result}

Give 2 line summary on the issue

"""
prompt=ChatPromptTemplate.from_template(template)
def summarizer(result):
    chain=prompt|model
    return chain.invoke({"result":result})
