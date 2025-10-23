import os
import json
from typing import Literal, Dict, Any
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_xai import ChatXAI
from xai_grok import GrokClient
from langchain_community.llms.tongyi import Tongyi
# from openai import OpenAI




class ModelConfig:
    """
    配置不同AI模型的参数
    """
    def __init__(self, model_provider):
        self.model_provider = model_provider

        with open("/home/yangting/Documents/model_key.json", "r") as file:
            config = json.load(file)
            os.environ["DEEP_SEEK_API_KEY"] = config.get("llm_key", {}).get("deepseek_api_key")

            os.environ["OPENAI_API_KEY"] = config.get("llm_key", {}).get("gpt_api_key")

            os.environ["XAI_API_KEY"] = config.get("llm_key", {}).get("grok_api_key")
            os.environ["HW_API_KEY"] = config.get("llm_key", {}).get("hw_api_key")
            os.environ["NIVIDA_API_KEY"] = config.get("llm_key", {}).get("nivida_api_key")
            os.environ["ALI_DEEPSEEK_API_KEY"] = config.get("llm_key", {}).get("ali_deepseek_api_key")
            os.environ["GOOGLE_API_KEY"] = config.get("llm_key", {}).get("google_api_key")
            os.environ["ZETA_API_KEY"] = config.get("llm_key", {}).get("zeta_api_key")
        self.config = self._get_model_config()
        self.llm = self._initialize_llm()

    
    def _get_model_config(self):
        if self.model_provider == "openai":
            return {
                "api_key": os.getenv("OPENAI_API_KEY"),
                "model": "gpt-o3-mini",
                "temperature": 0.7,
                "max_tokens": 2048,
            }
        elif self.model_provider == "grok":
            return {
                "api_key": os.getenv("XAI_API_KEY"),
                "model": "grok-3",
                "temperature": 0.7,
                "max_tokens": 4096,
            }
        elif self.model_provider == "deepseek":
            return {
                "api_key": os.getenv("DEEP_SEEK_API_KEY"),
                "model": "deepseek-reasoner",
                "temperature": 0.7,
                "max_tokens": 4096,
            }
        elif self.model_provider == "hw":
            return {
                "api_key": os.getenv("HW_API_KEY"),
                "model": "DeepSeek-R1",
                "temperature": 0.7,
                "max_tokens": 4096,
            }
        elif self.model_provider == "nivida":
            return {
                "api_key": os.getenv("NIVIDA_API_KEY"),
                "model": "deepseek-ai/deepseek-r1",
                "temperature": 0.7,
                "max_tokens": 4096,
            }
        elif self.model_provider == "ali":
            return {
                "api_key": os.getenv("ALI_DEEPSEEK_API_KEY"),
                "model": "qwq-32b",
                "temperature": 0.7,
                "max_tokens": 4096,
            }
        elif self.model_provider == "google":
            return {
                "api_key": os.getenv("GOOGLE_API_KEY"),
                "model": "gemini-2.5-pro-preview-03-25",
                "temperature": 0.7,
                "max_tokens": 4096,
            }
        elif self.model_provider == "Zeta":
            return {
                "api_key": os.getenv("ZETA_API_KEY"),
                "model": "o1-high",
                "temperature": 0.7,
                "max_tokens": 4096,
            }
        
        else:
            raise ValueError("Unsupported model provider")
    
    def _initialize_llm(self):
        print(self.config)
        if self.model_provider == "openai":
            return ChatOpenAI(model_name=self.config["model"], temperature=self.config["temperature"], )
        elif self.model_provider == "grok":
            return ChatOpenAI(api_key=self.config["api_key"],model_name=self.config["model"], temperature=self.config["temperature"],base_url="https://api.x.ai/v1")
        elif self.model_provider == "deepseek":
            return ChatOpenAI(api_key=self.config["api_key"],model_name=self.config["model"], temperature=self.config["temperature"],base_url="https://api.deepseek.com/v1")
        elif self.model_provider == "hw":
            return ChatOpenAI(api_key=self.config["api_key"],model_name=self.config["model"], temperature=self.config["temperature"],base_url="https://maas-cn-southwest-2.modelarts-maas.com/v1/infers/952e4f88-ef93-4398-ae8d-af37f63f0d8e/v1")
        elif self.model_provider == "nivida":
            return ChatOpenAI(api_key=self.config["api_key"],model_name=self.config["model"], temperature=self.config["temperature"],base_url="https://integrate.api.nvidia.com/v1")
        elif self.model_provider == "ali":
            return ChatOpenAI(api_key=self.config["api_key"],model_name=self.config["model"], temperature=self.config["temperature"],base_url="https://dashscope.aliyuncs.com/compatible-mode/v1/",streaming=True)
        elif self.model_provider == "google":
            client = ChatOpenAI(api_key=self.config["api_key"],model=self.config["model"], temperature=self.config["temperature"],base_url="https://generativelanguage.googleapis.com/v1beta/openai/")
            return client
        elif self.model_provider == "Zeta":
            return ChatOpenAI(api_key=self.config["api_key"],model_name=self.config["model"], temperature=self.config["temperature"],base_url="https://api.zetatechs.online/v1")
        else:
            raise ValueError("Unsupported model provider")
    
    def get_config(self) -> Dict[str, Any]:
        return self.config
    
    def get_llm(self):
        return self.llm
    
    def update_config(self, new_config: Dict[str, Any]):
        """
        更新配置参数
        """
        self.config.update(new_config)
        self.llm = self._initialize_llm()

# 示例用法
if __name__ == "__main__":

#     # config = ModelConfig(model_provider="google")
#     # llm = config.get_llm()
#     # result = llm.models.generate_content(model="gemini-2.0-flash",contents="hello")   
#     # print(result.text)

    config = ModelConfig(model_provider="google")
    llm = config.get_llm()
    # print(llm.model_name)
    result = llm.invoke("hello")
    print(result.content)
    # google
    # config = ModelConfig(model_provider="google")
    # llm = config.get_llm()

    # result = llm.invoke("hello")
    # print(result.content)


   
