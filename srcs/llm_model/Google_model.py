from google import genai
from pydantic import BaseModel
import os
import json
class Recipe(BaseModel):
  recipe_name: str
  ingredients: str


class Google_model:
    def __init__(self,model='gemini-2.0-flash',temperature=0.7):
        with open("/home/yangting/Documents/model_key.json", "r") as file:
            config = json.load(file)
            os.environ["GOOGLE_API_KEY"] = config.get("llm_key", {}).get("google_api_key")
            self.client = genai.Client(api_key=os.environ["GOOGLE_API_KEY"])
            self.model = model
            self.temperature = temperature
    def set_model(self,model):
        self.model = model
    def set_temperature(self,temperature):
        self.temperature = temperature
    def generate_content(self,contents,response_format=None):
        response = self.client.models.generate_content(
            model=self.model,
            contents=contents,
            config={
                'response_mime_type': 'application/json',
                'response_schema': response_format,
            },
            temperature=self.temperature
        )
        return response




if __name__ == "__main__":
    google = Google_model()
    result = google.generate_content(contents = "List a few popular cookie recipes. Be sure to include the amounts of ingredients.",response_format = Recipe)
    print(result.text)
    print(type(result))
