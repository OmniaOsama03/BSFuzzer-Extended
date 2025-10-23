from openai import OpenAI

from pydantic import BaseModel, Field
from datetime import date
from enum import Enum
from typing import List
import os
import json

class Example(BaseModel):
    response: str = Field(description="response")

# Pydantic Schemas
class Currency(str, Enum):
    USD = "USD"
    EUR = "EUR"
    GBP = "GBP"

class LineItem(BaseModel):
    description: str = Field(description="Description of the item or service")
    quantity: int = Field(description="Number of units", ge=1)
    unit_price: float = Field(description="Price per unit", ge=0)

class Address(BaseModel):
    street: str = Field(description="Street address")
    city: str = Field(description="City")
    postal_code: str = Field(description="Postal/ZIP code")
    country: str = Field(description="Country")

class Invoice(BaseModel):
    vendor_name: str = Field(description="Name of the vendor")
    vendor_address: Address = Field(description="Vendor's address")
    invoice_number: str = Field(description="Unique invoice identifier")
    invoice_date: date = Field(description="Date the invoice was issued")
    line_items: List[LineItem] = Field(description="List of purchased items/services")
    total_amount: float = Field(description="Total amount due", ge=0)
    currency: Currency = Field(description="Currency of the invoice")

class Grok_model:
    def __init__(self,model="grok-2",temperature=0.7    ):
        with open("/home/yangting/Documents/model_key.json", "r") as file:
            config = json.load(file)
            os.environ["XAI_API_KEY"] = config.get("llm_key", {}).get("grok_api_key")
            self.client = OpenAI(
                api_key=os.environ["XAI_API_KEY"],
                base_url="https://api.x.ai/v1",
            )
            self.model = model
            self.temperature = temperature
    def set_model(self,model):
        self.model = model
    def set_temperature(self,temperature):
        self.temperature = temperature
    def generate_content(self,contents,response_format=Example):
        response = self.client.beta.chat.completions.parse(
            model=self.model,
            messages=contents,
            response_format=response_format,
            temperature=self.temperature
        )
        response = response.choices[0].message.parsed
        
        return response
        

if __name__ == "__main__":
    grok = Grok_model()
    result = grok.generate_content(contents = [{"role": "user", "content": "Given a raw invoice, carefully analyze the text and extract the invoice data into JSON format."}],response_format = Invoice)
    print(result)
    print(type(result))