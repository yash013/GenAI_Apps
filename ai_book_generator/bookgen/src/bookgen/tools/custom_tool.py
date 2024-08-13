from crewai_tools import BaseTool
from openai import OpenAI
from dotenv import load_dotenv
import os,re, requests
import subprocess
import mdpdf

load_dotenv()


class GetImages(BaseTool):
    name: str = "Image Generation Tool"
    description: str = (
        "Gets the images from a specific article using the Exa API. Takes in the Title of the article in a list, like this: ['Senator calls grow for OpenAI to prove it’s not silencing staff']."
    )
    
    def _run(self, chapter_content_and_character_details: str) -> str:
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

        response = client.images.generate(
        model="dall-e-3",
        prompt=f"Generate an image for this news: {chapter_content_and_character_details}. Style: Create an anime-style illustration. Do not add any text in the image.",
        size="1024x1024",
        quality="standard",
        n=1,
        )

        image_url = response.data[0].url
        words = chapter_content_and_character_details.split()[:5] 
        safe_words = [re.sub(r'[^a-zA-Z0-9_]', '', word) for word in words]  
        filename = "".join(safe_words).lower() + ".png"
        filepath = os.path.join(os.getcwd(), filename)

        # Download the image from the URL
        image_response = requests.get(image_url)
        if image_response.status_code == 200:
            with open(filepath, 'wb') as file:
                file.write(image_response.content)
        else:
            print("Failed to download the image.")
            return ""

        return filepath

class CovMdToPdf(BaseTool):
    name: str = "Convert Markdown to PDF Tool"
    description: str = (
        "Converts a Markdown file to a PDF document using the mdpdf command line application."
    )
    
    def _run(self, markdown_file_path: str) -> str:
        output_file = os.path.splitext(markdown_file_path)[0]+ '1' + '.pdf'
    
        # Command to convert markdown to PDF using mdpdf
        cmd = ['mdpdf', '--output', output_file, markdown_file_path]
        
        # Execute the command
        subprocess.run(cmd, check=True)
        
        return output_file

if __name__ == "__main__":

    pdf = CovMdToPdf()
    result = pdf.run("D:/aibookgen/bookgen/src/bookgen/story.md")
    print(type(result))
