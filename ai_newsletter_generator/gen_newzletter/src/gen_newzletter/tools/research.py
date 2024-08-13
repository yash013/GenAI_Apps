from crewai_tools import BaseTool
from exa_py import Exa
from openai import OpenAI
import os, re, requests
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()


class SearchAndContents(BaseTool):
    name: str = "Search and Contents Tool"
    description: str = (
        "Searches the web based on a search query for the latest results. Results are only from the last week. Uses the Exa API. This also returns the contents of the search results."
    )

    def _run(self, search_query: str) -> str:
        
        exa = Exa(api_key=os.getenv("EXA_API_KEY"))

        one_week_ago = datetime.now() - timedelta(days=7)
        date_cutoff = one_week_ago.strftime("%Y-%m-%d")

        search_results = exa.search_and_contents(
        query=search_query,
        use_autoprompt=True,
        start_published_date=date_cutoff,
        text={"include_html_tags": False, "max_characters": 10000}
        )

        return search_results

class FindSimilar(BaseTool):
    name: str = "Find Similar Tool"
    description: str = (
        "Searches for similar articles to a given article using the Exa API. Take in a URL of the article."
    )

    def _run(self, article_url: str) -> str:

        exa = Exa(api_key=os.getenv('EXA_API_KEY'))

        one_week_ago = datetime.now() - timedelta(days=7)
        date_cutoff = one_week_ago.strftime("%Y-%m-%d")

        search_results = exa.find_similar(
            url=article_url,
            start_published_date=date_cutoff
        )

        return search_results


class GetContents(BaseTool):
    name: str = "Get Contents Tool"
    description: str = (
        "Gets the contents of a specific article using the Exa API. Takes in the ID of the article in a list, like this: ['https://www.cnbc.com/2024/04/12/my-news-story']."
    )
    
    def _run(self, article_id: str) -> str:
        exa = Exa(api_key=os.getenv('EXA_API_KEY'))

        contents_result = exa.get_contents(
            ids=article_id
        )
 
        return contents_result
    
class GetImages(BaseTool):
    name: str = "Image Generation Tool"
    description: str = (
        "Gets the image for a newsletter. Takes in the Title of the newsletter, like this: ['AI advancement news']."
    )
    
    def _run(self, title: str) -> str:
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

        response = client.images.generate(
        model="dall-e-2",
        prompt=f"Generate an image for this newsletter: {title}.",
        size="1024x1024",
        quality="standard",
        n=1,
        )
 
        image_url = response.data[0].url
        words = title.split()[:5] 
        safe_words = [re.sub(r'[^a-zA-Z0-9_]', '', word) for word in words]  
        filename = "_".join(safe_words).lower() + ".png"
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
    

if __name__ == "__main__":
    
    # search_and_contents = SearchAndContents()
    # search_results = search_and_contents.run(search_query="latest news on ai")
    # print(search_results)
    
    get_image = GetImages()
    result = get_image.run(title="AI infrastructure and pledge")
    print(result)

    # find_similar = FindSimilar()
    # similar = find_similar.run(article_url="https://aiandacademia.substack.com/p/ai-and-politics-the-latest-developments")
    # print(similar)

    # get_contents = GetContents()
    # contents = get_contents.run(article_id=["https://www.insidehighered.com/news/tech-innovation/artificial-intelligence/2024/07/29/students-and-professors-expect-more", "https://forum.effectivealtruism.org/posts/bfZwHJzbBrkARzdYD/the-new-uk-government-s-stance-on-ai-safety"])
    # print(contents)
    