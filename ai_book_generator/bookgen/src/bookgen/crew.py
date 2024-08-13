from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task
from crewai_tools.tools import FileReadTool
from bookgen.tools.custom_tool import GetImages, CovMdToPdf
from langchain_groq import ChatGroq
import mdpdf

# Uncomment the following line to use an example of a custom tool
# from bookgen.tools.custom_tool import MyCustomTool

# Check our tools documentations for more information on how to use them
# from crewai_tools import SerperDevTool


@CrewBase
class BookgenCrew():
	"""Bookgen crew"""
	agents_config = 'config/agents.yaml'
	tasks_config = 'config/tasks.yaml'

	file_read_tool = FileReadTool(
		file_path='D:/aibookgen/bookgen/src/bookgen/config/template.md',
		description='A tool to read the Story Template file and understand the expected output format.'
	)

	def llm(self):
		llm = ChatGroq(model="llama-3.1-70b-versatile")
		# llm = ChatGroq(model="mixtral-8x7b-32768")
		return llm

	@agent
	def story_outliner(self) -> Agent:
		return Agent(
			config=self.agents_config['story_outlier'],
			# tools=[MyCustomTool()], # Example of custom tool, loaded on the beginning of file
			verbose=True,
			llm=self.llm(),
			allow_delegation=False

		)

	@agent
	def story_writer(self) -> Agent:
		return Agent(
			config=self.agents_config['story_writer'],
			# tools=[MyCustomTool()], # Example of custom tool, loaded on the beginning of file
			verbose=True,
			llm=self.llm(),
			allow_delegation=False
		)

	@agent
	def image_generator(self) -> Agent:
		return Agent(
			config=self.agents_config['image_generator'],
			# tools=[MyCustomTool()], # Example of custom tool, loaded on the beginning of file
			verbose=True,
			tools=  [GetImages()],
			allow_delegation=False  
		)

	@agent
	def content_formatter(self) -> Agent:
		return Agent(
			config=self.agents_config['content_formatter'],
			# tools=[MyCustomTool()], # Example of custom tool, loaded on the beginning of file
			verbose=True,
			llm=self.llm(),
			tools=[self.file_read_tool],
			allow_delegation=False
		)

	@agent
	def markdown_to_pdf_creator(self) -> Agent:
		return Agent(
			config=self.agents_config['pdf_converter'],
			# tools=[MyCustomTool()], # Example of custom tool, loaded on the beginning of file
			verbose=True,
			llm=self.llm(),
			tools=[CovMdToPdf()],
			allow_delegation=False
		)

	@task
	def outline_task(self) -> Task:
		return Task(
			config=self.tasks_config['outline_task'],
			agent=self.story_outliner()
		)

	@task
	def write_task(self) -> Task:
		return Task(
			config=self.tasks_config['write_task'],
			agent=self.story_writer()
		)

	@task
	def image_task(self) -> Task:
		return Task(
			config=self.tasks_config['image_task'],
			agent=self.image_generator()
		)

	@task
	def format_task(self) -> Task:
		return Task(
			config=self.tasks_config['format_task'],
			agent=self.content_formatter(),
			context=[self.write_task(), self.image_task()],
			output_file="story.md"
		)

	@task
	def pdf_task(self) -> Task:
		return Task(
			config=self.tasks_config['pdf_task'],
			agent=self.markdown_to_pdf_creator()
		)
	

	@crew
	def crew(self) -> Crew:
		"""Creates the Bookgen crew"""
		return Crew(
			agents=self.agents, # Automatically created by the @agent decorator
			tasks=self.tasks, # Automatically created by the @task decorator
			process=Process.sequential,
			verbose=2,
			# process=Process.hierarchical, # In case you wanna use that instead https://docs.crewai.com/how-to/Hierarchical/
		)

if __name__ == "__main__": 
    result =  BookgenCrew().crew().kickoff()

    print(result)