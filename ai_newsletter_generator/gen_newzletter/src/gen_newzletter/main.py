#!/usr/bin/env python
import sys
from gen_newzletter.crew import GenNewzletterCrew

# This main file is intended to be a way for your to run your
# crew locally, so refrain from adding necessary logic into this file.
# Replace with inputs you want to test with, it will automatically
# interpolate any tasks and agents information

def load_html_template(): 
    with open('D:/crewai_newz/gen_newzletter/src/gen_newzletter/config/newsletter_template.html', 'r') as file:
        html_template = file.read()
        
    return html_template



def run():
    # Replace with your inputs, it will automatically interpolate any tasks and agents information
    inputs = {
        'topic': input('Enter the topic for your newsletter: '),
        'personal_message': input('Enter a personal message for your newsletter: '),
        'html_template': load_html_template()
    }
    GenNewzletterCrew().crew().kickoff(inputs=inputs)
