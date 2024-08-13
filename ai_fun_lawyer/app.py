import streamlit as st
from LLM import infer
from util import write_answer

def main():
    
    st.set_page_config(
        page_title="AI fun lawyer",
        page_icon="📧",
        # layout="wide",
    )
    
if __name__ == "__main__":
    main()

st.title("AI fun lawyer")

st.write("Let the Essay save your son!!")

st.markdown("🚨🚨🚨This is just a fun lawyer made with the intentions of not hurting anybody's feelings or sentiments!!🚨🚨🚨")

acCrime = st.text_input("Enter The crime your son have commited!!")
if st.button('Submit', key='submit_button', help='Click to submit your input.'):
    placeholder = st.empty()
            # placeholder.image("examine.gif")
    Evaluation=infer(acCrime)

    write_answer(Evaluation)


# display_footer()

    # speak(Evaluation)
