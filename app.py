import streamlit as st
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
import json
import zipfile
from io import BytesIO
from unstructured.partition.auto import partition
import tempfile
from pathlib import Path
from uuid import uuid4
from typing import List

st.title('Text Redaction App')

INPUT_MODES = ['Text', 'File Upload']

if 'input_mode' not in st.session_state:
    st.session_state.input_mode = INPUT_MODES[0]

input_mode = st.sidebar.radio('Select input mode', 
                              INPUT_MODES,
                              index=INPUT_MODES.index(st.session_state.input_mode),
                              key='input_mode')

analyzer = AnalyzerEngine()

ENTITY_TYPES = analyzer.get_supported_entities()
default_entity_types = [
    'PERSON',
    'EMAIL_ADDRESS',
    'PHONE_NUMBER'
]

if 'entities_to_redact' not in st.session_state:
    st.session_state.entities_to_redact = default_entity_types

redact_options = st.sidebar.multiselect(
    'Select PII types to redact',
    ENTITY_TYPES, 
    default=st.session_state.entities_to_redact,
    key='entities_to_redact'
)

anonymizer = AnonymizerEngine()

def run_redaction(text: str, entities_to_redact: List[str]):
    if not entities_to_redact:
        # Resolving Presido bug
        return []
    return analyzer.analyze(text=text, entities=entities_to_redact, language='en')


if input_mode == 'Text':
    default_text = 'My name is Hisham and my phone number is 07123456789'

    text = st.text_area('Enter text to redact', default_text)
    texts = {'raw_input': text}
elif input_mode == 'File Upload':
    uploaded_files = st.file_uploader('Choose a file', accept_multiple_files=True)
    texts = {}

    for file_index, uploaded_file in enumerate(uploaded_files):
        bytes_data = uploaded_file.getvalue()
        file_path = Path(uploaded_file.name)

        temp_file = tempfile.NamedTemporaryFile(delete=True, suffix=file_path.suffix)
        temp_file.write(bytes_data)
        elements = partition(temp_file.name)
        file_text = ''
        for element in elements:
            if element.text:  
                file_text += element.text + '\n'
        texts[uploaded_file.name] = file_text


def anonymize_results(text: str, results):
    return anonymizer.anonymize(text=text, analyzer_results=results)

submit_button = st.button('Redact')

def bold_redacted_items(text, items):
    for item in items:
        start = item['start']
        end = item['end']
        text = text[:start] + '**' + text[start:end] + '**' + text[end:]
    return text

if submit_button:
    if not texts:
        st.warning("Please upload at least one file or enter some text.")
        st.stop()    
    
    text_results = {}
    progress_bar = st.progress(0)

    for index, file_name in enumerate(texts):
        text = texts[file_name]
        results = run_redaction(text, entities_to_redact=redact_options)

        if not results:  
            text_results[file_name] = {"text": text, "items": []}
            continue

        anonymized_text = anonymize_results(text, results)
        results = json.loads(anonymized_text.to_json())
        text_results[file_name] = results

        progress_bar.progress((index+1)/float(len(texts)))

    
    if len(texts.keys()) == 1:
        results = text_results[list(texts.keys())[0]]

        with st.expander("Preview Redacted Text"):
            st.markdown(bold_redacted_items(results["text"], results["items"]))

        st.download_button(
            label="Download redacted file", 
            data=results["text"], 
            file_name=f"{list(texts.keys())[0]}.txt", 
            mime="application/json"
        )
    else:
        zip_file = BytesIO()
        with zipfile.ZipFile(zip_file, "w") as zf:
            for file_name in text_results:
                results = text_results[file_name]
                zf.writestr(file_name+".txt", results["text"])
        
        st.download_button(
            label="Download redacted files", 
            data=zip_file.getvalue(), 
            file_name=f"redacted_files_{str(uuid4())}.zip", 
            mime="application/zip"
        )
