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
from typing import List, Dict, Optional

class Redactor:
    """Handles text redaction using Presidio analyzer and anonymizer."""
    
    def __init__(self, entities_to_redact: List[str]):
        self.entities_to_redact = entities_to_redact
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
    
    def analyze_text(self, text: str) -> List:
        """Analyze text for PII entities."""
        if not self.entities_to_redact or not text.strip():
            return []
        return self.analyzer.analyze(
            text=text, 
            entities=self.entities_to_redact, 
            language='en'
        )
    
    def anonymize_text(self, text: str, analysis_results: List) -> Dict:
        """Anonymize text based on analysis results."""
        if not analysis_results:
            return {"text": text, "items": []}
        
        anonymized_result = self.anonymizer.anonymize(
            text=text, 
            analyzer_results=analysis_results
        )
        return json.loads(anonymized_result.to_json())
    
    def process_text(self, text: str) -> Dict:
        """Complete redaction process for a single text."""
        analysis_results = self.analyze_text(text)
        return self.anonymize_text(text, analysis_results)
    
    @staticmethod
    def bold_redacted_items(items: List[Dict[str, int]], text: str) -> str:
        """Add bold formatting to redacted items for display."""
        if not items:
            return text
        
        # Sort items by start position in reverse order to avoid offset issues
        sorted_items = sorted(items, key=lambda x: x['start'], reverse=True)
        
        modified_text = text
        for item in sorted_items:
            start = item['start']
            end = item['end']
            modified_text = (
                modified_text[:start] + 
                '**' + modified_text[start:end] + '**' + 
                modified_text[end:]
            )
        return modified_text

def extract_text_from_file(uploaded_file) -> Optional[str]:
    """Extract text from uploaded file using unstructured."""
    try:
        bytes_data = uploaded_file.getvalue()
        file_path = Path(uploaded_file.name)

        with tempfile.NamedTemporaryFile(delete=False, suffix=file_path.suffix) as temp_file:
            temp_file.write(bytes_data)
            temp_file.flush()
            
            elements = partition(temp_file.name)
            extracted_text = '\n'.join([
                element.text for element in elements 
                if element.text and element.text.strip()
            ])
            
        Path(temp_file.name).unlink() 
        return extracted_text
        
    except Exception as e:
        st.error(f"Error processing file {uploaded_file.name}: {str(e)}")
        return None

def main():
    st.title('🔒 Text Redaction App')
    st.write("Automatically detect and redact personally identifiable information (PII) from text and documents.")
    
    INPUT_MODES = ['Text Input', 'File Upload']
    
    if 'input_mode' not in st.session_state:
        st.session_state.input_mode = INPUT_MODES[0]
    
    st.sidebar.header("Configuration")
    
    input_mode = st.sidebar.radio(
        'Select input mode:', 
        INPUT_MODES,
        index=INPUT_MODES.index(st.session_state.input_mode),
        key='input_mode'
    )
    
    analyzer = AnalyzerEngine()
    ENTITY_TYPES = analyzer.get_supported_entities()
    
    default_entity_types = [
        'PERSON', 'EMAIL_ADDRESS', 'PHONE_NUMBER', 
        'CREDIT_CARD', 'IBAN_CODE', 'IP_ADDRESS'
    ]
    
    if 'entities_to_redact' not in st.session_state:
        st.session_state.entities_to_redact = default_entity_types
    
    redact_options = st.sidebar.multiselect(
        'Select PII types to redact:',
        ENTITY_TYPES, 
        default=st.session_state.entities_to_redact,
        key='entities_to_redact',
        help="Choose which types of personal information to detect and redact"
    )
    
    if not redact_options:
        st.sidebar.warning("Please select at least one PII type to redact.")
        return
    
    texts = {}
    
    if input_mode == 'Text Input':
        st.header("Text Input")
        default_text = """My name is Hisham and my phone number is 555-123-4567. 
You can reach me at hisham@email.com or visit my website at 192.168.1.1."""
        
        text = st.text_area(
            'Enter text to redact:', 
            default_text, 
            height=200,
            help="Enter the text you want to analyze for PII"
        )
        
        if text.strip():
            texts['Text Input'] = text
            
    elif input_mode == 'File Upload':
        st.header("File Upload")
        uploaded_files = st.file_uploader(
            'Choose files to process:', 
            accept_multiple_files=True,
            type=['txt', 'pdf', 'docx', 'doc'],
            help="Upload text files, PDFs, or Word documents"
        )
        
        if uploaded_files:
            for uploaded_file in uploaded_files:
                extracted_text = extract_text_from_file(uploaded_file)
                if extracted_text:
                    texts[uploaded_file.name] = extracted_text
    
    col1, col2, col3 = st.columns([1, 1, 1])
    with col2:
        process_button = st.button('🔍 Process & Redact', use_container_width=True)
    
    if process_button:
        if not texts:
            st.warning("⚠️ Please provide text input or upload files before processing.")
            return
        
        if not redact_options:
            st.warning("⚠️ Please select at least one PII type to redact.")
            return
        
        redactor = Redactor(entities_to_redact=redact_options)
        
        with st.spinner('Processing files...'):
            text_results = {}
            progress_bar = st.progress(0)
            
            total_files = len(texts)
            for index, (file_name, text_content) in enumerate(texts.items()):
                if text_content.strip():  # Only process non-empty texts
                    text_results[file_name] = redactor.process_text(text_content)
                else:
                    text_results[file_name] = {"text": text_content, "items": []}
                
                progress_bar.progress((index + 1) / total_files)
        
        st.success(f"✅ Successfully processed {len(text_results)} file(s)")
        
        if len(texts) == 1:
            file_name = list(texts.keys())[0]
            results = text_results[file_name]
            
            col1, col2 = st.columns(2)
            with col1:
                st.metric("PII Items Found", len(results['items']))
            with col2:
                entities_found = set(item['entity_type'] for item in results['items'])
                st.metric("Entity Types Found", len(entities_found))
            
            with st.expander("📄 Preview Redacted Text", expanded=True):
                if results['items']:
                    preview_text = Redactor.bold_redacted_items(
                        items=results['items'], 
                        text=results['text']
                    )
                    st.markdown(preview_text)
                else:
                    st.info("No PII detected in the text.")
                    st.text(results['text'])
            
            if results['items']:
                with st.expander("🔍 Detected PII Details"):
                    for item in results['items']:
                        score_text = f" (Score: {item['score']:.2f})" if 'score' in item else ""
                        st.write(f"**{item['entity_type']}**: Found at index {item['start']}-{item['end']}{score_text}")
            st.download_button(
                label="📥 Download Redacted Text", 
                data=results["text"], 
                file_name=f"redacted_{file_name}.txt", 
                mime="text/plain",
                use_container_width=True
            )
        else:
            st.header("📊 Processing Summary")
            
            total_items = sum(len(results['items']) for results in text_results.values())
            st.metric("Total PII Items Found", total_items)
            
            zip_buffer = BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
                for file_name, results in text_results.items():
                    zip_file.writestr(f"redacted_{file_name}.txt", results["text"])
            
            st.download_button(
                label="📦 Download All Redacted Files (ZIP)", 
                data=zip_buffer.getvalue(), 
                file_name=f"redacted_files_{str(uuid4())[:8]}.zip", 
                mime="application/zip",
                use_container_width=True
            )
            
            with st.expander("📋 Individual File Results"):
                for file_name, results in text_results.items():
                    st.subheader(file_name)
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"PII Items: {len(results['items'])}")
                    with col2:
                        entities = set(item['entity_type'] for item in results['items'])
                        st.write(f"Entity Types: {', '.join(entities) if entities else 'None'}")

if __name__ == "__main__":
    main()
