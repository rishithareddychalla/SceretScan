import io
import os
import zipfile
import re
from typing import Iterator, Tuple
from sentinel_scan.sources.file_source import DEFAULT_EXCLUDES, DEFAULT_EXCLUDE_EXTENSIONS

def get_zip_files(zip_path: str) -> Iterator[Tuple[str, str]]:
    """
    Reads a ZIP file in-memory and yields tuples of (file_path_in_zip, file_content).
    Filters out binaries and excluded paths/extensions, except for supported document formats.
    """
    if not os.path.exists(zip_path):
        raise FileNotFoundError(f"ZIP file not found: {zip_path}")
        
    # We want to allow document formats and binary targets even if they might otherwise be filtered
    doc_extensions = {".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".rtf", ".doc", ".xls", ".ppt", ".bin", ".exe", ".dll", ".so"}
        
    try:
        with zipfile.ZipFile(zip_path, 'r') as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                
                name = info.filename
                
                # Check default folder excludes (e.g. node_modules)
                parts = name.replace('\\', '/').split('/')
                if any(part in DEFAULT_EXCLUDES for part in parts):
                    continue
                    
                # Check extension (but allow documents)
                _, ext = os.path.splitext(name)
                ext_lower = ext.lower()
                if ext_lower in DEFAULT_EXCLUDE_EXTENSIONS and ext_lower not in doc_extensions:
                    continue
                    
                try:
                    with z.open(info.filename) as f:
                        raw_bytes = f.read()
                        
                        if ext_lower == ".pdf":
                            try:
                                import pypdf
                                pdf_file = io.BytesIO(raw_bytes)
                                reader = pypdf.PdfReader(pdf_file)
                                text_parts = []
                                for page in reader.pages:
                                    t = page.extract_text()
                                    if t:
                                        text_parts.append(t)
                                content = "\n".join(text_parts)
                            except Exception:
                                content = ""
                                
                        elif ext_lower == ".docx":
                            try:
                                import xml.etree.ElementTree as ET
                                docx_file = io.BytesIO(raw_bytes)
                                with zipfile.ZipFile(docx_file) as dz:
                                    xml_content = dz.read('word/document.xml')
                                    root = ET.fromstring(xml_content)
                                    texts = []
                                    for elem in root.iter():
                                        if elem.tag.endswith('}t') or elem.tag == 't':
                                            if elem.text:
                                                texts.append(elem.text)
                                    content = " ".join(texts)
                            except Exception:
                                content = ""
                                
                        elif ext_lower == ".xlsx":
                            try:
                                import xml.etree.ElementTree as ET
                                xlsx_file = io.BytesIO(raw_bytes)
                                texts = []
                                with zipfile.ZipFile(xlsx_file) as dz:
                                    if 'xl/sharedStrings.xml' in dz.namelist():
                                        xml_content = dz.read('xl/sharedStrings.xml')
                                        root = ET.fromstring(xml_content)
                                        for elem in root.iter():
                                            if elem.tag.endswith('}t') or elem.tag == 't':
                                                if elem.text:
                                                    texts.append(elem.text)
                                    for sheet_name in dz.namelist():
                                        if sheet_name.startswith('xl/worksheets/sheet') and sheet_name.endswith('.xml'):
                                            xml_content = dz.read(sheet_name)
                                            root = ET.fromstring(xml_content)
                                            for elem in root.iter():
                                                if elem.tag.endswith('}v') or elem.tag == 'v':
                                                    if elem.text:
                                                        texts.append(elem.text)
                                content = "\n".join(texts)
                            except Exception:
                                content = ""
                                
                        elif ext_lower == ".pptx":
                            try:
                                import xml.etree.ElementTree as ET
                                pptx_file = io.BytesIO(raw_bytes)
                                texts = []
                                with zipfile.ZipFile(pptx_file) as dz:
                                    for slide_name in dz.namelist():
                                        if slide_name.startswith('ppt/slides/slide') and slide_name.endswith('.xml'):
                                            xml_content = dz.read(slide_name)
                                            root = ET.fromstring(slide_name)
                                            for elem in root.iter():
                                                if elem.tag.endswith('}t') or elem.tag == 't':
                                                    if elem.text:
                                                        texts.append(elem.text)
                                content = "\n".join(texts)
                            except Exception:
                                content = ""
                                
                        elif ext_lower == ".odt":
                            try:
                                import xml.etree.ElementTree as ET
                                odt_file = io.BytesIO(raw_bytes)
                                with zipfile.ZipFile(odt_file) as dz:
                                    xml_content = dz.read('content.xml')
                                    root = ET.fromstring(xml_content)
                                    texts = []
                                    for elem in root.iter():
                                        if elem.tag.endswith('}text') or elem.tag.endswith('}p') or elem.tag == 'text' or elem.tag == 'p':
                                            if elem.text:
                                                texts.append(elem.text)
                                            if elem.tail:
                                                texts.append(elem.tail)
                                    content = " ".join(texts)
                            except Exception:
                                content = ""
                                
                        elif ext_lower == ".rtf":
                            try:
                                rtf_str = raw_bytes.decode('utf-8', errors='ignore')
                                rtf_str = re.sub(r'\\[a-z0-9*-]+', ' ', rtf_str)
                                rtf_str = re.sub(r'[{}]', ' ', rtf_str)
                                rtf_str = re.sub(r'\s+', ' ', rtf_str)
                                content = rtf_str.strip()
                            except Exception:
                                content = ""
                                
                        elif ext_lower in {".doc", ".xls", ".ppt", ".bin", ".exe", ".dll", ".so"}:
                            # Extract binary strings
                            ascii_strings = re.findall(rb'[ -~]{4,}', raw_bytes)
                            utf16_strings = re.findall(rb'(?:[\x20-\x7E]\x00){4,}', raw_bytes)
                            decoded = []
                            for s in ascii_strings:
                                try:
                                    decoded.append(s.decode('ascii'))
                                except Exception:
                                    pass
                            for s in utf16_strings:
                                try:
                                    decoded.append(s.decode('utf-16le'))
                                except Exception:
                                    pass
                            content = "\n".join(decoded)
                            
                        else:
                            try:
                                content = raw_bytes.decode('utf-8', errors='surrogateescape')
                            except Exception:
                                # Fallback to binary strings
                                ascii_strings = re.findall(rb'[ -~]{4,}', raw_bytes)
                                utf16_strings = re.findall(rb'(?:[\x20-\x7E]\x00){4,}', raw_bytes)
                                decoded = []
                                for s in ascii_strings:
                                    try:
                                        decoded.append(s.decode('ascii'))
                                    except Exception:
                                        pass
                                for s in utf16_strings:
                                    try:
                                        decoded.append(s.decode('utf-16le'))
                                    except Exception:
                                        pass
                                content = "\n".join(decoded)
                                
                        yield name, content
                except Exception:
                    continue
    except zipfile.BadZipFile:
        raise ValueError(f"Invalid or corrupted ZIP file: {zip_path}")
