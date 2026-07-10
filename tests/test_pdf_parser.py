from unittest.mock import MagicMock, patch
import io
import zipfile
from sentinel_scan.sources.file_source import read_file_safe

def test_read_file_safe_pdf_extraction():
    mock_reader = MagicMock()
    mock_page_1 = MagicMock()
    mock_page_1.extract_text.return_value = "This is a PDF report."
    mock_page_2 = MagicMock()
    mock_page_2.extract_text.return_value = "API_KEY=AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5"
    mock_reader.pages = [mock_page_1, mock_page_2]
    
    with patch("pypdf.PdfReader", return_value=mock_reader):
        content = read_file_safe("secrets_report.pdf")
        assert "This is a PDF report." in content
        assert "API_KEY=AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5" in content

def test_read_file_safe_pdf_handling_exception():
    # If pypdf throws an error, read_file_safe should return an empty string gracefully
    with patch("pypdf.PdfReader", side_effect=Exception("Corrupt PDF file")):
        content = read_file_safe("broken.pdf")
        assert content == ""

def test_read_file_safe_docx_extraction():
    import tempfile
    import os
    import zipfile
    temp_dir = tempfile.gettempdir()
    docx_path = os.path.join(temp_dir, "test_temp_doc.docx")
    
    # Create a real docx (zip file)
    with zipfile.ZipFile(docx_path, 'w') as z:
        xml_content = b'<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:t>Secret DOCX token: secret_token_123</w:t></w:p></w:document>'
        z.writestr('word/document.xml', xml_content)
        
    try:
        content = read_file_safe(docx_path)
        assert "Secret DOCX token" in content
        assert "secret_token_123" in content
    finally:
        if os.path.exists(docx_path):
            os.remove(docx_path)

def test_read_file_safe_xlsx_extraction():
    import tempfile
    import os
    import zipfile
    temp_dir = tempfile.gettempdir()
    xlsx_path = os.path.join(temp_dir, "test_temp_sheet.xlsx")
    
    with zipfile.ZipFile(xlsx_path, 'w') as z:
        shared_strings = b'<?xml version="1.0" encoding="UTF-8"?><sst><si><t>Secret XLSX cell</t></si></sst>'
        sheet_data = b'<?xml version="1.0" encoding="UTF-8"?><worksheet><sheetData><row><c><v>12345</v></c></row></sheetData></worksheet>'
        z.writestr('xl/sharedStrings.xml', shared_strings)
        z.writestr('xl/worksheets/sheet1.xml', sheet_data)
        
    try:
        content = read_file_safe(xlsx_path)
        assert "Secret XLSX cell" in content
        assert "12345" in content
    finally:
        if os.path.exists(xlsx_path):
            os.remove(xlsx_path)

def test_read_file_safe_odt_extraction():
    import tempfile
    import os
    import zipfile
    temp_dir = tempfile.gettempdir()
    odt_path = os.path.join(temp_dir, "test_temp_odt.odt")
    
    with zipfile.ZipFile(odt_path, 'w') as z:
        xml_content = b'<?xml version="1.0" encoding="UTF-8"?><office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"><office:body><office:text><text:p>Secret ODT content: my_key</text:p></office:text></office:body></office:document-content>'
        z.writestr('content.xml', xml_content)
        
    try:
        content = read_file_safe(odt_path)
        assert "Secret ODT content" in content
        assert "my_key" in content
    finally:
        if os.path.exists(odt_path):
            os.remove(odt_path)

def test_read_file_safe_rtf_extraction():
    import tempfile
    import os
    temp_dir = tempfile.gettempdir()
    rtf_path = os.path.join(temp_dir, "test_temp_rtf.rtf")
    
    rtf_data = b"{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0\\fnil\\fcharset0 Courier;}}\n\\viewkind4\\uc1\\pard\\lang1033\\f0\\fs20 Secret RTF content: password123\\par\n}"
    with open(rtf_path, "wb") as f:
        f.write(rtf_data)
        
    try:
        content = read_file_safe(rtf_path)
        assert "Secret RTF content" in content
        assert "password123" in content
    finally:
        if os.path.exists(rtf_path):
            os.remove(rtf_path)

def test_read_file_safe_binary_fallback():
    import tempfile
    import os
    temp_dir = tempfile.gettempdir()
    bin_path = os.path.join(temp_dir, "test_temp_binary.exe")
    
    binary_data = b"Some random binary junk \x00\xff\x04\x00S\x00e\x00c\x00r\x00e\x00t\x00 \x00B\x00i\x00n\x00a\x00r\x00y\x00 \x00s\x00t\x00r\x00i\x00n\x00g\x00 \x001\x002\x003\x00\x00\xff Plain ASCII secret here \xff\x00"
    with open(bin_path, "wb") as f:
        f.write(binary_data)
        
    try:
        content = read_file_safe(bin_path)
        assert "Plain ASCII secret here" in content
        assert "Secret Binary string 123" in content
    finally:
        if os.path.exists(bin_path):
            os.remove(bin_path)
