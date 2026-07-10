import os
import io
import tempfile
import zipfile
from sentinel_scan.sources.zip_source import get_zip_files

def test_get_zip_files_extraction():
    temp_dir = tempfile.gettempdir()
    zip_path = os.path.join(temp_dir, "test_temp_archive.zip")
    
    # Sub-DOCX bytes
    docx_io = io.BytesIO()
    with zipfile.ZipFile(docx_io, 'w') as sub_z:
        sub_z.writestr('word/document.xml', b'<?xml version="1.0" encoding="utf-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:t>Secret DOCX in ZIP: token_123</w:t></w:p></w:document>')
    docx_data = docx_io.getvalue()
    
    # Sub-ODT bytes
    odt_io = io.BytesIO()
    with zipfile.ZipFile(odt_io, 'w') as sub_z:
        sub_z.writestr('content.xml', b'<?xml version="1.0" encoding="utf-8"?><office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"><office:body><office:text><text:p>Secret ODT in ZIP: key_abc</text:p></office:text></office:body></office:document-content>')
    odt_data = odt_io.getvalue()
    
    # Binary file bytes
    bin_data = b"Junk \x00\xff\x00S\x00e\x00c\x00r\x00e\x00t\x00 \x00W\x00i\x00n\x00 \x001\x002\x003\x00\xff\x00 ASCII secret here \xff"
    
    with zipfile.ZipFile(zip_path, 'w') as z:
        z.writestr("src/secrets.txt", b"API_KEY=AIzaSyD5E6")
        z.writestr("docs/report.docx", docx_data)
        z.writestr("docs/notes.odt", odt_data)
        z.writestr("bin/app.exe", bin_data)
        # Excluded folder node_modules
        z.writestr("node_modules/dep/index.js", b"console.log(1)")
        # Excluded extension png
        z.writestr("img/logo.png", b"png_data")
        
    try:
        files = list(get_zip_files(zip_path))
        file_map = dict(files)
        
        # Verify node_modules is ignored
        assert not any(name.startswith("node_modules/") for name in file_map)
        
        # Verify png is ignored
        assert not any(name.endswith(".png") for name in file_map)
        
        # Verify plain txt
        assert "src/secrets.txt" in file_map
        assert "API_KEY=AIzaSyD5E6" in file_map["src/secrets.txt"]
        
        # Verify nested docx
        assert "docs/report.docx" in file_map
        assert "Secret DOCX in ZIP" in file_map["docs/report.docx"]
        assert "token_123" in file_map["docs/report.docx"]
        
        # Verify nested odt
        assert "docs/notes.odt" in file_map
        assert "Secret ODT in ZIP" in file_map["docs/notes.odt"]
        assert "key_abc" in file_map["docs/notes.odt"]
        
        # Verify binary string extraction
        assert "bin/app.exe" in file_map
        assert "ASCII secret here" in file_map["bin/app.exe"]
        assert "Secret Win 123" in file_map["bin/app.exe"]
        
    finally:
        if os.path.exists(zip_path):
            os.remove(zip_path)
