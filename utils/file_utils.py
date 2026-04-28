# utils/file_utils.py
import magic
import os
import olefile  # 【新增导入】微创手术刀

def get_real_extension(file_path: str) -> str:
    try:
        with open(file_path, 'rb') as f:
            file_header = f.read(8192)
            
        mime_type = magic.from_buffer(file_header, mime=True).lower()
        
        mime_mapping = {
            'text/plain': '.txt',
            'application/pdf': '.pdf',
            'application/msword': '.doc',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
            'application/vnd.ms-excel': '.xls',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
            'application/vnd.ms-powerpoint': '.ppt',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation': '.pptx'
        }
        
        if mime_type in mime_mapping:
            return mime_mapping[mime_type]
            
        # 物理特征兜底：判断是否为老版 Office (OLE2 容器)
        is_ole2 = file_header.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1')

        if mime_type in ['application/vnd.ms-office', 'application/cdfv2', 'application/x-ole-storage', 'application/octet-stream'] or is_ole2:
            # ========================================================
            # 【核心补丁】使用 olefile 直接拆解二进制流，100% 精准识别，不卡死
            # ========================================================
            if olefile.isOleFile(file_path):
                try:
                    with olefile.OleFileIO(file_path) as ole:
                        # 提取内部所有数据流的名称
                        streams = [item for sublist in ole.listdir() for item in sublist]
                        
                        if 'WordDocument' in streams:
                            return '.doc'
                        if 'Workbook' in streams or 'Book' in streams:
                            return '.xls'
                        if 'PowerPoint Document' in streams:
                            return '.ppt'
                except Exception:
                    pass # 如果结构严重损坏，静默处理
            
            # 如果连 olefile 都拆不开，说明是真的坏了，回退到原后缀
            return os.path.splitext(file_path)[1].lower()
            
        return os.path.splitext(file_path)[1].lower()
        
    except Exception:
        return os.path.splitext(file_path)[1].lower()